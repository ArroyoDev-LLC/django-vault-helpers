from datetime import datetime, timedelta
from django.core.serializers.json import DjangoJSONEncoder
from .exceptions import VaultConfigurationError, VaultCredentialProviderError
import distutils.util
import dateutil.parser
import portalocker
import json
import logging
import os.path
import os
import pytz
import hvac
import threading
import stat

logger = logging.getLogger(__name__)

# Constants
AUTH_TYPE_APPID = 'app-id'
AUTH_TYPE_APPROLE = 'approle'
AUTH_TYPE_SSL = 'ssl'
AUTH_TYPE_TOKEN = 'token'

# Basic Vault configuration
VAULT_URL = os.environ.get('VAULT_URL')
VAULT_CACERT = os.environ.get('VAULT_CACERT')
VAULT_SSL_VERIFY = not bool(distutils.util.strtobool(os.environ.get('VAULT_SKIP_VERIFY', 'no')))
VAULT_DEBUG = bool(distutils.util.strtobool(os.environ.get('VAULT_DEBUG', 'no')))

# Vault Authentication Option: Token
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

# Vault Authentication Option: AppID
VAULT_APPID = os.getenv("VAULT_APPID")
VAULT_USERID = os.getenv("VAULT_USERID")

# Vault Authentication Option: SSL Client Certificate
VAULT_SSLCERT = os.getenv("VAULT_SSLCERT")
VAULT_SSLKEY = os.getenv("VAULT_SSLKEY")

# Vault Authentication Option: AppRole
VAULT_ROLEID = os.getenv("VAULT_ROLEID")
VAULT_SECRETID = os.getenv("VAULT_SECRETID")

# File path to use for caching the vault token
VAULT_TOKEN_CACHE = os.getenv("VAULT_TOKEN_CACHE", ".vault-token")
VAULT_AWS_CACHE = os.getenv("VAULT_AWS_CACHE", ".vault-aws")
VAULT_DB_CACHE = os.getenv("VAULT_DB_CACHE", ".vault-db")

# Secret path to obtain database credentials
VAULT_DATABASE_PATH = os.environ.get("VAULT_DATABASE_PATH")

# Secret path to obtain AWS credentials
VAULT_AWS_PATH = os.environ.get("VAULT_AWS_PATH")

# PostgreSQL role to assume upon connection
DATABASE_OWNERROLE = os.environ.get("DATABASE_OWNERROLE")

# Thread local storage used to store the VaultAuthenticator instance
threadLocal = threading.local()


class VaultAuthenticator(object):
    TOKEN_REFRESH_SECONDS = 30


    @classmethod
    def has_envconfig(cls):
        has_url = bool(VAULT_URL)
        has_token = bool(VAULT_TOKEN)
        has_appid = (VAULT_APPID and VAULT_USERID)
        has_ssl = (VAULT_SSLCERT and VAULT_SSLKEY)
        has_approle = (VAULT_ROLEID and VAULT_SECRETID)
        return has_url and (has_token or has_appid or has_ssl or has_approle)


    @classmethod
    def fromenv(cls):
        if VAULT_TOKEN:
            return cls.token(VAULT_URL, VAULT_TOKEN)
        elif VAULT_APPID and VAULT_USERID:
            return cls.app_id(VAULT_URL, VAULT_APPID, VAULT_USERID)
        elif VAULT_ROLEID and VAULT_SECRETID:
            return cls.approle(VAULT_URL, VAULT_ROLEID, VAULT_SECRETID)
        elif VAULT_SSLCERT and VAULT_SSLKEY:
            return cls.ssl_client_cert(VAULT_URL, VAULT_SSLCERT, VAULT_SSLKEY)
        raise VaultConfigurationError("Unable to configure Vault authentication from the environment")


    @classmethod
    def app_id(cls, url, app_id, user_id):
        creds = (app_id, user_id)
        return cls(url, creds, AUTH_TYPE_APPID, AUTH_TYPE_APPID)


    @classmethod
    def approle(cls, url, role_id, secret_id=None, mountpoint=AUTH_TYPE_APPROLE):
        creds = (role_id, secret_id)
        return cls(url, creds, AUTH_TYPE_APPROLE, mountpoint)


    @classmethod
    def ssl_client_cert(cls, url, certfile, keyfile):
        if not os.path.isfile(certfile) or not os.access(certfile, os.R_OK):
            raise VaultCredentialProviderError("File not found or not readable: %s" % certfile)
        if not os.path.isfile(keyfile) or not os.access(keyfile, os.R_OK):
            raise VaultCredentialProviderError("File not found or not readable: %s" % keyfile)
        creds = (certfile, keyfile)
        i = cls(url, creds, AUTH_TYPE_SSL, AUTH_TYPE_SSL)
        i.credentials = (certfile, keyfile)
        return i


    @classmethod
    def token(cls, url, token):
        return cls(url, token, AUTH_TYPE_TOKEN, AUTH_TYPE_TOKEN)


    def __init__(self, url, credentials, auth_type, auth_mount):
        self.url = url
        self.credentials = credentials
        self.auth_type = auth_type
        self.auth_mount = auth_mount
        self.ssl_verify = VAULT_CACERT if VAULT_CACERT else VAULT_SSL_VERIFY
        self._client = None
        self._client_pid = None
        self._client_expires = None


    @property
    def token_filename(self):
        return os.path.abspath(os.path.expanduser(VAULT_TOKEN_CACHE))


    @property
    def lock_filename(self):
        return '{}.lock'.format(self.token_filename)


    def authenticated_client(self):
        # Is there a valid client still in memory? Try to use it.
        if self._client and self._client_pid and self._client_expires:
            refresh_threshold = (self._client_expires - timedelta(seconds=self.TOKEN_REFRESH_SECONDS))
            if self._client_pid == os.getpid() and datetime.now(tz=pytz.UTC) <= refresh_threshold and self._client.is_authenticated():
                return self._client

        # Obtain a lock file so prevent races between multiple processes trying to obtain tokens at the same time
        with portalocker.Lock(self.lock_filename, timeout=10):

            # Try to use a cached token if at all possible
            cache = self.read_token_cache()
            if cache:
                client = hvac.Client(url=self.url, verify=self.ssl_verify, token=cache['token'])
                if client.is_authenticated():
                    self._client = client
                    self._client_pid = os.getpid()
                    self._client_expires = cache['expire_time']
                    return self._client

            # Couldn't use cache, so obtain a new token instead
            client = self.build_client()
            self.write_token_cache(client)

        # Return the client
        return client


    def build_client(self):
        if self.auth_type == AUTH_TYPE_TOKEN:
            client = hvac.Client(url=self.url, verify=self.ssl_verify, token=self.credentials)

        elif self.auth_type == AUTH_TYPE_APPID:
            client = hvac.Client(url=self.url, verify=self.ssl_verify)
            client.auth_app_id(*self.credentials)

        elif self.auth_type == AUTH_TYPE_APPROLE:
            client = hvac.Client(url=self.url, verify=self.ssl_verify)
            client.auth_approle(*self.credentials, mount_point=self.auth_mount, use_token=True)

        elif self.auth_type == AUTH_TYPE_SSL:
            client = hvac.Client(url=self.url, verify=self.ssl_verify, cert=self.credentials)
            client.auth_tls()

        else:
            raise VaultCredentialProviderError("Missing or invalid Vault authentication configuration")

        if not client.is_authenticated():
            raise VaultCredentialProviderError("Unable to authenticate Vault client using provided credentials " "(type=%s)" % self.auth_type)

        return client


    def read_token_cache(self):
        # Try to read the cached token from the file system
        try:
            with open(self.token_filename, 'r') as token_file:
                data = json.load(token_file)
        except OSError:
            return None

        # Parse the token expiration time
        try:
            data['expire_time'] = dateutil.parser.parse(data.get('expire_time'))
        except ValueError:
            return None

        # Check if the token is expired. If it is, return None
        refresh_threshold = (data['expire_time'] - timedelta(seconds=self.TOKEN_REFRESH_SECONDS))
        if datetime.now(tz=pytz.UTC) > refresh_threshold:
            return None

        return data


    def write_token_cache(self, client):
        token_info = client.lookup_token()
        self._client = client
        self._client_pid = os.getpid()  # Store the current PID so we know to create a new client if this process gets forked.
        if token_info['data']['expire_time']:
            self._client_expires = dateutil.parser.parse(token_info['data']['expire_time'])
        else:
            self._client_expires = datetime.now(tz=pytz.UTC) + timedelta(days=30)
        token_data = {
            'expire_time': self._client_expires,
            'token': self._client.token,
        }
        with open(self.token_filename, 'w') as token_file:
            json.dump(token_data, token_file, cls=DjangoJSONEncoder)
        # Make the file only readable to the owner
        os.chmod(self.token_filename, stat.S_IRUSR | stat.S_IWUSR)


    def purge_token_cache(self):
        with portalocker.Lock(self.lock_filename, timeout=10):
            os.unlink(self.token_filename)



def init_vault():
    if VaultAuthenticator.has_envconfig():
        threadLocal.vaultAuthenticator = VaultAuthenticator.fromenv()
    else:
        threadLocal.vaultAuthenticator = None
        logger.warning('Could not load Vault configuration from environment variables')


def reset_vault():
    threadLocal.vaultAuthenticator = None


def get_vault_auth():
    if not getattr(threadLocal, 'vaultAuthenticator', None):
        init_vault()
    return threadLocal.vaultAuthenticator
