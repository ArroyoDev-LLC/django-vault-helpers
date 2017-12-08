from datetime import datetime, timedelta
from django.core.serializers.json import DjangoJSONEncoder
from vault12factor import VaultCredentialProviderException, BaseVaultAuthenticator
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

logger = logging.getLogger(__name__)

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

# Unwrap vault responses
VAULT_UNWRAP = bool(distutils.util.strtobool(os.getenv("VAULT_UNWRAP", "no")))

# File path to use for caching the vault token
VAULT_TOKEN_CACHE = os.getenv("VAULT_TOKEN_CACHE", ".vault-token")

# Secret path to obtain database credentials
VAULT_DATABASE_PATH = os.environ.get("VAULT_DATABASE_PATH")

# Secret path to obtain AWS credentials
VAULT_AWS_PATH = os.environ.get("VAULT_AWS_PATH")

# PostgreSQL role to assume upon connection
DATABASE_OWNERROLE = os.environ.get("DATABASE_OWNERROLE")

# Thread local storage used to store the VaultAuthenticator instance
threadLocal = threading.local()


class CachedVaultAuthenticator(BaseVaultAuthenticator):
    TOKEN_REFRESH_SECONDS = 30


    @classmethod
    def has_envconfig(cls):
        if (VAULT_TOKEN or
                (VAULT_APPID and VAULT_USERID) or
                (VAULT_SSLCERT and VAULT_SSLKEY) or
                (VAULT_ROLEID and VAULT_SECRETID)):
            return True
        return False


    @classmethod
    def fromenv(cls):
        authenticator = None
        if VAULT_TOKEN:
            authenticator = cls.token(VAULT_TOKEN)
        elif VAULT_APPID and VAULT_USERID:
            authenticator = cls.app_id(VAULT_APPID, VAULT_USERID)
        elif VAULT_ROLEID and VAULT_SECRETID:
            authenticator = cls.approle(VAULT_ROLEID, VAULT_SECRETID)
        elif VAULT_SSLCERT and VAULT_SSLKEY:
            authenticator = cls.ssl_client_cert(VAULT_SSLCERT, VAULT_SSLKEY)

        if authenticator:
            if VAULT_UNWRAP:
                authenticator.unwrap_response = True
            return authenticator

        raise VaultCredentialProviderException("Unable to configure Vault authentication from the environment")


    def __init__(self):
        super().__init__()
        self._client = None
        self._client_pid = None
        self._client_expires = None


    @property
    def token_filename(self):
        return os.path.abspath(os.path.expanduser(VAULT_TOKEN_CACHE))


    @property
    def lock_filename(self):
        return '{}.lock'.format(self.token_filename)


    def authenticated_client(self, *args, **kwargs):
        # Set some default kwargs
        if 'url' not in kwargs:
            kwargs['url'] = VAULT_URL
        if 'verify' not in kwargs:
            kwargs['verify'] = VAULT_CACERT if VAULT_CACERT else VAULT_SSL_VERIFY

        # Is there a valid client still in memory? Try to use it.
        if self._client and self._client_pid and self._client_expires:
            refresh_threshold = (self._client_expires - timedelta(seconds=self.TOKEN_REFRESH_SECONDS))
            if self._client_pid == os.getpid() and datetime.now(tz=pytz.UTC) <= refresh_threshold:
                return self._client

        # Obtain a lock file so prevent races between multiple processes trying to obtain tokens at the same time
        with portalocker.Lock(self.lock_filename, timeout=10):

            # Try to use a cached token if at all possible
            cache = self.read_token_cache()
            if cache:
                client = hvac.Client(token=cache['token'], *args, **kwargs)
                if client.is_authenticated():
                    self._client = client
                    self._client_pid = os.getpid()
                    self._client_expires = cache['expire_time']
                    return self._client

            # Couldn't use cache, so obtain a new token instead
            client = super().authenticated_client(*args, **kwargs)
            self.write_token_cache(client)

        # Return the client
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



def init_vault():
    if not CachedVaultAuthenticator.has_envconfig():
        logger.warning('Could not load Vault configuration from environment variables')
        return
    threadLocal.vaultAuthenticator = CachedVaultAuthenticator.fromenv()



def get_vault_auth():
    if not getattr(threadLocal, 'vaultAuthenticator', None):
        init_vault()
    return threadLocal.vaultAuthenticator
