from datetime import datetime, timedelta
from django.core.serializers.json import DjangoJSONEncoder
from threading import Thread
from .exceptions import VaultConfigurationError, VaultCredentialProviderError
import asyncio
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
import random

logger = logging.getLogger(__name__)

# Constants
AUTH_TYPE_APPID = 'app-id'
AUTH_TYPE_APPROLE = 'approle'
AUTH_TYPE_AWS_IAM = 'aws'
AUTH_TYPE_KUBERNETES = 'kubernetes'
AUTH_TYPE_SSL = 'ssl'
AUTH_TYPE_TOKEN = 'token'
TOKEN_REFRESH_SECONDS = (60 * 10)
TOKEN_RENEW_INTERVAL = (60 * 5)

# Basic Vault configuration
VAULT_URL = os.environ.get('VAULT_URL')
VAULT_CACERT = os.environ.get('VAULT_CACERT')
VAULT_SSL_VERIFY = not bool(distutils.util.strtobool(os.environ.get('VAULT_SKIP_VERIFY', 'no')))
VAULT_DEBUG = bool(distutils.util.strtobool(os.environ.get('VAULT_DEBUG', 'no')))
VAULT_TOKEN_LEASE_RENEW_SECONDS = int(os.environ.get("VAULT_TOKEN_LEASE_RENEW_SECONDS", '3600'))

# Vault Authentication Option: Token
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

# Vault Authentication Option: AppID
VAULT_APPID = os.getenv("VAULT_APPID")
VAULT_USERID = os.getenv("VAULT_USERID")

# Vault Authentication Option: AWS IAM
VAULT_IAM_HEADER_VALUE = os.getenv('VAULT_IAM_HEADER_VALUE')
VAULT_IAM_ROLE = os.getenv('VAULT_IAM_ROLE')
VAULT_IAM_REGION = os.getenv('VAULT_IAM_REGION', 'us-east-1')  # This is the signature signing region, not the endpoint region

# Vault Authentication Option: Kubernetes
VAULT_KUBERNETES_ROLE = os.getenv('VAULT_KUBERNETES_ROLE')
VAULT_KUBERNETES_TOKEN_PATH = os.getenv('VAULT_KUBERNETES_TOKEN_PATH')

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
VAULT_DATABASE_RETRY_DELAY = float(os.environ.get("VAULT_DATABASE_RETRY_DELAY", '2'))
VAULT_DATABASE_LEASE_RENEW_SECONDS = int(os.environ.get("VAULT_DATABASE_LEASE_RENEW_SECONDS", '3600'))

# Secret path to obtain AWS credentials
VAULT_AWS_PATH = os.environ.get("VAULT_AWS_PATH")

# PostgreSQL role to assume upon connection
DATABASE_OWNERROLE = os.environ.get("DATABASE_OWNERROLE")

# Thread local storage used to store the VaultAuthenticator instance
threadLocal = threading.local()


class VaultAuthenticator(object):

    @classmethod
    def has_envconfig(cls):
        has_url = bool(VAULT_URL)
        has_token = bool(VAULT_TOKEN)
        has_appid = (VAULT_APPID and VAULT_USERID)
        has_iam = (VAULT_IAM_HEADER_VALUE and VAULT_IAM_ROLE)
        has_kube = (VAULT_KUBERNETES_ROLE and VAULT_KUBERNETES_TOKEN_PATH)
        has_ssl = (VAULT_SSLCERT and VAULT_SSLKEY)
        has_approle = (VAULT_ROLEID and VAULT_SECRETID)
        return has_url and (has_token or has_appid or has_iam or has_kube or has_ssl or has_approle)


    @classmethod
    def fromenv(cls):
        if VAULT_TOKEN:
            return cls.token(VAULT_URL, VAULT_TOKEN)
        elif VAULT_APPID and VAULT_USERID:
            return cls.app_id(VAULT_URL, VAULT_APPID, VAULT_USERID)
        elif VAULT_IAM_HEADER_VALUE and VAULT_IAM_ROLE:
            return cls.aws_iam(VAULT_URL, VAULT_IAM_HEADER_VALUE, VAULT_IAM_ROLE)
        elif VAULT_KUBERNETES_ROLE and VAULT_KUBERNETES_TOKEN_PATH:
            return cls.kubernetes(VAULT_URL, VAULT_KUBERNETES_ROLE, VAULT_KUBERNETES_TOKEN_PATH)
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
    def aws_iam(cls, url, header_value, role):
        creds = (header_value, role)
        return cls(url, creds, AUTH_TYPE_AWS_IAM, AUTH_TYPE_AWS_IAM)


    @classmethod
    def kubernetes(cls, url, role, token_path):
        with open(token_path, 'r') as token_file:
            token = token_file.read()
        creds = (role, token)
        return cls(url, creds, AUTH_TYPE_KUBERNETES, AUTH_TYPE_KUBERNETES)


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
        # Start background thread to keep the Vault token fresh
        self.start_background_lease_renewer(interval=TOKEN_RENEW_INTERVAL)


    @property
    def token_filename(self):
        return os.path.abspath(os.path.expanduser(VAULT_TOKEN_CACHE))


    @property
    def lock_filename(self):
        return '{}.lock'.format(self.token_filename)


    def authenticated_client(self):
        # Is there a valid client still in memory? Try to use it.
        if self._client and self._client_pid and self._client_expires:
            refresh_threshold = (self._client_expires - timedelta(seconds=TOKEN_REFRESH_SECONDS))
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

        elif self.auth_type == AUTH_TYPE_AWS_IAM:
            import boto3
            session = boto3.Session()
            credentials = session.get_credentials()
            client = hvac.Client(url=self.url, verify=self.ssl_verify)
            client.auth_aws_iam(
                access_key=credentials.access_key,
                secret_key=credentials.secret_key,
                session_token=credentials.token,
                header_value=self.credentials[0],
                mount_point=self.auth_mount,
                role=self.credentials[1],
                use_token=True,
                region=VAULT_IAM_REGION)

        elif self.auth_type == AUTH_TYPE_KUBERNETES:
            client = hvac.Client(url=self.url, verify=self.ssl_verify)
            client.auth_kubernetes(
                role=self.credentials[0],
                jwt=self.credentials[1],
                use_token=True,
                mount_point=self.auth_mount)

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


    def renew_lease(self):
        logger.info('Attempting to renew Vault token lease.')
        with portalocker.Lock(self.lock_filename, timeout=10):
            # Read the current lease data from disk
            data = self.read_token_cache(lease_grace_period=0)
            if not data:
                logger.info('Failed to renew lease because the Vault token cache was empty.')
                return
            # Check if we still need to renew the lease
            now = datetime.now(tz=pytz.UTC)
            old_expiry = data['expire_time']
            refresh_threshold = (old_expiry - timedelta(seconds=(TOKEN_REFRESH_SECONDS + TOKEN_RENEW_INTERVAL)))
            if now < refresh_threshold:
                logger.info('Not renewing Vault token lease because the current expiry time is acceptable. now=[%s], expires=[%s]', now, old_expiry)
                return
            # Renew the lease
            client = self.authenticated_client()
            try:
                result = client.renew_token(increment=VAULT_TOKEN_LEASE_RENEW_SECONDS)
            except Exception as e:
                logger.warning('Failed to renew Vault token lease. error=[%s]', e)
                return
            # Write the result back to disk
            self.write_token_cache(client)
        lease_duration = result.get('auth', {}).get('lease_duration', 0)
        new_expiry = datetime.now(tz=pytz.UTC) + timedelta(seconds=lease_duration)
        logger.info("Renewed lease for Vault token. accessor=[%s], old_expires=[%s], new_expires=[%s]",
            result.get('auth', {}).get('accessor', ''),
            old_expiry.isoformat(),
            new_expiry.isoformat())
        return


    def start_background_lease_renewer(self, interval):
        if getattr(self, 'daemon_thread', None) and self.daemon_thread.isAlive():
            return
        self.daemon_thread = Thread(
            target=self.start_lease_renewer,
            args=(interval, ),
            daemon=True)
        self.daemon_thread.start()


    def start_lease_renewer(self, interval):
        loop = asyncio.new_event_loop()

        def _schedule():
            jitter = (interval / 5)
            min_interval = interval - jitter
            max_interval = interval + jitter
            in_seconds = random.randrange(min_interval, max_interval)
            logger.info('Will attempt to renew Vault token lease in %s seconds', in_seconds)
            loop.call_later(in_seconds, _renew)

        def _renew():
            try:
                self.renew_lease()
            except Exception as e:
                logger.exception('Failed to renew Vault token lease. error=[%s]', e)
            _schedule()

        _schedule()
        loop.run_forever()


    def read_token_cache(self, lease_grace_period=TOKEN_REFRESH_SECONDS):
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
        refresh_threshold = (data['expire_time'] - timedelta(seconds=lease_grace_period))
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
            try:
                os.unlink(self.token_filename)
            except FileNotFoundError:
                pass



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
