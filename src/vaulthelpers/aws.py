from botocore.exceptions import CredentialRetrievalError
from datetime import datetime, timedelta
from dateutil.parser import parse
from . import common
import logging
import boto3
import botocore
import pytz

logger = logging.getLogger(__name__)


class VaultProvider(botocore.credentials.CredentialProvider):
    """
    CredentialProvider plug-in for botocore to fetch and refresh credentials from Vault

    Roughly based off of ``botocore.credentials.EnvProvider``.
    """
    METHOD = 'vault'
    REFRESH_MARGIN = (60 * 10)  # Refresh credentials 10 minutes before they expire


    def __init__(self, url, auth, path, pin_cacert=None, ssl_verify=True):
        """Initialize the Vault credentials provider.

        Arguments:
            url {string} -- Vault API URL
            auth {VaultAuth12Factor} -- Vault Authenticator instance. See 12factor-vault package
            path {string} -- Vault secret path to use to fetch AWS credentials

        Keyword Arguments:
            pin_cacert {string} -- Path to HTTPS CA certificate file for CA pinning (default: {None})
            ssl_verify {bool} -- Verify validity of Vault's SSL certificate (default: {True})
        """
        self.url = url
        self.auth = auth
        self.path = path
        self.pin_cacert = pin_cacert
        self.ssl_verify = ssl_verify


    def load(self):
        """Load AWS credentials from Vault

        Returns:
            {botocore.credentials.RefreshableCredentials} -- AWS Credentials object with built-in refresh callback
        """
        fetcher = self._create_credentials_fetcher()
        credentials = fetcher()
        return botocore.credentials.RefreshableCredentials(
            access_key=credentials['access_key'],
            secret_key=credentials['secret_key'],
            token=credentials['token'],
            expiry_time=parse(credentials['expiry_time']),
            refresh_using=fetcher,
            method=self.METHOD)


    def _create_credentials_fetcher(self):
        """Create a return a function which can be called to fetch AWS credentials form Vault

        Returns:
            {dictionary} -- Credentials dictionary with keys ``access_key``, ``secret_key``, ``token``, and ``expiry_time``
        """
        def fetch_credentials():
            try:
                vcl = self.auth.authenticated_client(
                    url=self.url,
                    verify=self.pin_cacert if self.pin_cacert else self.ssl_verify)
                result = vcl.read(self.path)
            except Exception as e:
                logger.error('Failed to load configuration from Vault at path {}.'.format(self.path))
                raise CredentialRetrievalError(provider=self.METHOD, error_msg=str(e))

            expiry_time = datetime.utcnow().replace(tzinfo=pytz.utc)
            expiry_time += timedelta(seconds=result['lease_duration'])
            expiry_time -= timedelta(seconds=self.REFRESH_MARGIN)

            credentials = {
                'access_key': result['data']['access_key'],
                'secret_key': result['data']['secret_key'],
                'token': result['data']['security_token'],
                'expiry_time': expiry_time.strftime('%Y-%m-%d %H:%M:%S%z'),
            }
            return credentials

        return fetch_credentials


class VaultSession(botocore.session.Session):
    def __init__(self, vault_url, vault_auth, vault_path, *args, vault_pin_cacert=None, vault_ssl_verify=True, **kwargs):
        """Initialize a ``botocore`` session using credentials from Vault.

        Exactly the same as ``botocore.session.Session``, but uses AWS credentials from Vault.

        Arguments:
            vault_url {string} -- Vault API URL
            vault_auth {VaultAuth12Factor} -- Vault Authenticator instance. See 12factor-vault package
            vault_path {string} -- Vault secret path to use to fetch AWS credentials

        Keyword Arguments:
            vault_pin_cacert {string} -- Path to HTTPS CA certificate file for CA pinning (default: {None})
            vault_ssl_verify {bool} -- Verify validity of Vault's SSL certificate (default: {True})
        """
        self._vault_kwargs = {
            'url': vault_url,
            'auth': vault_auth,
            'path': vault_path,
            'pin_cacert': vault_pin_cacert,
            'ssl_verify': vault_ssl_verify,
        }
        super().__init__(*args, **kwargs)


    def _register_credential_provider(self):
        """Registers a credential resolve instance with VaultProvider inserted as the most preferred credential provider."""
        def get_cred_resolver():
            credential_resolver = botocore.credentials.create_credential_resolver(self)
            vault_provider = VaultProvider(**self._vault_kwargs)
            credential_resolver.insert_before(botocore.credentials.EnvProvider.METHOD, vault_provider)
            return credential_resolver
        self._components.lazy_register_component('credential_provider', get_cred_resolver)


def init_boto3_credentials():
    """Configures boto3 to use AWS credentials from Vault"""
    if not common.VAULT_URL:
        logger.warning('Failed to load AWS credentials from Vault: missing Vault API URL.')
        return

    if not common.VAULT_AWS_PATH:
        logger.warning('Failed to load AWS credentials from Vault: missing AWS secret path.')
        return

    vault_auth = common.get_vault_auth()
    if not vault_auth:
        logger.warning('Failed to load AWS credentials from Vault: missing Vault authentication.')
        return

    botocore_session = VaultSession(
        vault_url=common.VAULT_URL,
        vault_auth=vault_auth,
        vault_path=common.VAULT_AWS_PATH,
        vault_pin_cacert=common.VAULT_CACERT,
        vault_ssl_verify=common.VAULT_SSL_VERIFY)
    boto3.setup_default_session(botocore_session=botocore_session)
