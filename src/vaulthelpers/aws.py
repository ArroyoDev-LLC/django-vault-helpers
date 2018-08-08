from botocore.exceptions import CredentialRetrievalError
from datetime import datetime, timedelta
from dateutil.parser import parse
from django.core.serializers.json import DjangoJSONEncoder
from . import common, utils
import portalocker
import logging
import boto3
import botocore
import pytz
import json
import hashlib
import os
import stat

logger = logging.getLogger(__name__)


class VaultProvider(botocore.credentials.CredentialProvider):
    """
    CredentialProvider plug-in for botocore to fetch and refresh credentials from Vault

    Roughly based off of ``botocore.credentials.EnvProvider``.
    """
    METHOD = 'vault'
    REFRESH_MARGIN = (60 * 10)  # Refresh credentials 10 minutes before they expire


    def __init__(self, path):
        """
        Initialize the Vault credentials provider.

        Arguments:
            path {string} -- Vault secret path to use to fetch AWS credentials
        """
        self.path = path


    @property
    def cache_filename(self):
        base_path = os.path.abspath(os.path.expanduser(common.VAULT_AWS_CACHE))
        path_hash = hashlib.md5(self.path.encode()).hexdigest().lower()
        return '{}-{}'.format(base_path, path_hash)


    @property
    def lock_filename(self):
        return '{}.lock'.format(self.cache_filename)


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
            # Obtain a lock file so prevent races between multiple processes trying to obtain tokens at the same time
            with portalocker.Lock(self.lock_filename, timeout=10):
                # Try to use cached credentials if at all possible
                credentials = self._read_credential_cache()
                if credentials:
                    return credentials

                # No cache, so obtain new credentials
                try:
                    vcl = common.get_vault_auth().authenticated_client()
                    result = vcl.read(self.path)
                except Exception as e:
                    utils.log_exception('Failed to load configuration from Vault at path {}.'.format(self.path))
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
                self._write_credential_cache(credentials)
            return credentials

        return fetch_credentials


    def _read_credential_cache(self):
        # Try to read the cached credentials from the file system
        try:
            with open(self.cache_filename, 'r') as cache_file:
                data = json.load(cache_file)
        except OSError:
            return None

        # Parse the credentials expiration time
        expiry_time = None
        try:
            expiry_time = parse(data.get('expiry_time'))
        except ValueError:
            return None

        # If no expiry time was found, something went wrong. Return None
        if not expiry_time:
            return None

        # Check if the credentials are expired. If they are, return None
        refresh_threshold = (expiry_time - timedelta(seconds=self.REFRESH_MARGIN))
        if datetime.now(tz=pytz.UTC) > refresh_threshold:
            return None

        # Finally, return the cached data
        return data


    def _write_credential_cache(self, credentials):
        with open(self.cache_filename, 'w') as cache_file:
            json.dump(credentials, cache_file, cls=DjangoJSONEncoder)
        # Make the file only readable to the owner
        os.chmod(self.cache_filename, stat.S_IRUSR | stat.S_IWUSR)


    def purge_credential_cache(self):
        with portalocker.Lock(self.lock_filename, timeout=10):
            try:
                os.unlink(self.cache_filename)
            except FileNotFoundError:
                pass



class VaultSession(botocore.session.Session):
    def __init__(self, vault_path, *args, **kwargs):
        """Initialize a ``botocore`` session using credentials from Vault.

        Exactly the same as ``botocore.session.Session``, but uses AWS credentials from Vault.

        Arguments:
            vault_path {string} -- Vault secret path to use to fetch AWS credentials
        """
        self._vault_path = vault_path
        super().__init__(*args, **kwargs)


    def _register_credential_provider(self):
        """Registers a credential resolve instance with VaultProvider inserted as the most preferred credential provider."""
        def get_cred_resolver():
            credential_resolver = botocore.credentials.create_credential_resolver(self)
            vault_provider = VaultProvider(self._vault_path)
            credential_resolver.insert_before(botocore.credentials.EnvProvider.METHOD, vault_provider)
            return credential_resolver
        self._components.lazy_register_component('credential_provider', get_cred_resolver)



def init_boto3_credentials():
    """
    Configures boto3 to use AWS credentials from Vault
    """
    if not common.VAULT_AWS_PATH:
        logger.warning('Failed to load AWS credentials from Vault: missing AWS secret path.')
        return

    botocore_session = VaultSession(vault_path=common.VAULT_AWS_PATH)
    boto3.setup_default_session(botocore_session=botocore_session)
