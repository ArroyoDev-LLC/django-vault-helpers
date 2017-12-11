from datetime import datetime, timedelta
from django.db.backends.base import base as django_db_base
from django.db import utils as django_db_utils
from requests.exceptions import RequestException
from hvac.exceptions import InvalidRequest
from .exceptions import VaultCredentialProviderError
from . import common, utils
import logging
import dj_database_url
import pytz
import warnings

set_role_warning_given = False

_operror_types = ()
_operror_types += (django_db_utils.OperationalError,)
try:
    import psycopg2
except ImportError:
    pass
else:
    _operror_types += (psycopg2.OperationalError,)

try:
    import sqlite3
except ImportError:
    pass
else:
    _operror_types += (sqlite3.OperationalError,)

try:
    import MySQLdb
except ImportError:
    pass
else:
    _operror_types += (MySQLdb.OperationalError,)

logger = logging.getLogger(__name__)



class DatabaseCredentialProvider(object):
    def __init__(self, secret_path):
        self.secret_path = secret_path
        self._creds = None
        self._lease_id = None
        self._lease_expires = None


    @property
    def username(self):
        if self._creds is None:
            self.refresh_creds()
        return self._creds["username"]


    @property
    def password(self):
        if self._creds is None:
            self.refresh_creds()
        return self._creds["password"]


    def reset_creds(self):
        self._creds = None
        self._lease_id = None
        self._lease_expires = None


    def refresh_creds(self):
        vcl = common.get_vault_auth().authenticated_client()
        try:
            result = vcl.read(self.secret_path)
        except RequestException as e:
            raise VaultCredentialProviderError(
                "Unable to read credentials from path '{}' with request error: {}".format(self.secret_path, str(e)))

        if "data" not in result or "username" not in result["data"] or "password" not in result["data"]:
            raise VaultCredentialProviderError(
                "Read dict from Vault path {} did not match expected structure (data->{username, password}): %s".format(self.secret_path, str(result)))

        self._creds = result['data']
        self._lease_id = result['lease_id']
        self._lease_expires = datetime.now(tz=pytz.UTC) + timedelta(seconds=result['lease_duration'])
        logger.info("Loaded new Vault DB credentials from {path}: lease_id={lease_id}, expires={expires}, username={username}".format(
            path=self.secret_path,
            lease_id=self._lease_id,
            expires=self._lease_expires.isoformat(),
            username=self._creds['username']))


    def refresh_creds_if_needed(self, lease_grace_period=10):
        refresh = False
        # If we have no credentials at all, refresh the credentials.
        if self._creds is None:
            refresh = True

        # If theres less than {lease_grace_period} seconds left in the lease, refresh the credentials.
        if self._lease_expires is not None and datetime.now(tz=pytz.UTC) >= (self._lease_expires - timedelta(seconds=lease_grace_period)):
            refresh = True

        # If lease got revoked, refresh the credentials.
        if self.fetch_lease_ttl() <= lease_grace_period:
            refresh = True

        # If needed, refresh.
        if refresh:
            self.refresh_creds()
        return


    def fetch_lease_ttl(self):
        client = common.get_vault_auth().authenticated_client()
        params = { "lease_id": self._lease_id }
        try:
            resp = client._put('/v1/sys/leases/lookup', json=params).json()
        except InvalidRequest:
            return 0
        return resp.get('data', {}).get('ttl', 0)



class DjangoAutoRefreshDBCredentialsDict(dict):
    def __init__(self, provider, *args, **kwargs):
        self._provider = provider
        super().__init__(*args, **kwargs)


    def refresh_credentials(self):
        lease_grace_period = self.get('OPTIONS', {}).get('vault_lease_grace_period', 60)
        self._provider.refresh_creds_if_needed(lease_grace_period)
        self["USER"] = self._provider.username
        self["PASSWORD"] = self._provider.password


    def __str__(self) -> str:
        return "DjangoAutoRefreshDBCredentialsDict(%s)" % super().__str__()


    def __repr__(self) -> str:
        return "DjangoAutoRefreshDBCredentialsDict(%s)" % super().__repr__()



def get_config(extra_config={}):
    """Load database configuration from Vault.

    Keyword Arguments:
        extra_config {dict} -- Extra keys for the returned configuration dictionary (default: {{}})

    Returns:
        {dictionary} -- Django database configuration
    """
    db_config = dj_database_url.config()
    db_config.update({
        'SET_ROLE': common.DATABASE_OWNERROLE,
    })
    db_config.update(extra_config)

    if not common.VAULT_DATABASE_PATH:
        logger.warning('Failed to load DB configuration from Vault: missing database secret path.')
        return db_config

    vault_creds = DatabaseCredentialProvider(common.VAULT_DATABASE_PATH)

    try:
        db_config.update({
            'USER': vault_creds.username,
            'PASSWORD': vault_creds.password,
        })
    except Exception:
        utils.log_exception('Failed to load configuration from Vault at path {}.'.format(common.VAULT_DATABASE_PATH))
        return db_config

    return DjangoAutoRefreshDBCredentialsDict(vault_creds, db_config)



def monkeypatch_django():
    def ensure_connection_with_retries(self):
        if self.connection is not None and self.connection.closed:
            logger.debug("Failed connection detected")
            self.connection = None

        if self.connection is None:
            with self.wrap_database_errors:
                try:
                    self.connect()
                except Exception as e:
                    if isinstance(e, _operror_types):
                        max_retries = self.settings_dict.get('OPTIONS', {}).get('vault_connection_retries', 1)
                        if hasattr(self, "_vault_retries") and self._vault_retries >= max_retries:
                            logger.error("Retrying with new credentials from Vault didn't help {}".format(str(e)))
                            raise
                        else:
                            logger.info("Database connection failed. Refreshing credentials from Vault")
                            if not hasattr(self.settings_dict, 'refresh_credentials'):
                                self.settings_dict = get_config(self.settings_dict)
                            self.settings_dict.refresh_credentials()
                            self._vault_retries = 1
                            self.ensure_connection()
                    else:
                        logger.debug("Database connection failed, but not due to a known error {}".format(str(e)))
                        raise
                else:
                    self._vault_retries = 0

    logger.debug("Installed vaulthelpers database connection helper into BaseDatabaseWrapper")
    django_db_base.BaseDatabaseWrapper.ensure_connection = ensure_connection_with_retries



def set_role_connection(sender, connection, **kwargs):
    global set_role_warning_given
    role = None
    if "set_role" in connection.settings_dict:
        role = connection.settings_dict["set_role"]
    elif "SET_ROLE" in connection.settings_dict:
        role = connection.settings_dict["SET_ROLE"]

    if role:
        connection.cursor().execute("SET ROLE %s", (role, ))
    else:
        if not set_role_warning_given:
            warnings.warn("Value for SET_ROLE is missing from settings.DATABASE")
            set_role_warning_given = True
