from datetime import datetime, timedelta
from dateutil.parser import parse
from django.db.backends.base import base as django_db_base
from django.db import utils as django_db_utils
from django.core.serializers.json import DjangoJSONEncoder
from requests.exceptions import RequestException
from hvac.exceptions import InvalidRequest
from threading import Thread
from .exceptions import VaultCredentialProviderError
from . import common, utils
import asyncio
import logging
import dj_database_url
import pytz
import warnings
import portalocker
import hashlib
import os
import json
import stat
import time
import random

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


DEFAULT_GRACE_SECONDS = (60 * 10)
DEFAULT_RENEW_INTERVAL = (60 * 5)



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


    @property
    def cache_filename(self):
        base_path = os.path.abspath(os.path.expanduser(common.VAULT_DB_CACHE))
        path_hash = hashlib.md5(self.secret_path.encode()).hexdigest().lower()
        return '{}-{}'.format(base_path, path_hash)


    @property
    def lock_filename(self):
        return '{}.lock'.format(self.cache_filename)


    def reset_creds(self):
        self._creds = None
        self._lease_id = None
        self._lease_expires = None


    def refresh_creds(self, lease_grace_period=DEFAULT_GRACE_SECONDS):
        logger.info('Beginning database credential refresh. Obtaining lock file.')
        # Obtain a lock file so prevent races between multiple processes trying to obtain credentials at the same time
        with portalocker.Lock(self.lock_filename, timeout=10):
            logger.info('Obtained lock file.')
            # Try to use cached credentials if at all possible
            data = self._read_credential_cache(lease_grace_period)
            if data:
                self._creds = data['creds']
                self._lease_id = data['lease_id']
                self._lease_expires = data['lease_expiration']
                logger.info("Loaded cached Vault DB credentials from filesystem %s: lease_id=[%s], expires=[%s], username=[%s]",
                    self.secret_path,
                    self._lease_id,
                    self._lease_expires.isoformat(),
                    self._creds['username'])
                return

            # No cache, so obtain new credentials
            logger.info('Failed to load credentials from cache. Getting authenticated Vault client.')
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
            self._write_credential_cache(self._creds, self._lease_id, self._lease_expires)
        logger.info("Loaded new Vault DB credentials from %s: lease_id=[%s], expires=[%s], username=[%s]",
            self.secret_path,
            self._lease_id,
            self._lease_expires.isoformat(),
            self._creds['username'])


    def refresh_creds_if_needed(self, lease_grace_period=DEFAULT_GRACE_SECONDS):
        logger.info('Determining is database credential refresh is needed. grace_period=[%s]', lease_grace_period)

        refresh = False
        # If we have no credentials at all, refresh the credentials.
        if self._creds is None:
            logger.info('Database credential refresh is needed because self._creds is None')
            refresh = True

        # If theres less than {lease_grace_period} seconds left in the lease, refresh the credentials.
        now = datetime.now(tz=pytz.UTC)
        graceful_expires = None
        if self._lease_expires is not None:
            graceful_expires = (self._lease_expires - timedelta(seconds=lease_grace_period))
        if graceful_expires is not None and now >= graceful_expires:
            logger.info('Database credential refresh is needed because self._lease_expires is within grace period. now=[%s], expires=[%s]',
                now,
                self._lease_expires)
            refresh = True

        # If lease got revoked, refresh the credentials.
        lease_ttl = self.fetch_lease_ttl()
        if lease_ttl <= lease_grace_period:
            logger.info('Database credential refresh is needed because lease_ttl is within grace period. lease_ttl=[%s], grace_period=[%s]',
                lease_ttl,
                lease_grace_period)
            refresh = True

        # If needed, refresh.
        if refresh:
            logger.info('Database credential refresh is needed. lease_ttl=[%s], grace_period=[%s]', lease_ttl, lease_grace_period)
            self.refresh_creds(lease_grace_period)
        else:
            logger.info('Database credential refresh is not needed. lease_ttl=[%s], grace_period=[%s]', lease_ttl, lease_grace_period)
        return


    def fetch_lease_ttl(self):
        if not self._lease_id:
            return 0
        client = common.get_vault_auth().authenticated_client()
        try:
            resp = client.sys.read_lease(lease_id=self._lease_id)
        except InvalidRequest as e:
            logger.info('Failed to fetch lease TTL from Vault. Assuming lease is expire. lease_id=[%s], error=[%s]', self._lease_id, e)
            return 0
        ttl = resp.get('data', {}).get('ttl', 0)
        logger.info('Fetched lease ID from Vault. lease_id=[%s], ttl=[%s]', self._lease_id, ttl)
        return ttl


    def renew_lease(self):
        logger.info('Attempting to renew credential lease.')
        with portalocker.Lock(self.lock_filename, timeout=10):
            # Read the current lease data from disk
            data = self._read_credential_cache(lease_grace_period=0)
            if not data:
                logger.info('Failed to renew lease because the credential cache was empty.')
                return
            # Check if we still need to renew the lease
            now = datetime.now(tz=pytz.UTC)
            old_expiry = data['lease_expiration']
            refresh_threshold = (old_expiry - timedelta(seconds=(DEFAULT_GRACE_SECONDS + DEFAULT_RENEW_INTERVAL)))
            if now < refresh_threshold:
                logger.info('Not renewing credential lease because the current expiry time is acceptable. now=[%s], expires=[%s]', now, old_expiry)
                return
            # Renew the lease
            client = common.get_vault_auth().authenticated_client()
            try:
                result = client.sys.renew_lease(
                    lease_id=data['lease_id'],
                    increment=common.VAULT_DATABASE_LEASE_RENEW_SECONDS)
            except Exception as e:
                logger.warning('Failed to renew credential lease. lease_id=[%s], error=[%s]', self._lease_id, e)
                return
            # Write the result back to disk
            self._creds = data['creds']
            self._lease_id = result['lease_id']
            self._lease_expires = datetime.now(tz=pytz.UTC) + timedelta(seconds=result['lease_duration'])
            self._write_credential_cache(self._creds, self._lease_id, self._lease_expires)
        logger.info("Renewed lease for Vault DB credentials. lease_id=[%s], old_expires=[%s], new_expires=[%s], username=[%s]",
            self._lease_id,
            old_expiry.isoformat(),
            self._lease_expires.isoformat(),
            self._creds['username'])
        return


    def _read_credential_cache(self, lease_grace_period):
        # Try to read the cached credentials from the file system
        try:
            with open(self.cache_filename, 'r') as cache_file:
                data = json.load(cache_file)
        except OSError as e:
            logger.info('Failed to read database credential cache from disk. error=[%s]', e)
            return None

        # Parse the credentials expiration time
        try:
            data['lease_expiration'] = parse(data.get('lease_expiration'))
        except ValueError as e:
            logger.info('Failed to read database credential cache because lease_expiration is invalid. error=[%s]', e)
            return None

        # If no expiry time was found, something went wrong. Return None
        if not data['lease_expiration']:
            logger.info('Failed to read database credential cache because lease_expiration is missing.')
            return None

        # Check if the credentials are expired. If they are, return None
        now = datetime.now(tz=pytz.UTC)
        refresh_threshold = (data['lease_expiration'] - timedelta(seconds=lease_grace_period))
        if now > refresh_threshold:
            logger.info('Failed to read database credential cache because cached credentials are expired. now=[%s], expired=[%s]', now, refresh_threshold)
            return None

        # Finally, return the cached data
        logger.info('Returning cached database credentials. expires=[%s]', refresh_threshold)
        return data


    def _write_credential_cache(self, creds, lease_id, lease_expiration):
        data = {
            'creds': creds,
            'lease_id': lease_id,
            'lease_expiration': lease_expiration,
        }
        with open(self.cache_filename, 'w') as cache_file:
            json.dump(data, cache_file, cls=DjangoJSONEncoder)
        # Make the file only readable to the owner
        os.chmod(self.cache_filename, stat.S_IRUSR | stat.S_IWUSR)


    def purge_credential_cache(self):
        logger.info('Attempting to purge database credential cache. path=[%s]', self.cache_filename)
        with portalocker.Lock(self.lock_filename, timeout=10):
            try:
                os.unlink(self.cache_filename)
            except FileNotFoundError:
                logger.info('Failed to purge Database credential cache because cache file was not found. path=[%s]', self.cache_filename)
                pass



class DjangoAutoRefreshDBCredentialsDict(dict):
    def __init__(self, provider, *args, **kwargs):
        self._provider = provider
        super().__init__(*args, **kwargs)


    def refresh_credentials(self):
        # Load config
        lease_grace_period = self.get('OPTIONS', {}).get('vault_lease_grace_period', DEFAULT_GRACE_SECONDS)
        # Obtain creds
        self._provider.refresh_creds_if_needed(lease_grace_period)

        # Start a background thread to keep the creds fresh
        self.start_background_lease_renewer(DEFAULT_RENEW_INTERVAL)

        self["USER"] = self._provider.username
        self["PASSWORD"] = self._provider.password


    def reset_credentials(self):
        self._provider.reset_creds()
        self["USER"] = None
        self["PASSWORD"] = None


    def purge_credential_cache(self):
        self._provider.purge_credential_cache()
        self.reset_credentials()


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
            logger.info('Will attempt to renew database credential lease in %s seconds', in_seconds)
            loop.call_later(in_seconds, _renew)

        def _renew():
            try:
                self._provider.renew_lease()
            except Exception as e:
                logger.exception('Failed to renew database credential lease. error=[%s]', e)
            _schedule()

        _schedule()
        loop.run_forever()


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
            logger.info("Failed database connection detected")
            self.connection = None

        if self.connection is None:
            with self.wrap_database_errors:
                try:
                    # Try to connect
                    self.connect()
                except Exception as e:
                    # See if this is a known error type or not
                    if not isinstance(e, _operror_types):
                        logger.warning("Database connection failed, but not due to a known error. errors=[%s]", e)
                        raise

                    # Get the max number of retry attempts
                    max_retries = self.settings_dict.get('OPTIONS', {}).get('vault_connection_retries', 3)

                    # If the max retry count has been exceeded, raise the error
                    if hasattr(self, "_vault_retries") and self._vault_retries >= max_retries:
                        logger.error("Retrying with new credentials from Vault didn't help. errors=[%s]", e)
                        raise

                    # Try to refresh Vault credentials and attempt another connection
                    logger.info("Database connection failed. Refreshing credentials from Vault.")
                    if not hasattr(self.settings_dict, 'refresh_credentials'):
                        logger.info("Installed vaulthelpers database connection settings_dict")
                        self.settings_dict = get_config(self.settings_dict)

                    # If we've already retried once, purge the cache and try again
                    if hasattr(self, "_vault_retries") and self._vault_retries >= 1:
                        logger.info("Purging credential cache before refreshing credentials from Vault.")
                        self.settings_dict.purge_credential_cache()

                    # Refresh the credentials from Vault
                    self.settings_dict.refresh_credentials()
                    if not hasattr(self, "_vault_retries"):
                        self._vault_retries = 0
                    self._vault_retries += 1

                    # Pause before attempting to connect with new credentials. Sometimes needed to allow the new user
                    # from Vault to replicate to DB followers.
                    if common.VAULT_DATABASE_RETRY_DELAY > 0:
                        time.sleep(common.VAULT_DATABASE_RETRY_DELAY)

                    # Re-connect
                    self.ensure_connection()
                else:
                    # After a successful connection, reset the retry count back down to 0
                    self._vault_retries = 0

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
