from django.apps.config import AppConfig
from django.core.exceptions import ImproperlyConfigured
from django.db.backends.signals import connection_created
from . import aws  # NOQA
from . import common  # NOQA
from . import database  # NOQA
from . import utils
import os

default_app_config = 'vaulthelpers.VaultHelpersAppConfig'



def client():
    vault_auth = common.get_vault_auth()
    if not vault_auth:
        return
    vcl = vault_auth.authenticated_client()
    return vcl



class VaultHelpersAppConfig(AppConfig):
    name = 'vaulthelpers'

    def ready(self):
        # Register DB credential fetching code so that we can fetch credentials from Vault before
        # attempting to connect to the database.
        if common.VaultAuthenticator.has_envconfig():
            from django.conf import settings
            found = False
            for k, db in settings.DATABASES.items():
                if isinstance(db, database.DjangoAutoRefreshDBCredentialsDict):
                    found = True
            if found:
                database.monkeypatch_django()

        # Register SET_ROLE signal handler for the standard PostgreSQL database wrapper
        from django.db.backends.postgresql.base import DatabaseWrapper as PostgreSQLDatabaseWrapper
        connection_created.connect(database.set_role_connection, sender=PostgreSQLDatabaseWrapper)

        # Register SET_ROLE signal handler for the PostGIS database wrapper
        try:
            from django.contrib.gis.db.backends.postgis.base import DatabaseWrapper as PostGISDatabaseWrapper
            connection_created.connect(database.set_role_connection, sender=PostGISDatabaseWrapper)
        except (ImportError, ImproperlyConfigured):  # This exception will get thrown if the GDAL C libraries aren't installed.
            pass



class EnvironmentConfig(object):
    def __init__(self, path, kv_version=1):
        self.path = path
        self.config = {}
        try:
            vcl = client()
            if vcl:
                self.config = vcl.read(self.path).get('data', {})
        except Exception:
            utils.log_exception('Failed to load configuration from Vault at path {}.'.format(path))
        # Adjust for K/V API version
        if kv_version == 2:
            self.config = self.config.get('data', {})


    def get(self, name, default=None):
        value = self.config.get(name)
        if value:
            return value
        return os.environ.get(name, default)


    def __getitem__(self, name):
        if name in self.config:
            return self.config[name]
        if name in os.environ:
            return os.environ[name]
        raise KeyError(name)
