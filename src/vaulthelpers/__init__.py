from django.apps.config import AppConfig
from django.core.exceptions import ImproperlyConfigured
from django.db.backends.signals import connection_created
from django.db.backends.postgresql.base import DatabaseWrapper as PostgreSQLDatabaseWrapper
from . import aws  # NOQA
from . import common  # NOQA
from . import database  # NOQA
from . import utils
import os
import logging

# Try to import PostGISDatabaseWrapper. This will fail if GDAL isn't installed.
try:
    from django.contrib.gis.db.backends.postgis.base import DatabaseWrapper as PostGISDatabaseWrapper
except (ImportError, ImproperlyConfigured):
    PostGISDatabaseWrapper = None

logger = logging.getLogger(__name__)

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
        # Register DB credential fetching code
        if common.VaultAuthenticator.has_envconfig():
            from django.conf import settings
            found = False
            for k, db in settings.DATABASES.items():
                if isinstance(db, database.DjangoAutoRefreshDBCredentialsDict):
                    found = True
            if found:
                database.monkeypatch_django()

        # Register SET_ROLE signal handler
        connection_created.connect(database.set_role_connection, sender=PostgreSQLDatabaseWrapper)
        if PostGISDatabaseWrapper is not None:
            connection_created.connect(database.set_role_connection, sender=PostGISDatabaseWrapper)



class EnvironmentConfig(object):
    def __init__(self, path):
        self.path = path
        self.config = {}
        try:
            vcl = client()
            if vcl:
                self.config = vcl.read(self.path).get('data', {})
        except Exception:
            utils.log_exception('Failed to load configuration from Vault at path {}.'.format(path))

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
