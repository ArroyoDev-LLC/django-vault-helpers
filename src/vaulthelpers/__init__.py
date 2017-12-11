from django.apps.config import AppConfig
from . import aws  # NOQA
from . import common  # NOQA
from . import database  # NOQA
from . import utils
import os
import logging

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
        if common.VaultAuthenticator.has_envconfig():
            from django.conf import settings
            found = False
            for k, db in settings.DATABASES.items():
                if isinstance(db, database.DjangoAutoRefreshDBCredentialsDict):
                    found = True
            if found:
                database.monkeypatch_django()



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
