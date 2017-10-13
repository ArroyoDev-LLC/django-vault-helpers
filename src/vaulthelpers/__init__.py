from . import aws  # NOQA
from . import common  # NOQA
from . import database  # NOQA
import os
import logging

logger = logging.getLogger(__name__)


def client():
    vault_auth = common.get_vault_auth()
    if not vault_auth:
        return
    verify = common.VAULT_CACERT or common.VAULT_SSL_VERIFY
    vcl = vault_auth.authenticated_client(common.VAULT_URL, verify=verify)
    return vcl


class EnvironmentConfig(object):
    def __init__(self, path):
        self.path = path
        self.config = {}
        try:
            vcl = client()
            if vcl:
                self.config = vcl.read(self.path).get('data', {})
        except Exception:
            logger.error('Failed to load configuration from Vault at path {}.'.format(path))

    def get(self, name, default=None):
        value = self.config.get(name)
        if value:
            return value
        return os.environ.get(name, default)
