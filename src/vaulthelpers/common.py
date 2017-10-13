from vault12factor import VaultAuth12Factor
import os
import logging
import distutils.util

logger = logging.getLogger(__name__)

VAULT_AUTH = None

VAULT_URL = os.environ.get('VAULT_URL')
VAULT_CACERT = os.environ.get('VAULT_CACERT')
VAULT_SSL_VERIFY = not bool(distutils.util.strtobool(os.environ.get('VAULT_SKIP_VERIFY', 'no')))
VAULT_DEBUG = bool(distutils.util.strtobool(os.environ.get('VAULT_DEBUG', 'no')))

VAULT_DATABASE_PATH = os.environ.get("VAULT_DATABASE_PATH")
VAULT_AWS_PATH = os.environ.get("VAULT_AWS_PATH")

DATABASE_OWNERROLE = os.environ.get("DATABASE_OWNERROLE")


def init_vault():
    global VAULT_AUTH
    if not VaultAuth12Factor.has_envconfig():
        logger.warning('Could not load Vault configuration from environment variables')
        return
    VAULT_AUTH = VaultAuth12Factor.fromenv()


def get_vault_auth():
    global VAULT_AUTH
    if not VAULT_AUTH:
        init_vault()
    return VAULT_AUTH
