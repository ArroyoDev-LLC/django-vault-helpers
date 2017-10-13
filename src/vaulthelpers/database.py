from vault12factor import VaultCredentialProvider, DjangoAutoRefreshDBCredentialsDict
from . import common
import logging
import dj_database_url

logger = logging.getLogger(__name__)


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

    if not common.VAULT_URL:
        logger.warning('Failed to load DB configuration from Vault: missing Vault API URL.')
        return db_config

    if not common.VAULT_DATABASE_PATH:
        logger.warning('Failed to load DB configuration from Vault: missing database secret path.')
        return db_config

    vault_auth = common.get_vault_auth()
    if not vault_auth:
        logger.warning('Failed to load DB configuration from Vault: missing Vault authentication.')
        return db_config

    vault_creds = VaultCredentialProvider(
        vaulturl=common.VAULT_URL,
        vaultauth=vault_auth,
        secretpath=common.VAULT_DATABASE_PATH,
        pin_cacert=common.VAULT_CACERT,
        ssl_verify=common.VAULT_SSL_VERIFY,
        debug_output=common.VAULT_DEBUG)

    try:
        db_config.update({
            'USER': vault_creds.username,
            'PASSWORD': vault_creds.password,
        })
    except Exception:
        logger.error('Failed to load configuration from Vault at path {}.'.format(common.VAULT_DATABASE_PATH))
        return db_config

    return DjangoAutoRefreshDBCredentialsDict(vault_creds, db_config)
