class VaultHelperError(Exception):
    pass


class VaultConfigurationError(VaultHelperError):
    pass


class VaultCredentialProviderError(VaultHelperError):
    pass
