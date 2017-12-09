from .base import VaultHelperTest
import vaulthelpers


class EnvironmentConfigTest(VaultHelperTest):

    def test_dictionary_keys(self):
        config = vaulthelpers.EnvironmentConfig('secret/vaulthelpers-sandbox/django-settings')
        self.assertEquals(config['SECRET_KEY'], 'my-django-secret-key')
        self.assertEquals(config['SOME_API_KEY'], 'some-secret-api-key')


    def test_get_method(self):
        config = vaulthelpers.EnvironmentConfig('secret/vaulthelpers-sandbox/django-settings')
        self.assertEquals(config.get('SECRET_KEY'), 'my-django-secret-key')
        self.assertEquals(config.get('SOME_API_KEY'), 'some-secret-api-key')


    def test_default_for_nonexisting_key(self):
        config = vaulthelpers.EnvironmentConfig('secret/vaulthelpers-sandbox/django-settings')
        self.assertEquals(config.get('MISSING_KEY'), None)
        self.assertEquals(config.get('MISSING_KEY', 'my-default'), 'my-default')


    def test_environment_variable_fallback(self):
        config = vaulthelpers.EnvironmentConfig('secret/vaulthelpers-sandbox/django-settings')
        self.assertEquals(config['DATABASE_OWNERROLE'], 'vaulthelpers')
        with self.assertRaises(KeyError):
            config['MISSING_KEY']
        self.assertEquals(config.get('DATABASE_OWNERROLE'), 'vaulthelpers')
        self.assertEquals(config.get('MISSING_KEY'), None)
