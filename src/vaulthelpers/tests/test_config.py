from .base import VaultHelperTest
import vaulthelpers


class EnvironmentConfigTest(VaultHelperTest):

    def test_dictionary_keys(self):
        config = vaulthelpers.EnvironmentConfig('secret/data/vaulthelpers-sandbox/django-settings', kv_version=2)
        self.assertEqual(config['SECRET_KEY'], 'my-django-secret-key')
        self.assertEqual(config['SOME_API_KEY'], 'some-secret-api-key')


    def test_get_method(self):
        config = vaulthelpers.EnvironmentConfig('secret/data/vaulthelpers-sandbox/django-settings', kv_version=2)
        self.assertEqual(config.get('SECRET_KEY'), 'my-django-secret-key')
        self.assertEqual(config.get('SOME_API_KEY'), 'some-secret-api-key')


    def test_default_for_nonexisting_key(self):
        config = vaulthelpers.EnvironmentConfig('secret/data/vaulthelpers-sandbox/django-settings', kv_version=2)
        self.assertEqual(config.get('MISSING_KEY'), None)
        self.assertEqual(config.get('MISSING_KEY', 'my-default'), 'my-default')


    def test_environment_variable_fallback(self):
        config = vaulthelpers.EnvironmentConfig('secret/data/vaulthelpers-sandbox/django-settings', kv_version=2)
        self.assertEqual(config['DATABASE_OWNERROLE'], 'vaulthelpers')
        with self.assertRaises(KeyError):
            config['MISSING_KEY']
        self.assertEqual(config.get('DATABASE_OWNERROLE'), 'vaulthelpers')
        self.assertEqual(config.get('MISSING_KEY'), None)
