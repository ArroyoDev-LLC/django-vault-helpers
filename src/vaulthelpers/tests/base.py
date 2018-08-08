from django.db import connection
from django.test import TransactionTestCase
from django.contrib.auth.models import User
import vaulthelpers
import hvac
import os


class VaultHelperTest(TransactionTestCase):
    def setUp(self):
        # Close the database connection
        connection.close()
        connection.connection = None

        # Revoke all the non-root tokens in Vault
        root_client = self.get_root_client()
        accessors = root_client.adapter.get('/v1/auth/token/accessors?list=true').json()['data']['keys']
        for accessor in accessors:
            params = { 'accessor': accessor }
            token_meta = root_client.adapter.post('/v1/auth/token/lookup-accessor', json=params).json()
            if token_meta['data']['display_name'] == 'approle':
                root_client.adapter.post('/v1/auth/token/revoke-accessor', json=params)

        # Reset the vault cache
        vaulthelpers.common.reset_vault()

        # Create a Django user
        User.objects.create_user(username='root', email='root@example.com')


    def get_root_client(self):
        return hvac.Client(url=vaulthelpers.common.VAULT_URL, token=os.environ['VAULT_ROOT_TOKEN'])
