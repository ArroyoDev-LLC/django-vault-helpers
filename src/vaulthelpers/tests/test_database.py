from .base import VaultHelperTest
from django.db import connection
import vaulthelpers
import os


class DatabaseConnectionTest(VaultHelperTest):

    def test_database_role(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT SESSION_USER, CURRENT_USER;")
            session_user, current_user = cursor.fetchone()
        self.assertRegex(session_user, r'^v\-approle\-vaulthel\-', "The session user should be a transient user created by Vault.")
        self.assertEqual(current_user, 'vaulthelpers', "The current user should be the part role assumed after authentication.")


    def test_config(self):
        # Make sure environment variables are set to configure the DB host, port, name, etc.
        self.assertEqual(os.environ.get('DATABASE_URL'), 'postgres://postgres:5432/vaulthelpers')
        self.assertEqual(os.environ.get('DATABASE_OWNERROLE'), 'vaulthelpers')
        self.assertEqual(os.environ.get('VAULT_DATABASE_PATH'), 'database/creds/vaulthelpers-sandbox')

        # Fetch the configuration from Vault.
        config = vaulthelpers.database.get_config({
            'ATOMIC_REQUESTS': True,
            'CONN_MAX_AGE': 3600,
        })

        # Make sure the output configuration merged everything together correctly.
        self.assertEqual(config['NAME'], 'vaulthelpers')
        self.assertRegex(config['USER'], r'^v-approle-vaulthel-([a-z0-9]+)-([0-9]+)$')
        self.assertRegex(config['PASSWORD'], r'^.+$')
        self.assertEqual(config['HOST'], 'postgres')
        self.assertEqual(config['PORT'], 5432)
        self.assertEqual(config['CONN_MAX_AGE'], 3600)
        self.assertEqual(config['ENGINE'], 'django.db.backends.postgresql_psycopg2')
        self.assertEqual(config['SET_ROLE'], 'vaulthelpers')
        self.assertEqual(config['ATOMIC_REQUESTS'], True)
