from .base import VaultHelperTest
from django.db import connection
from django.contrib.auth.models import User
import vaulthelpers
import os
import hvac


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
        self.assertRegex(config['USER'], r'^v-approle-vaulthel-([a-zA-Z0-9]+)-([0-9]+)$')
        self.assertRegex(config['PASSWORD'], r'^.+$')
        self.assertEqual(config['HOST'], 'postgres')
        self.assertEqual(config['PORT'], 5432)
        self.assertEqual(config['CONN_MAX_AGE'], 3600)
        self.assertEqual(config['ENGINE'], 'django.db.backends.postgresql_psycopg2')
        self.assertEqual(config['SET_ROLE'], 'vaulthelpers')
        self.assertEqual(config['ATOMIC_REQUESTS'], True)


    def test_renew_db_creds_with_unbroken_connection(self):
        # Ensure the DB connection is usable
        self.assertEqual('root', User.objects.get(username='root').username)

        # Get the current user
        with connection.cursor() as cursor:
            cursor.execute("SELECT CURRENT_USER;")
            current_user_A, = cursor.fetchone()
        self.assertEqual(current_user_A, 'vaulthelpers')

        # Get a reference to the standard Vault client (used to obtain DB creds)
        standard_client = vaulthelpers.common.get_vault_auth().authenticated_client()

        # Ensure the standard client is usable
        self.assertTrue(standard_client.is_authenticated())

        # Using the root token, revoke the token which granted the database credential lease. This will drop the current SESSION_USER from PostgreSQL.
        root_client = hvac.Client(url=vaulthelpers.common.VAULT_URL, token=os.environ['VAULT_ROOT_TOKEN'])
        root_client.revoke_token(standard_client.token)

        # Ensure the standard client is not usable
        self.assertFalse(standard_client.is_authenticated())

        # Ensure the DB connection is still usable
        self.assertEqual('root', User.objects.get(username='root').username)

        # Get the current and session user
        with connection.cursor() as cursor:
            cursor.execute("SELECT CURRENT_USER;")
            current_user_B, = cursor.fetchone()
        self.assertEqual(current_user_B, 'vaulthelpers')


    def test_renew_db_creds_with_broken_connection(self):
        # Ensure the DB connection is usable
        self.assertEqual('root', User.objects.get(username='root').username)

        # Get the current and session user
        with connection.cursor() as cursor:
            cursor.execute("SELECT SESSION_USER, CURRENT_USER;")
            session_user_A, current_user_A = cursor.fetchone()
        self.assertRegex(session_user_A, r'^v\-approle\-vaulthel\-')
        self.assertEqual(current_user_A, 'vaulthelpers')

        # Get a reference to the standard Vault client (used to obtain DB creds)
        standard_client = vaulthelpers.common.get_vault_auth().authenticated_client()

        # Ensure the standard client is usable
        self.assertTrue(standard_client.is_authenticated())

        # Using the root token, revoke the token which granted the database credential lease. This will drop the current SESSION_USER from PostgreSQL.
        root_client = hvac.Client(url=vaulthelpers.common.VAULT_URL, token=os.environ['VAULT_ROOT_TOKEN'])
        root_client.revoke_token(standard_client.token)

        # Ensure the standard client is not usable
        self.assertFalse(standard_client.is_authenticated())

        # Close the connection to force a reconnect
        connection.close()
        connection.settings_dict.reset_credentials()

        # Ensure the DB connection is still usable
        self.assertEqual('root', User.objects.get(username='root').username)

        # Get the current and session user
        with connection.cursor() as cursor:
            cursor.execute("SELECT SESSION_USER, CURRENT_USER;")
            session_user_B, current_user_B = cursor.fetchone()
        self.assertRegex(session_user_B, r'^v\-approle\-vaulthel\-')
        self.assertEqual(current_user_B, 'vaulthelpers')

        # Make sure the first session user isn't the same as the second (to prove that the test actually forced a credential re-fetch)
        self.assertNotEqual(session_user_A, session_user_B)

        # Close the connection to force another reconnect, but this time without destroying the user
        connection.close()
        connection.settings_dict.reset_credentials()

        # Ensure the DB connection is still usable
        self.assertEqual('root', User.objects.get(username='root').username)

        # Get the current and session user
        with connection.cursor() as cursor:
            cursor.execute("SELECT SESSION_USER, CURRENT_USER;")
            session_user_C, current_user_C = cursor.fetchone()
        self.assertRegex(session_user_C, r'^v\-approle\-vaulthel\-')
        self.assertEqual(current_user_C, 'vaulthelpers')

        # Make sure the second session user **is** the same as the third (to prove that the credential caching works)
        self.assertEqual(session_user_B, session_user_C)
