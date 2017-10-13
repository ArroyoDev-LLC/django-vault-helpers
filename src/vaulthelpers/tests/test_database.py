from django.test import TestCase
from django.db import connection


class DatabaseConnectionTest(TestCase):

    def test_database_role(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT SESSION_USER, CURRENT_USER;")
            session_user, current_user = cursor.fetchone()
        self.assertRegex(session_user, r'^v\-token\-vaulthel\-', "The session user should be a transient user created by Vault.")
        self.assertEqual(current_user, 'vaulthelpers', "The current user should be the part role assumed after authentication.")
