from unittest import mock
from .base import VaultHelperTest
import vaulthelpers


class VaultAuthenticationTest(VaultHelperTest):

    @mock.patch('os.getpid')
    @mock.patch('hvac.Client')
    def test_process_forking(self, Client, getpid):
        # Mock the PID, so that we can test process forking
        getpid.return_value = 1

        # Construct a mock Vault client
        mockClient = mock.MagicMock()
        Client.return_value = mockClient

        # Client should not have been created yet
        self.assertEqual(Client.call_count, 0)

        # Construct a client
        vaulthelpers.common.get_vault_auth().authenticated_client()

        # Client should have been created called once
        self.assertEqual(Client.call_count, 1)

        # Construct a client again
        vaulthelpers.common.get_vault_auth().authenticated_client()

        # Existing client should have been recycled, rather than recreated
        self.assertEqual(Client.call_count, 1)

        # Change the PID, simulating the process getting forked after a client already exists
        getpid.return_value = 2

        # Construct a client again
        vaulthelpers.common.get_vault_auth().authenticated_client()

        # Since the PID changed, the existing client should have been discarded and a new one created.
        self.assertEqual(Client.call_count, 2)


    def test_token_recycling(self):
        # Construct a client and record the token it gets after logging in
        vcl = vaulthelpers.common.get_vault_auth().authenticated_client()
        token_A = vcl.token

        # Construct a client again and get it's token.
        vcl = vaulthelpers.common.get_vault_auth().authenticated_client()
        token_B = vcl.token

        # Token should be reused, not regenerated.
        self.assertEqual(token_A, token_B)

        # Force the client to be destroyed, then create it again.
        vaulthelpers.common.reset_vault()
        vcl = vaulthelpers.common.get_vault_auth().authenticated_client()
        token_C = vcl.token

        # Token should be reused again, this time due to file caching.
        self.assertEqual(token_A, token_C)

        # Purge the file cache, force the client to be destroyed, then create the client again.
        vaulthelpers.common.get_vault_auth().purge_token_cache()
        vaulthelpers.common.reset_vault()
        vcl = vaulthelpers.common.get_vault_auth().authenticated_client()
        token_D = vcl.token

        # Token should be different this time.
        self.assertNotEqual(token_A, token_D)

        # Once more, destroy the client and get a token
        vaulthelpers.common.reset_vault()
        vcl = vaulthelpers.common.get_vault_auth().authenticated_client()
        token_E = vcl.token

        # Cache should have recycled token_D again
        self.assertEqual(token_D, token_E)
