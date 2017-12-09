from django.test import TestCase
import vaulthelpers


class VaultHelperTest(TestCase):
    def setUp(self):
            vaulthelpers.common.reset_vault()
