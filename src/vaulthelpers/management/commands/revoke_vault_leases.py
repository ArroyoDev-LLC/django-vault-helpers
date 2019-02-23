from django.core.management.base import BaseCommand
from vaulthelpers import common


class Command(BaseCommand):
    help = 'Revoke the active Vault token and any associated secret leases'

    def handle(self, *args, **options):
        client = common.get_vault_auth().authenticated_client()
        client.revoke_self_token()
        self.stdout.write('Revoked Vault token and all associated secret leases')
