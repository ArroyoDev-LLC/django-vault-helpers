from django.core.management.base import BaseCommand
from vaulthelpers import common


class Command(BaseCommand):
    help = 'Revoke the active Vault token and any associated secret leases'

    def handle(self, *args, **options):
        authenticator = common.get_vault_auth()
        if authenticator is None:
            return
        client = authenticator.authenticated_client()
        client.revoke_self_token()
        self.stdout.write('Revoked Vault token and all associated secret leases')
