#!/usr/bin/env python
"""
Provision some secrets in the vault server for unit testing.
"""
import os
import hvac


vault = hvac.Client(
    url=os.environ['VAULT_URL'],
    token=os.environ['VAULT_ROOT_TOKEN'],
    verify=False)


backends = vault.list_auth_backends()
if 'approle/' not in backends:
    print('Enabling the approle auth backend...')
    vault.enable_auth_backend('approle')
else:
    print('AppRole auth backend is already mounted.')


backends = vault.list_secret_backends()
if 'database/' not in backends:
    print('Enabling the database secret backend...')
    vault.enable_secret_backend('database')
else:
    print('Database secret backend is already mounted.')


print('Provisioning policy for Django...')
vault.set_policy('vaulthelpers-sandbox', rules={
    "path": {
        "database/creds/vaulthelpers-sandbox": {
            "capabilities": [
                "read"
            ]
        },
        "secret/vaulthelpers-sandbox/django-settings": {
            "capabilities": [
                "read"
            ]
        },
    }
})


print('Provisioning app role and secret for Django...')
vault.create_role('vaulthelpers-sandbox',
    bind_secret_id=True,
    policies=['vaulthelpers-sandbox'],
    token_ttl='60m',
    token_max_ttl='60m')
vault.set_role_id('vaulthelpers-sandbox', os.environ['VAULT_ROLEID'])
try:
    vault.create_role_custom_secret_id('vaulthelpers-sandbox', os.environ['VAULT_SECRETID'])
except hvac.exceptions.InternalServerError:
    pass


print('Provisioning generic secret for Django settings...')
vault.write('secret/vaulthelpers-sandbox/django-settings',
    SECRET_KEY='my-django-secret-key',
    SOME_API_KEY='some-secret-api-key')


print('Provisioning PostgreSQL connection configuration...')
vault.write('database/config/vaulthelpers-sandbox',
    plugin_name='postgresql-database-plugin',
    allowed_roles='vaulthelpers-sandbox',
    connection_url='postgresql://vaulthelpers:supersecretpassword@postgres:5432/vaulthelpers?sslmode=disable')


print('Provisioning PostgreSQL role configuration...')
create_role_sql = "CREATE ROLE \"{{name}}\" WITH LOGIN ENCRYPTED PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE \"vaulthelpers\" INHERIT;"
vault.write('database/roles/vaulthelpers-sandbox',
    db_name='vaulthelpers-sandbox',
    creation_statements=create_role_sql,
    default_ttl='1h',
    max_ttl='24h')
