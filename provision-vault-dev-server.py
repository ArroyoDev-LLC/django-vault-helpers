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


# backends = vault.list_auth_backends()
backends = vault.sys.list_auth_methods()
if 'approle/' not in backends:
    print('Enabling the approle auth backend...')
    vault.sys.enable_auth_method('approle')
else:
    print('AppRole auth backend is already mounted.')


backends = vault.sys.list_mounted_secrets_engines()
if 'secret/' not in backends:
    print('Enabling the K/V secret backend...')
    vault.sys.enable_secrets_engine('kv', config={'version': 2})
else:
    print('K/V secret backend is already mounted.')


backends = vault.sys.list_mounted_secrets_engines()
if 'database/' not in backends:
    print('Enabling the database secret backend...')
    vault.sys.enable_secrets_engine('database')
else:
    print('Database secret backend is already mounted.')


print('Provisioning policy for Django...')
vault.sys.create_or_update_policy('vaulthelpers-sandbox', policy={
    "path": {
        "database/creds/vaulthelpers-sandbox": {
            "capabilities": [
                "read"
            ]
        },
        "secret/data/vaulthelpers-sandbox/django-settings": {
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
vault.write('secret/data/vaulthelpers-sandbox/django-settings',
    data={
        "SECRET_KEY": 'my-django-secret-key',
        "SOME_API_KEY": 'some-secret-api-key',
    })


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
