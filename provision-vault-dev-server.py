#!/usr/bin/env python
import os
import hvac


vault = hvac.Client(
    url=os.environ['VAULT_URL'],
    token=os.environ['VAULT_TOKEN'],
    verify=False)


backends = vault.list_secret_backends()
if 'database/' not in backends:
    print('Enabling the database secret backend...')
    vault.enable_secret_backend('database')
else:
    print('Database secret backend is already mounted.')


print('Provisioning PostgreSQL connection configuration...')
resp = vault.write('database/config/vaulthelpers-sandbox',
    plugin_name='postgresql-database-plugin',
    allowed_roles='vaulthelpers-sandbox',
    connection_url='postgresql://vaulthelpers:supersecretpassword@postgres:5432/vaulthelpers?sslmode=disable')


print('Provisioning PostgreSQL role configuration...')
create_role_sql = "CREATE ROLE \"{{name}}\" WITH LOGIN ENCRYPTED PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE \"vaulthelpers\" INHERIT;"
resp = vault.write('database/roles/vaulthelpers-sandbox',
    db_name='vaulthelpers-sandbox',
    creation_statements=create_role_sql,
    default_ttl='1h',
    max_ttl='24h')
