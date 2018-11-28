===============================
Django Vault Helpers
===============================

|  |build| |license| |kit| |format|

This is a helper library with the goal of making it easier to retrieve secrets from Hasicorp Vault from a Django project.


Installation
============

Install ``django-vault-helpers`` from pip.

::

    $ pip install django-vault-helpers

Add the new packages to your installed apps.

::

    INSTALLED_APPS = [
        ...
        'vaulthelpers',
        ...
    ]


Authenticating to Vault
+++++++++++++++++++++++

Configure connection settings using environment variables to authenticate to Vault.

===========================  =============================================================
Environment Variable         Description
===========================  =============================================================
VAULT_URL                    Required. The URL of the Vault API. For example,
                             ``https://vault:8200/``.
VAULT_CACERT                 Optional. File path to the Vault CA certificate.
VAULT_SKIP_VERIFY            Optional. Set to disable validation of Vault's SSL cert.
VAULT_DEBUG                  Optional. Enable Vault debug logging.
===========================  =============================================================

In addition to the settings above, you must provide environment variables for one of the authentication methods below.

============================  =============================================================
Environment Variable          Description
============================  =============================================================
VAULT_TOKEN                   Token for Vault Token authentication
VAULT_APPID, VAULT_USERID     App-ID authentication
VAULT_ROLEID, VAULT_SECRETID  App-Role authentication
VAULT_SSLCERT, VAULT_SSLKEY   SSL Client Cert authentication
============================  =============================================================


Database Connection Secrets
+++++++++++++++++++++++++++

To use Vault to load database connection configuration and credentials, configure the Vault database secret backend as described in the `Database secret backend documentation <https://www.vaultproject.io/docs/secrets/databases/postgresql.html>`_. For example:

::

    $ vault mount database
    Successfully mounted 'database' at 'database'!
    $ CONNECTION_NAME='myapplication'
    $ CONNECTION_URL='postgresql://vaultuser:FOO@mydb:5432/myapplication'
    $ PARENT_ROLE_NAME='myapplication'
    $ vault write "database/config/$CONNECTION_NAME" \
            plugin_name="postgresql-database-plugin" \
            allowed_roles="$CONNECTION_NAME" \
            connection_url="$CONNECTION_URL"
    $ vault write "database/roles/$CONNECTION_NAME" \
            db_name="$CONNECTION_NAME" \
            creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN ENCRYPTED PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE \"${PARENT_ROLE_NAME}\" INHERIT NOCREATEROLE NOCREATEDB NOSUPERUSER NOREPLICATION;" \
            default_ttl="1h" \
            max_ttl="24h"


Next, add settings via the following environment variables.

===========================  =============================================================
Environment Variable         Description
===========================  =============================================================
VAULT_DATABASE_PATH          Vault path to read from when fetching database credentials.
                             For example, ``database/creds/myapplication``.
DATABASE_URL                 Database connection string, sans the username and password.
                             For example, ``postgres://mydb:5432/myapplication``.
DATABASE_OWNERROLE           For PostgreSQL, the name of the role to assume after
                             connecting using ``SET ROLE``
===========================  =============================================================

Finally, edit your projects ``settings.py`` file to load database configuration using Vault.

::

    import vaulthelpers

    # Load database credentials from Vault
    DATABASES = {
        'default': vaulthelpers.database.get_config(),
    }

To add additional keys to the database configuration, pass in a dictionary to the ``get_config`` call. For example:

::

    import vaulthelpers

    # Load database credentials from Vault
    DATABASES = {
        'default': vaulthelpers.database.get_config({
            'ATOMIC_REQUESTS': True,
            'CONN_MAX_AGE': 3600,
        }),
    }


AWS Credentials
+++++++++++++++

To use Vault to load IAM or STS credentials for AWS, configure the Vault AWS secret backend as described in the `AWS secret backend documentation <https://www.vaultproject.io/docs/secrets/aws/index.html>`_.

::

    $ vault mount aws
    Successfully mounted 'aws' at 'aws'!
    $ vault write aws/config/root \
            access_key=AKIAJWVN5Z4FOFT7NLNA \
            secret_key=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 \
            region=us-east-1
    $ vault write aws/roles/myapplication \
            arn=arn:aws:iam::ACCOUNT-ID-WITHOUT-HYPHENS:role/MyApplicationRoleName

Next, add settings via the following environment variables.

===========================  =============================================================
Environment Variable         Description
===========================  =============================================================
VAULT_AWS_PATH               Vault path to read from when fetching AWS credentials.
                             For example, ``aws/sts/myapplication``.
===========================  =============================================================

Finally, configure you Django project to load AWS credentials using Vault. To do this, edit the ``settings.py`` file to include the following line.

::

    import vaulthelpers

    # Load AWS credentials from Vault
    vaulthelpers.aws.init_boto3_credentials()

This will override the credential resolve code in ``boto3`` and ``botocore`` so that it will fetch credentials from Vault instead of the usual means, like environment variables or the EC2 metadata service.


Direct HVAC Client Access
+++++++++++++++++++++++++

To directly access the authentication ``hvac`` client connector, fetch it from the ``vaulthelpers.common`` module.

::

    import vaulthelpers

    vault_auth = vaulthelpers.common.get_vault_auth()
    verify = vaulthelpers.common.VAULT_CACERT or vaulthelpers.common.VAULT_SSL_VERIFY
    vcl = vault_auth.authenticated_client(vaulthelpers.common.VAULT_URL, verify=verify)
    result = vcl.read('secret/data/apps/myaplication')
    print(result)


Changelog
=========

0.6.0
+++++
- Add support for Django 2.1
- Add support for Python 3.7
- Migrate from Sentry's old SDK (raven) to their new SDK (sentry-sdk).

0.5.0
+++++
- Cache database and AWS credentials on the file system so that a multi-threaded / multi-process system doesn't need separate credentials for each process and thread.
- Improve security by setting the file permissions of all cache files (vault token, AWS, database) to only be readable by the owner.

0.4.2
+++++
- Fix Django 2.0 Deprecation warnings.

0.4.1
+++++
- Fix bug with SET ROLE when using the PostGIS database wrapper.

0.4.0
+++++
- Fix bug with Database credential fetch code when a lease appears to still be valid but isn't, due to it's parent token getting revoked.
- Added tests for database and AWS components.
- Dropped dependencies on ``12factor-vault`` and ``django-postgresql-setrole``. When upgrading to this version, it is recommended to uninstall these packages.

0.3.3
+++++
- Fix bug in with passing url parameter to HVAC client in ``common.EnvironmentConfig``
- Improve testing.
- Support Django 2.0

0.3.2
+++++
- Prevent recycling TCP connections after forking a process.

0.3.1
+++++
- Fixed TCP connection issue by caching VaultAuthenticator instance in thread local storage.

0.3.0
+++++
- Add file system caching of vault tokens.

0.2.0
+++++
- Add S3 storage backend based on ``storages.backends.s3boto3.S3Boto3Storage``.

0.1.0
+++++
- Initial release.


.. |build| image:: https://gitlab.com/thelabnyc/django-vault-helpers/badges/master/build.svg
    :target: https://gitlab.com/thelabnyc/django-vault-helpers/commits/master
.. |license| image:: https://img.shields.io/pypi/l/django-vault-helpers.svg
    :target: https://pypi.python.org/pypi/
.. |kit| image:: https://badge.fury.io/py/django-vault-helpers.svg
    :target: https://pypi.python.org/pypi/django-vault-helpers
.. |format| image:: https://img.shields.io/pypi/format/django-vault-helpers.svg
    :target: https://pypi.python.org/pypi/django-vault-helpers
