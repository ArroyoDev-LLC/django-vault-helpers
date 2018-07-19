from datetime import datetime, timedelta
from freezegun import freeze_time
from .base import VaultHelperTest
import vaulthelpers
import boto3
import pytz
import os
import requests_mock


class AWSCredentialsTest(VaultHelperTest):

    def setUp(self):
        super().setUp()
        boto3.DEFAULT_SESSION = None
        try:
            os.unlink('/tmp/.vault-aws-34ac139d5002477fce8d63447f0f2569')
            os.unlink('/tmp/.vault-aws-34ac139d5002477fce8d63447f0f2569.lock')
        except FileNotFoundError:
            pass
        vaulthelpers.aws.init_boto3_credentials()


    def mock_sts_creds(self, rmock, suffix):
        rmock.get('http://vault:8200/v1/aws/sts/vaulthelpers-sandbox', json={
            'lease_duration': 3600,
            'data': {
                'access_key': "access-key-{}".format(suffix),
                'secret_key': "secret-key-{}".format(suffix),
                'security_token': "security-token-{}".format(suffix),
            },
        })


    @requests_mock.mock(real_http=True)
    def test_obtain_sts_creds(self, rmock):
        self.mock_sts_creds(rmock, 'A')

        # Should fetch credentials
        creds = boto3._get_default_session().get_credentials()
        self.assertEqual(creds.access_key, "access-key-A")
        self.assertEqual(creds.secret_key, "secret-key-A")
        self.assertEqual(creds.token, "security-token-A")

        self.mock_sts_creds(rmock, 'B')

        # Should used cached credentials
        creds = boto3._get_default_session().get_credentials()
        self.assertEqual(creds.access_key, "access-key-A")
        self.assertEqual(creds.secret_key, "secret-key-A")
        self.assertEqual(creds.token, "security-token-A")


    @requests_mock.mock(real_http=True)
    def test_renew_sts_creds(self, rmock):
        now = datetime.now(tz=pytz.UTC)
        self.mock_sts_creds(rmock, 'A')

        # Should fetch credentials
        with freeze_time(now):
            creds = boto3._get_default_session().get_credentials()
            self.assertEqual(creds.access_key, "access-key-A")
            self.assertEqual(creds.secret_key, "secret-key-A")
            self.assertEqual(creds.token, "security-token-A")
            self.assertFalse(creds.refresh_needed())

        self.mock_sts_creds(rmock, 'B')

        # Should fetch credentials again, since the time changed
        with freeze_time(now + timedelta(hours=2)):
            creds = boto3._get_default_session().get_credentials()
            self.assertTrue(creds.refresh_needed())
            self.assertEqual(creds.access_key, "access-key-B")
            self.assertEqual(creds.secret_key, "secret-key-B")
            self.assertEqual(creds.token, "security-token-B")


    @requests_mock.mock(real_http=True)
    def test_sts_creds_auto_refresh(self, rmock):
        now = datetime.now(tz=pytz.UTC)
        self.mock_sts_creds(rmock, 'A')

        # Should fetch credentials
        with freeze_time(now):
            creds = boto3._get_default_session().get_credentials()
            self.assertEqual(creds.access_key, "access-key-A")
            self.assertEqual(creds.secret_key, "secret-key-A")
            self.assertEqual(creds.token, "security-token-A")
            self.assertFalse(creds.refresh_needed())

        self.mock_sts_creds(rmock, 'B')

        # Should fetch credentials again, since the time changed
        with freeze_time(now + timedelta(hours=2)):
            self.assertEqual(creds.access_key, "access-key-B")
            self.assertEqual(creds.secret_key, "secret-key-B")
            self.assertEqual(creds.token, "security-token-B")
