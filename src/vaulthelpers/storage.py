from storages.backends.s3boto3 import S3Boto3Storage as BaseS3Boto3Storage
import boto3


class S3Boto3Storage(BaseS3Boto3Storage):
    @property
    def connection(self):
        connection = getattr(self._connections, 'connection', None)
        if connection is None:
            self._connections.connection = boto3.resource('s3',
                region_name=self.region_name,
                use_ssl=self.use_ssl,
                endpoint_url=self.endpoint_url,
                config=self.config)
        return self._connections.connection
