import sys
import logging

try:
    from raven.contrib.django.raven_compat.models import client as raven_client
except ImportError:
    raven_client = None

logger = logging.getLogger(__name__)


def log_exception(msg):
    if raven_client is not None:
        raven_client.captureException()
        logger.error('{} Exception: {}'.format(msg, str(sys.exc_info()[1])))
    else:
        logger.debug('Could not report exception to Sentry because raven is not installed.')
        logger.exception(msg)
