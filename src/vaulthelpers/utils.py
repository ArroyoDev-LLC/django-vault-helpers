import sys
import logging

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None

logger = logging.getLogger(__name__)


def log_exception(msg):
    if sentry_sdk is not None:
        sentry_sdk.capture_exception()
        logger.error('{} Exception: {}'.format(msg, str(sys.exc_info()[1])))
    else:
        logger.debug('Could not report exception to Sentry because raven is not installed.')
        logger.exception(msg)
