import logging.config
import os.path
import socket


def get_logger(name):
    logger = logging.getLogger(name)
    logger.addFilter(_context_filter)
    return logger


class ContextFilter(logging.Filter):
    _hostname = socket.gethostname()
    def filter(self, record):
        record.hostname = self._hostname
        return True


# build context filter
_context_filter = ContextFilter()

# use logger.conf if it exists
if os.path.exists("logger.conf"):
    # will raise an exception when logger.conf is malformed
    logging.config.fileConfig("logger.conf")

# fallback to basic configuration when needed
logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s")

