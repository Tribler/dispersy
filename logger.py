import logging
import socket


def get_logger(name):
    logger = logging.getLogger(name)
    logger.addFilter(_context_filter)
    return logger

def get_context_filter():
    return _context_filter

class ContextFilter(logging.Filter):
    # Note: logging.Filter is an old-style class.  Hence super(...) and @property.setter do not work
    def __init__(self, identifier):
        logging.Filter.__init__(self)
        self.identifier = identifier

    def filter(self, record):
        record.identifier = self.identifier
        return True


# build context filter
_context_filter = ContextFilter(socket.gethostname())
