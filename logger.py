import functools
import logging
import socket
import warnings


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

#warnings.simplefilter('always', DeprecationWarning)

class deprecated(object):
    def __init__(self, msg=None):
        """
        A decorator which can be used to mark functions
        as deprecated.It will result in a deprecation warning being shown
        when the function is used.
        """
        self.msg = msg

    def __call__(self, func):
        message = self.msg or "Use of deprecated function '{}`.".format(func.__name__)

        @functools.wraps(func)
        def wrapper_func(*args, **kwargs):
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper_func


# build context filter
_context_filter = ContextFilter(socket.gethostname())
