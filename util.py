import Queue
import functools
import logging
import sys
import traceback
import warnings
from cProfile import Profile
from socket import inet_aton, error as socket_error
from thread import get_ident
from threading import current_thread
from time import time

from twisted.internet import reactor, defer
from twisted.internet.task import LoopingCall
from twisted.python import failure
from twisted.python.threadable import isInIOThread

from .statistics import _runtime_statistics


logger = logging.getLogger(__name__)


MEMORY_DUMP_INTERVAL = float(60 * 60)


#
# Various decorators
#

def call_on_reactor_thread(func):
    def helper(*args, **kargs):
        if isInIOThread():
            # TODO(emilon): Do we really want it to block if its on the reactor thread?
            return func(*args, **kargs)
        else:
            return reactor.callFromThread(func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


def blocking_call_on_reactor_thread(func):
    def helper(*args, **kargs):
        if isInIOThread():
            return func(*args, **kargs)
        else:
            return blockingCallFromThread(reactor, func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


def documentation(documented_func):
    def helper(func):
        if documented_func.__doc__:
            prefix = documented_func.__doc__ + "\n"
        else:
            prefix = ""
        func.__doc__ = prefix + "\n        @note: This documentation is copied from " + documented_func.__class__.__name__ + "." + documented_func.__name__
        return func
    return helper

if __debug__:
    def runtime_duration_warning(threshold):
        assert isinstance(threshold, float), type(threshold)
        assert 0.0 <= threshold

        def helper(func):
            def runtime_duration_warning_helper(*args, **kargs):
                start = time()
                try:
                    return func(*args, **kargs)
                finally:
                    end = time()
                    if end - start >= threshold:
                        logger.warning("%.2fs %s", end - start, func)
            runtime_duration_warning_helper.__name__ = func.__name__ + "_RDWH"
            return runtime_duration_warning_helper
        return helper

else:
    def runtime_duration_warning(threshold):
        def helper(func):
            return func
        return helper

# Niels 21-06-2012: argv seems to be missing if python is not started as a script
if "--profiler" in getattr(sys, "argv", []):
    _profiled_threads = set()

    def attach_profiler(func):
        def helper(*args, **kargs):
            filename = "profile-%s-%d.out" % (current_thread().name, get_ident())
            if filename in _profiled_threads:
                raise RuntimeError("Can not attach profiler on the same thread twice")

            logger.debug("running with profiler [%s]", filename)
            _profiled_threads.add(filename)
            profiler = Profile()

            try:
                return profiler.runcall(func, *args, **kargs)
            finally:
                logger.debug("profiler results [%s]", filename)
                profiler.dump_stats(filename)
                _profiled_threads.remove(filename)

        return helper

else:
    def attach_profiler(func):
        return func


def attach_runtime_statistics(format_):
    """
    Keep track of how often and how long a function was called.

    FORMAT_ must be a (unicode)string.  Each unique string tracks individual statistics.  FORMAT_
    uses the format mini language and has access to all the arguments and keyword arguments of the
    function.  The python format mini language is described at:
    http://docs.python.org/2/library/string.html#format-specification-mini-language.

    Furthermore, two keyword arguments are provided:
    - function_name: is set to the func.__name__, and
    - return_value: is set to the value returned by func

       @attach_runtime_statistics(u"{function_name} bar={1}, moo={moo} returns={return_value}")
       def foo(self, bar, moo='milk'):
           return bar + 40

       foo(1)
       foo(2)
       foo(2)

    After running the above example, the statistics will show that:
    - 'foo bar=1 moo=milk returns=41' was called once
    - 'foo bar=2 moo=milk returns=42' was called twice

    Updated runtime information is available from Dispersy.statistics.runtime after calling
    Dispersy.statistics.update().  Statistics.runtime is a list (in no particular order) containing
    dictionaries with the keys: count, duration, average, and entry.
    """
    assert isinstance(format_, basestring), type(format_)

    def helper(func):
        @functools.wraps(func)
        def wrapper(*args, **kargs):
            return_value = None
            start = time()
            try:
                return_value = func(*args, **kargs)
                return return_value
            finally:
                end = time()
                entry = format_.format(function_name=func.__name__, return_value=return_value, *args, **kargs)
                _runtime_statistics[entry].increment(end - start)
        return wrapper
    return helper


class deprecated(object):

    def __init__(self, msg=None):
        """
        A decorator which can be used to mark functions
        as deprecated.  It will result in a deprecation warning being shown
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


#
# General Instrumentation stuff
#

def init_instrumentation():
    """
    Instrumentation initializer, starts the components enabled trough the command line arguments.
    """
    if "--memory-dump" in sys.argv:
        start_memory_dumper()


def start_memory_dumper():
    """
    Initiates the memory profiler.
    """
    start = time()
    from meliae import scanner
    LoopingCall(lambda: scanner.dump_all_objects("memory-%d.out" % (time() - start))).start(MEMORY_DUMP_INTERVAL, now=True)
    reactor.addSystemEventTrigger("before", "shutdown", lambda: scanner.dump_all_objects("memory-%d-shutdown.out" % (time() - start)))

#
# Other utils
#


def unhandled_error_observer(event):
    """
    Stop the reactor if we get an unhandled error.
    """
    if event['isError']:
        logger.warning("Strict, mode enabled, stopping the reactor")
        # TODO(emilon): Should we try to stop dispersy too?
        reactor.exitCode = 1
        if reactor.running:
            reactor.stop()


def blockingCallFromThread(reactor, f, *a, **kw):
    """
    Improved version of twisted's blockingCallFromThread that shows the complete
    stacktrace when an exception is raised on the reactor's thread.

    """
    queue = Queue.Queue()

    def _callFromThread():
        result = defer.maybeDeferred(f, *a, **kw)
        result.addBoth(queue.put)
    reactor.callFromThread(_callFromThread)
    result = queue.get()
    if isinstance(result, failure.Failure):
        other_thread_tb = traceback.extract_tb(result.getTracebackObject())
        this_thread_tb = traceback.extract_stack()
        logger.error("Exception raised on the reactor's thread '%s'.\n Traceback from this thread:\n%s\n"
                     " Traceback from the reactor's thread:\n %s", result.getErrorMessage(),
                     ''.join(traceback.format_list(this_thread_tb)), ''.join(traceback.format_list(other_thread_tb)))
        result.raiseException()
    return result

#
# Misc general validation functions
#

def is_valid_address(address):
        """
        Returns True when ADDRESS is valid.

        ADDRESS must be supplied as a (HOST string, PORT integer) tuple.

        An address is valid when it meets the following criteria:
        - HOST must be non empty
        - HOST must be non '0.0.0.0'
        - PORT must be > 0
        - HOST must be 'A.B.C.D' where A, B, and C are numbers higher or equal to 0 and lower or
          equal to 255.  And where D is higher than 0 and lower than 255
        """
        assert isinstance(address, tuple), type(address)
        assert len(address) == 2, len(address)
        assert isinstance(address[0], str), type(address[0])
        assert isinstance(address[1], int), type(address[1])

        if address[0] == "":
            return False

        if address[0] == "0.0.0.0":
            return False

        if address[1] <= 0:
            return False

        try:
            binary = inet_aton(address[0])
        except socket_error:
            return False

        # ending with .0
        # Niels: is now allowed, subnet mask magic call actually allow for this
        #        if binary[3] == "\x00":
        #            return False

        # ending with .255
        # Niels: same for this one, if the netmask is /23 a .255 could indicate 011111111 which is allowed
        #        if binary[3] == "\xff":
        #            return False

        return True
