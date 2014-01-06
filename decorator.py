from atexit import register as atexit_register
from cProfile import Profile
from collections import defaultdict
from functools import wraps
from thread import get_ident
from threading import current_thread
from time import time
import logging
import sys

from .logger import get_logger
logger = get_logger(__name__)


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

class RuntimeStatistic(object):
    def __init__(self):
        self._count = 0
        self._duration = 0.0

    @property
    def count(self):
        " Returns the number of times a method was called. "
        return self._count

    @property
    def duration(self):
        " Returns the cumulative time spent in a method. "
        return self._duration

    @property
    def average(self):
        " Returns the average time spent in a method. "
        return self._duration / self._count

    def increment(self, duration):
        " Increase self.count with 1 and self.duration with DURATION. "
        assert isinstance(duration, float), type(duration)
        self._duration += duration
        self._count += 1

    def get_dict(self, **kargs):
        " Returns a dictionary with the statistics. "
        return dict(count=self.count, duration=self.duration, average=self.average, **kargs)

_runtime_statistics = defaultdict(RuntimeStatistic)

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

       @attach_runtime_statistics("{function_name} bar={1}, moo={moo} returns={return_value}")
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
        @wraps(func)
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
