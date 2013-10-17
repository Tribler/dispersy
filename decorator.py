from atexit import register as atexit_register
from cProfile import Profile
from collections import defaultdict
from hashlib import sha1
from thread import get_ident
from threading import current_thread
from time import time
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

if "--runtime-statistics" in getattr(sys, "argv", []):
    _runtime_statistics_logger = get_logger("runtime-statistics")
    _runtime_statistics = defaultdict(lambda: [0, 0.0])

    def _output_runtime_statistics():
        entries = sorted([(stats[0], stats[1], entry) for entry, stats in _runtime_statistics.iteritems()])
        for count, duration, entry in entries:
            if "\n" in entry:
                _runtime_statistics_logger.info("<<<%s %dx %.2fs %.2fs\n%s\n>>>", sha1(entry).digest().encode("HEX"), count, duration, duration / count, entry)

        _runtime_statistics_logger.info(" COUNT      SUM      AVG  ENTRY")
        for count, duration, entry in entries:
            _runtime_statistics_logger.info("%5dx %7.2fs %7.2fs  %s", count, duration, duration / count, entry.strip().split("\n")[0])
    atexit_register(_output_runtime_statistics)

    def attach_runtime_statistics(format_):
        def helper(func):
            def attach_runtime_statistics_helper(*args, **kargs):
                start = time()
                try:
                    return func(*args, **kargs)
                finally:
                    end = time()
                    entry = format_.format(function_name=func.__name__, *args, **kargs)
                    _runtime_statistics_logger.debug(entry)
                    stats = _runtime_statistics[entry]
                    stats[0] += 1
                    stats[1] += (end - start)
            attach_runtime_statistics_helper.__name__ = func.__name__
            return attach_runtime_statistics_helper
        return helper

else:
    def attach_runtime_statistics(format_):
        """
        Keep track of how often and how long a function was called.

        Runtime statistics will only be collected when sys.argv contains '--runtime-statistics'.
        Otherwise the decorator will not influence the runtime in any way.

        FORMAT_ must be a (unicode)string.  Each unique string tracks individual statistics.
        FORMAT_ uses the format mini language and has access to all the arguments and keyword
        arguments of the function.  Furthermore, the function name is available as a keyword
        argument called 'function_name'.  The python format mini language is described at:
        http://docs.python.org/2/library/string.html#format-specification-mini-language.

           @attach_runtime_statistics("{function_name} bar={1}, moo={moo}")
           def foo(self, bar, moo='milk'):
               pass

           foo(1)
           foo(2)
           foo(2)

        After running the above example, the statistics will show that:
        - 'foo bar=1 moo=milk' was called once
        - 'foo bar=2 moo=milk' was called twice
        """
        def helper(func):
            return func
        return helper
