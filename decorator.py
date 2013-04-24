import logging
logger = logging.getLogger(__name__)

from atexit import register as atexit_register
from cProfile import Profile
from collections import defaultdict
from hashlib import sha1
from thread import get_ident
from threading import current_thread
from time import time
import sys

if __debug__:
    from time import sleep

class Constructor(object):
    """
    Allow a class to have multiple constructors.  The right one will
    be chosen based on the parameter types.

    class Foo(Constructor):
        @constructor(int)
        def _init_from_number(self, i):
            pass

        @constructor(str)
        def _init_from_str(self, s):
            pass
    """
    def __new__(cls, *args, **kargs):
        # We only need to get __constructors once per class
        if not hasattr(cls, "_Constructor__constructors"):
            constructors = []
            for m in dir(cls):
                attr = getattr(cls, m)
                if isinstance(attr, tuple) and len(attr) == 4 and attr[0] == "CONSTRUCTOR":
                    _, order, types, method = attr
                    constructors.append((order, types, method))
                    setattr(cls, m, method)
            constructors.sort()
            setattr(cls, "_Constructor__constructors", [(types, method) for _, types, method in constructors])
        return object.__new__(cls)

    def __init__(self, *args, **kargs):
        for types, method in getattr(self, "_Constructor__constructors"):
            if not len(types) == len(args):
                continue
            for type_, arg in zip(types, args):
                if not isinstance(arg, type_):
                    break
            else:
                return method(self, *args, **kargs)
        raise RuntimeError("No constructor found for", tuple(map(type, args)))

__constructor_order = 0
def constructor(*types):
    def helper(func):
        if __debug__:
            # do not do anything when running epydoc
            if sys.argv[0] == "(imported)":
                return func
        global __constructor_order
        __constructor_order += 1
        return "CONSTRUCTOR", __constructor_order, types, func
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

        return helper

else:
    def attach_profiler(func):
        return func

if "--runtime-statistics" in getattr(sys, "argv", []):
    _runtime_statistics_logger = logging.getLogger("runtime-statistics")
    _runtime_statistics = defaultdict(lambda: [0, 0.0])

    def _output_runtime_statistics():
        _runtime_statistics_logger.info(" COUNT      SUM      AVG  ENTRY")
        entries = [(stats[0], stats[1], entry) for entry, stats in _runtime_statistics.iteritems()]
        entries.sort()
        for count, duration, entry in entries:
            if "\n" in entry:
                print "<<<%s %dx %.2fs %.2fs\n%s\n>>>" % (sha1(entry).digest().encode("HEX"), count, duration, duration / count, entry)
                _runtime_statistics_logger.info("<<<%s %dx %.2fs %.2fs\n%s\n>>>", sha1(entry).digest().encode("HEX"), count, duration, duration / count, entry)

        for count, duration, entry in entries:
            print "%5dx %7.2fs %7.2fs  %s" % (count, duration, duration / count, "<%s>" % sha1(entry).digest().encode("HEX") if "\n" in entry else entry)
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
        def helper(func):
            return func
        return helper

if __debug__:
    def main():
        class Foo(Constructor):
            @constructor(int)
            def init_a(self, *args):
                self.init = int
                self.args = args
                self.clss = Foo

            @constructor(int, float)
            def init_b(self, *args):
                self.init = (int, float)
                self.args = args
                self.clss = Foo

            @constructor((str, unicode), )
            def init_c(self, *args):
                self.init = ((str, unicode), )
                self.args = args
                self.clss = Foo

        class Bar(Constructor):
            @constructor(int)
            def init_a(self, *args):
                self.init = int
                self.args = args
                self.clss = Bar

            @constructor(int, float)
            def init_b(self, *args):
                self.init = (int, float)
                self.args = args
                self.clss = Bar

            @constructor((str, unicode), )
            def init_c(self, *args):
                self.init = ((str, unicode), )
                self.args = args
                self.clss = Bar

        foo = Foo(1)
        assert foo.init == int
        assert foo.args == (1, )
        assert foo.clss == Foo

        foo = Foo(1, 1.0)
        assert foo.init == (int, float)
        assert foo.args == (1, 1.0)
        assert foo.clss == Foo

        foo = Foo("a")
        assert foo.init == ((str, unicode), )
        assert foo.args == ("a", )
        assert foo.clss == Foo

        foo = Foo(u"a")
        assert foo.init == ((str, unicode), )
        assert foo.args == (u"a", )
        assert foo.clss == Foo

        bar = Bar(1)
        assert bar.init == int
        assert bar.args == (1, )
        assert bar.clss == Bar

        bar = Bar(1, 1.0)
        assert bar.init == (int, float)
        assert bar.args == (1, 1.0)
        assert bar.clss == Bar

        bar = Bar("a")
        assert bar.init == ((str, unicode), )
        assert bar.args == ("a", )
        assert bar.clss == Bar

        bar = Bar(u"a")
        assert bar.init == ((str, unicode), )
        assert bar.args == (u"a", )
        assert bar.clss == Bar

        def invalid_args(cls, *args):
            try:
                obj = cls(*args)
                assert False
            except RuntimeError:
                pass

        invalid_args(Foo, 1.0)
        invalid_args(Foo, "a", 1)
        invalid_args(Foo, 1, 1.0, 1)
        invalid_args(Foo, [])

        invalid_args(Bar, 1.0)
        invalid_args(Bar, "a", 1)
        invalid_args(Bar, 1, 1.0, 1)
        invalid_args(Bar, [])

        print "Constructor test passed"

        @runtime_duration_warning(1.0)
        def test(delay):
            sleep(delay)

        test(0.5)
        test(1.5)

        print "Runtime duration test complete"

    if __name__ == "__main__":
        main()
