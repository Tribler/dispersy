"""
Helper class to easily and cleanly use singleton objects
"""

from threading import RLock

class Singleton(object):
    """
    Usage:

    class Foo(Singleton):
        def __init__(self, bar):
            self.bar = bar

    # create singleton instance and set bar = 123
    foo = Foo.get_instance(123)
    assert foo.bar == 123

    # retrieve existing singleton instance, Foo.__init__ is NOT called again
    foo = Foo.get_instance()
    assert foo.bar == 123

    # retrieve existing singleton instance, bar is NOT set to 456
    foo = Foo.get_instance(456)
    assert foo.bar == 123
    """
    
    _singleton_lock = RLock()

    @classmethod
    def get_instance(cls, *args, **kargs):
        if hasattr(cls, "_singleton_instance"):
            return getattr(cls, "_singleton_instance")
        
        with cls._singleton_lock:
            if not hasattr(cls, "_singleton_instance"):
                setattr(cls, "_singleton_instance", cls(*args, **kargs))
            return getattr(cls, "_singleton_instance")

class Parameterized1Singleton(object):
    """
    The required first parameter is used to uniquely identify a
    singleton instance.  Only one instance per first parameter will be
    created.

    class Bar(ParameterizedSingleton):
        def __init(self, name):
            self.name = name

    a1 = Bar.get_instance('a', 'a')
    a2 = Bar.get_instance('a', *whatever)
    b1 = Bar.get_instance('b', 'b')

    assert a1 == a2
    assert a1 != b1
    assert a2 != b2

    """

    _singleton_lock = RLock()

    @classmethod
    def get_instance(cls, *args, **kargs):
        assert len(args) > 0
        assert isinstance(args[0], (str, unicode, int, long, float))
        
        if hasattr(cls, "_singleton_instances") and args[0] in getattr(cls, "_singleton_instances"):
            return getattr(cls, "_singleton_instances")[args[0]]

        with cls._singleton_lock:
            instance = cls(*args, **kargs)
            if not hasattr(cls, "_singleton_instances"):
                setattr(cls, "_singleton_instances", {})
            getattr(cls, "_singleton_instances")[args[0]] = instance
            return instance
