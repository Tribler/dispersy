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
        
        else:
            cls._singleton_lock.acquire()
            try:
                if not hasattr(cls, "_singleton_instance"):
                    setattr(cls, "_singleton_instance", cls(*args, **kargs))
                return getattr(cls, "_singleton_instance")
            
            finally:
                cls._singleton_lock.release()
