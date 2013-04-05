from unittest import TestCase

from ..callback import Callback
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint

def call_on_dispersy_thread(func):
    def helper(*args, **kargs):
        return args[0]._dispersy.callback.call(func, args, kargs)
    helper.__name__ = func.__name__
    return helper

class DispersyTestClass(TestCase):
    """
    Setup Dispersy test.

    setUpClass will ensure the following members exists:
    - cls._callback
    - cls._dispersy
    - cls._dispersy.endpoint
    - cls._my_member

    tearDownClass will ensure these members are properly cleaned after all the class tests have
    finished.
    """
    @classmethod
    def setUpClass(cls):
        super(DispersyTestClass, cls).setUpClass()

        def create_dispersy():
            dispersy = Dispersy(cls._callback, u".", u":memory:")
            dispersy.endpoint = StandaloneEndpoint(dispersy, 12345)
            dispersy.endpoint.start()
            return dispersy

        cls._callback = Callback()
        cls._callback.start()
        cls._dispersy = cls._callback.call(create_dispersy)
        cls._my_member = cls._callback.call(cls._dispersy.get_new_member, (u"low",))

    @classmethod
    def tearDownClass(cls):
        super(DispersyTestClass, cls).tearDownClass()
        cls._callback.call(cls._dispersy.endpoint.stop)
        cls._callback.call(cls._dispersy.stop)
        cls._callback.stop()
