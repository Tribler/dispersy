
import logging
logger = logging.getLogger(__name__)

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
    - cls._dispersy
    - cls._my_member

    tearDownClass will ensure these members are properly cleaned after all the class tests have
    finished.
    """
    @classmethod
    def setUpClass(cls):
        super(DispersyTestClass, cls).setUpClass()

        callback = Callback("Dispersy-Unit-Test")
        endpoint = StandaloneEndpoint(12345)
        working_directory = u"."
        database_filename = u":memory:"

        cls._dispersy = Dispersy(callback, endpoint, working_directory, database_filename)
        cls._dispersy.start()
        cls._my_member = callback.call(cls._dispersy.get_new_member, (u"low",))

    @classmethod
    def tearDownClass(cls):
        super(DispersyTestClass, cls).tearDownClass()
        cls._dispersy.stop()
