from unittest import TestCase

from ..callback import Callback
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint


def call_on_dispersy_thread(func):
    def helper(*args, **kargs):
        return args[0]._dispersy.callback.call(func, args, kargs)
    helper.__name__ = func.__name__
    return helper


class DispersyTestFunc(TestCase):

    """
    Setup and tear down Dispersy before and after each test method.

    setUp will ensure the following members exists before each test method is called:
    - self._dispersy
    - self._my_member

    tearDown will ensure these members are properly cleaned after each test method is finished.
    """

    def setUp(self):
        super(DispersyTestFunc, self).setUp()

        callback = Callback("Dispersy-Unit-Test")
        endpoint = StandaloneEndpoint(12345)
        working_directory = u"."
        database_filename = u":memory:"

        self._dispersy = Dispersy(callback, endpoint, working_directory, database_filename)
        self._dispersy.start()
        self._my_member = callback.call(self._dispersy.get_new_member, (u"low",))

    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()
        self._dispersy.stop()
        self._dispersy = None
        self._my_member = None

class DispersyTestClass(TestCase):

    """
    Setup and tear down Dispersy before the first and after the last test method.

    setUpClass will ensure the following members exists before the first test method in the class is called:
    - cls._dispersy
    - cls._my_member

    tearDownClass will ensure these members are properly cleaned after after the last class test has finished.
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
        cls._dispersy = None
        cls._my_member = None
