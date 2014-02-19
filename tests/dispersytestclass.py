from unittest import TestCase
from .debugcommunity.community import DebugCommunity

from ..callback import Callback
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint
from ..logger import get_logger
logger = get_logger(__name__)


def call_on_dispersy_thread(func):
    def helper(*args, **kargs):
        return args[0]._dispersy.callback.call(func, args, kargs, priority= -1024)
    helper.__name__ = func.__name__
    return helper


class DispersyTestFunc(TestCase):

    # every Dispersy instance gets its own Callback thread with its own number.  this is useful in
    # some debugging scenarios.
    _thread_counter = 0

    """
    Setup and tear down Dispersy before and after each test method.

    setUp will ensure the following members exists before each test method is called:
    - self._callback
    - self._dispersy
    - self._my_member
    - self._enable_strict

    tearDown will ensure these members are properly cleaned after each test method is finished.
    """

    def on_callback_exception(self, exception, is_fatal):
        if self.enable_strict and self._dispersy and self._dispersy.callback.is_running:
            self._dispersy.stop()
            self._dispersy = None

        # consider every exception a fatal error when 'strict' is enabled
        return self.enable_strict

    @property
    def enable_strict(self):
        return self._enable_strict

    @enable_strict.setter
    def enable_strict(self, enable_strict):
        assert isinstance(enable_strict, bool), type(enable_strict)
        self._enable_strict = enable_strict

    def setUp(self):
        super(DispersyTestFunc, self).setUp()
        logger.debug("setUp")

        self._enable_strict = True
        DispersyTestFunc._thread_counter += 1
        self._callback = Callback("Test-%d" % (self._thread_counter,))
        self._callback.attach_exception_handler(self.on_callback_exception)
        endpoint = StandaloneEndpoint(12345)
        working_directory = u"."
        database_filename = u":memory:"

        self._dispersy = Dispersy(self._callback, endpoint, working_directory, database_filename)
        self._dispersy.start()
        self.create_community()

    @call_on_dispersy_thread
    def create_community(self):
        self._community = DebugCommunity.create_community(self._dispersy, self._dispersy.get_new_member(u"low"))

    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()
        logger.debug("tearDown")

        if self._dispersy and self._callback.is_running:
            self.assertTrue(self._dispersy.stop(10.0))

        else:
            # Dispersy was stopped because an exception occurred, hence Dispersy.stop was called
            # from its own thread which doesn't allow Dispersy.stop to wait until its thread is
            # closed.
            self.assertTrue(self._callback.join(10.0))

        self._callback = None
        self._dispersy = None
        self._community = None
