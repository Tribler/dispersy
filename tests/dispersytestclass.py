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


class DispersyTestFunc(TestCase):

    """
    Setup and tear down Dispersy before and after each test method.

    setUp will ensure the following members exists before each test method is called:
    - self._dispersy
    - self._my_member

    tearDown will ensure these members are properly cleaned after each test method is finished.
    """

    def on_callback_exception(self, exception, is_fatal):
        logger.exception("%s", exception)

        # properly shutdown Dispersy, note that it will always return False since
        # on_callback_exception is running on the callback thread making it impossible to have the
        # thread closed while this call is still being performed
        self.assertFalse(self._dispersy.stop())
        self._dispersy = None

        # consider every exception a fatal error
        return True

    def setUp(self):
        super(DispersyTestFunc, self).setUp()
        logger.debug("setUp")

        callback = Callback("Dispersy-Unit-Test")
        callback.attach_exception_handler(self.on_callback_exception)
        endpoint = StandaloneEndpoint(12345)
        working_directory = u"."
        database_filename = u":memory:"

        self._dispersy_stop_success = None
        self._dispersy = Dispersy(callback, endpoint, working_directory, database_filename)
        self._dispersy.start()
        self._my_member = callback.call(self._dispersy.get_new_member, (u"low",))

    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()
        logger.debug("tearDown")

        if self._dispersy:
            self.assertTrue(self._dispersy.stop())
            self._dispersy = None
        self._my_member = None
