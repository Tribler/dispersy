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

    def on_callback_exception(self, exception, is_fatal):
        if self._dispersy and self._dispersy.callback.is_running:
            self._dispersy.stop()
            self._dispersy = None
        return True

    def setUp(self):
        super(DispersyTestFunc, self).setUp()
        logger.debug("setUp")

        DispersyTestFunc._thread_counter += 1
        self._callback = Callback("Test-%d" % (self._thread_counter,))
        self._callback.attach_exception_handler(self.on_callback_exception)
        endpoint = StandaloneEndpoint(12345)
        working_directory = u"."
        database_filename = u":memory:"

        self._dispersy = Dispersy(self._callback, endpoint, working_directory, database_filename)
        self._dispersy.start()

        community_member = self._dispersy.callback.call(self._dispersy.get_new_member, (u"low",))
        self._community = self._dispersy.callback.call(DebugCommunity.create_community, (self._dispersy, community_member))

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


    def count_messages(self, message):
        packets_stored, = self._dispersy.database.execute(u"SELECT count(*) FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (self._community.database_id, message.authentication.member.database_id, message.database_id)).next()
        return packets_stored

    def assert_is_stored(self, message=None, messages=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                undone, packet = self._dispersy.database.execute(u"SELECT undone, packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                         (self._community.database_id, message.authentication.member.database_id, message.distribution.global_time)).next()
                self.assertEqual(undone, 0, "Message is undone")
                self.assertEqual(str(packet), message.packet)
            except StopIteration:
                self.fail("Message is not stored")

    def assert_not_stored(self, message=None, messages=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                         (self._community.database_id, message.authentication.member.database_id, message.distribution.global_time)).next()

                self.assertNotEqual(str(packet), message.packet)
            except StopIteration:
                pass

    assert_is_done = assert_is_stored
    def assert_is_undone(self, message=None, messages=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                         (self._community.database_id, message.authentication.member.database_id, message.distribution.global_time)).next()
                self.assertGreater(undone, 0, "Message is not undone")
            except StopIteration:
                self.fail("Message is not stored")
