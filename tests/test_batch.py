from time import time

from ..logger import get_logger
from ..message import Message, BatchConfiguration
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestBatch(DispersyTestFunc):

    def __init__(self, *args, **kargs):
        super(TestBatch, self).__init__(*args, **kargs)
        self._big_batch_took = 0.0
        self._small_batches_took = 0.0

    @call_on_dispersy_thread
    def test_one_batch_binary_duplicate(self):
        """
        When multiple binary identical UDP packets are received, the duplicate packets need to be
        reduced to one packet.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        message = node.create_full_sync_text("duplicates", 10)

        other.give_packets([message.packet for _ in xrange(10)], node)

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (self._community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [10])

    @call_on_dispersy_thread
    def test_one_batch_member_global_time_duplicate(self):
        """
        A member can create invalid duplicate messages that are binary different.

        For instance, two different messages that are created by the same member and have the same
        global_time, will be binary different while they are still duplicates.  Because dispersy
        uses the message creator and the global_time to uniquely identify messages.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        other.give_messages([node.create_full_sync_text("duplicates (%d)" % index, 10) for index in xrange(10)], node)

        # only one message may be in the database
        meta = self._community.get_meta_message(u"full-sync-text")
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (self._community.database_id, node.my_member.database_id, meta.database_id))]
        self.assertEqual(times, [10])

    @call_on_dispersy_thread
    def test_one_big_batch(self, length=1000):
        """
        Each community is handled in its own batch, hence we can measure performance differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time) for global_time in xrange(10, 10 + length)]

        begin = time()
        other.give_messages(messages, node)
        end = time()
        self._big_batch_took = end - begin

        meta = self._community.get_meta_message(u"full-sync-text")
        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)

    @call_on_dispersy_thread
    def test_many_small_batches(self, length=1000):
        """
        Each community is handled in its own batch, hence we can measure performace differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time) for global_time in xrange(10, 10 + length)]

        begin = time()
        for message in messages:
            other.give_message(message, node)
        end = time()
        self._small_batches_took = end - begin

        meta = self._community.get_meta_message(u"full-sync-text")
        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)
