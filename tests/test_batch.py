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
    def test_one_batch(self):
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        messages = [node.create_batched_text("duplicates", i + 10) for i in range(10)]
        other.give_messages(messages, node, cache=True)

        # no messages may be in the database, as they need to be batched
        self.assertEqual(self.count_messages(messages[0]), 0)

        yield messages[0].meta.batch.max_window + 1.0

        # all of the messages must be stored in the database, as batch_window expired
        self.assertEqual(self.count_messages(messages[0]), 10)

    @call_on_dispersy_thread
    def test_multiple_batch(self):
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        messages = [node.create_batched_text("duplicates", i + 10) for i in range(10)]
        for message in messages:
            other.give_message(message, node, cache=True)

            # no messages may be in the database, as they need to be batched
            self.assertEqual(self.count_messages(message), 0)

        yield messages[0].meta.batch.max_window + 1.0

        # all of the messages must be stored in the database, as batch_window expired
        self.assertEqual(self.count_messages(messages[0]), 10)

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
        for message in messages:
            other.give_message(message, node)
        end = time()
        self._small_batches_took = end - begin

        meta = self._community.get_meta_message(u"full-sync-text")
        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)
