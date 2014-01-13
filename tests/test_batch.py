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

    def test_max_batch_size_A(self):
        return self._dispersy.callback.call(self._max_batch_size, kargs=dict(length=1000 - 1, max_size=25))

    def test_max_batch_size_B(self):
        return self._dispersy.callback.call(self._max_batch_size, kargs=dict(length=1000, max_size=25))

    def test_max_batch_size_C(self):
        return self._dispersy.callback.call(self._max_batch_size, kargs=dict(length=1000 + 1, max_size=25))

    def _max_batch_size(self, length, max_size):
        """
        Gives many messages at once, the system should process them in max-batch-size batches.
        """
        class MaxBatchSizeCommunity(DebugCommunity):

            def _initialize_meta_messages(self):
                super(MaxBatchSizeCommunity, self)._initialize_meta_messages()

                batch = BatchConfiguration(max_window=0.01, max_size=max_size)

                meta = self._meta_messages[u"full-sync-text"]
                meta = Message(meta.community, meta.name, meta.authentication, meta.resolution, meta.distribution, meta.destination, meta.payload, meta.check_callback, meta.handle_callback, meta.undo_callback, batch=batch)
                self._meta_messages[meta.name] = meta

        community = MaxBatchSizeCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("START BIG BATCH (with max batch size)")
        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time) for global_time in xrange(10, 10 + length)]

        begin = time()
        node.give_messages(messages, cache=True)

        # wait till the batch is processed
        meta = community.get_meta_message(u"full-sync-text")
        while meta in self._dispersy._batch_cache:
            yield 0.1

        end = time()
        logger.debug("%2.2f seconds for _max_batch_size(%d, %d)", end - begin, length, max_size)

        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_one_batch_binary_duplicate(self):
        """
        When multiple binary identical UDP packets are received, the duplicate packets need to be
        reduced to one packet.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        global_time = 10
        message = node.create_full_sync_text("duplicates", global_time)
        node.give_packets([message.packet for _ in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_two_batches_binary_duplicate(self):
        """
        When multiple binary identical UDP packets are received, the duplicate packets need to be
        reduced to one packet.

        The second batch needs to be dropped aswell, while the last unique packet of the second
        batch is dropped when the when the database is consulted.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        global_time = 10
        # first batch
        message = node.create_full_sync_text("duplicates", global_time)
        node.give_packets([message.packet for _ in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # second batch
        node.give_packets([message.packet for _ in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_one_batch_member_global_time_duplicate(self):
        """
        A member can create invalid duplicate messages that are binary different.

        For instance, two different messages that are created by the same member and have the same
        global_time, will be binary different while they are still duplicates.  Because dispersy
        uses the message creator and the global_time to uniquely identify messages.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        global_time = 10
        node.give_messages([node.create_full_sync_text("duplicates (%d)" % index, global_time) for index in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, meta.database_id))]
        self.assertEqual(times, [global_time])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_two_batches_member_global_time_duplicate(self):
        """
        A member can create invalid duplicate messages that are binary different.

        For instance, two different messages that are created by the same member and have the same
        global_time, will be binary different while they are still duplicates.  Because dispersy
        uses the message creator and the global_time to uniquely identify messages.

        The second batch needs to be dropped aswell, while the last unique packet of the second
        batch is dropped when the when the database is consulted.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        global_time = 10
        # first batch
        node.give_messages([node.create_full_sync_text("duplicates (%d)" % index, global_time) for index in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, meta.database_id))]
        self.assertEqual(times, [global_time])

        # second batch
        node.give_messages([node.create_full_sync_text("duplicates (%d)" % index, global_time) for index in xrange(10)])

        # only one message may be in the database
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, meta.database_id))]
        self.assertEqual(times, [global_time])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_one_big_batch(self, length=1000):
        """
        Each community is handled in its own batch, hence we can measure performace differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("START BIG BATCH")
        messages = [node.create_full_sync_text("Dprint=False, big batch #%d" % global_time, global_time) for global_time in xrange(10, 10 + length)]

        begin = time()
        node.give_messages(messages)
        end = time()
        self._big_batch_took = end - begin

        meta = community.get_meta_message(u"full-sync-text")
        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_many_small_batches(self, length=1000):
        """
        Each community is handled in its own batch, hence we can measure performace differences when
        we make one large batch (using one community) and many small batches (using many different
        communities).
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("START SMALL BATCHES")
        messages = [node.create_full_sync_text("Dprint=False, small batch #%d" % global_time, global_time) for global_time in xrange(10, 10 + length)]

        begin = time()
        for message in messages:
            node.give_message(message)
        end = time()
        self._small_batches_took = end - begin

        meta = community.get_meta_message(u"full-sync-text")
        count, = self._dispersy.database.execute(u"SELECT COUNT(1) FROM sync WHERE meta_message = ?", (meta.database_id,)).next()
        self.assertEqual(count, len(messages))

        if self._big_batch_took and self._small_batches_took:
            self.assertSmaller(self._big_batch_took, self._small_batches_took * 1.1)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
