from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestPruning(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_local_creation_causes_pruning(self):
        """
        SELF creates messages that should be properly pruned.

        - SELF creates 10 pruning messages [1:10].  These should be active.
        - SELF creates 10 pruning messages [11:20].  These new messages should be active, while
          [1:10] should become inactive.
        - SELF creates 10 pruning messages [21:30].  These new messages should be active, while
          [1:10] should be pruned and [11:20] should become inactive.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-global-time-pruning-text")

        # check settings
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        # create 10 pruning messages
        messages = [community.create_full_sync_global_time_pruning_text("Hello World #%d" % i, forward=False) for i in xrange(0, 10)]
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        inactive = messages
        messages = [community.create_full_sync_global_time_pruning_text("Hello World #%d" % i, forward=False) for i in xrange(10, 20)]
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        pruned = inactive
        inactive = messages
        messages = [community.create_full_sync_global_time_pruning_text("Hello World #%d" % i, forward=False) for i in xrange(20, 30)]
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # pruned messages should no longer exist in the database
        for message in pruned:
            try:
                self._dispersy.database.execute(u"SELECT * FROM sync WHERE id = ?", (message.packet_id,)).next()
            except StopIteration:
                pass
            else:
                self.fail("Message should not be in the database")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_local_creation_of_other_messages_causes_pruning(self):
        """
        SELF creates messages that should be properly pruned.

        - SELF creates 10 pruning messages [1:10].  These should be active.
        - SELF creates 10 normal messages [11:20].  [1:10] should become inactive.
        - SELF creates 10 normal messages [21:30].  [1:10] should become pruned.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-global-time-pruning-text")

        # check settings
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        # create 10 pruning messages
        messages = [community.create_full_sync_global_time_pruning_text("Hello World #%d" % i, forward=False) for i in xrange(0, 10)]
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        _ = [community.create_full_sync_text("Hello World #%d" % i, forward=False) for i in xrange(10, 20)]
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        _ = [community.create_full_sync_text("Hello World #%d" % i, forward=False) for i in xrange(20, 30)]
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        for message in messages:
            try:
                self._dispersy.database.execute(u"SELECT * FROM sync WHERE id = ?", (message.packet_id,)).next()
            except StopIteration:
                pass
            else:
                self.fail("Message should not be in the database")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_remote_creation_causes_pruning(self):
        """
        NODE creates messages that should cause proper pruning on SELF.

        - NODE creates 10 pruning messages [1:10] and gives them to SELF.  These should be active.
        - NODE creates 10 pruning messages [11:20] and gives them to SELF.  These new messages should
          be active, while [1:10] should become inactive.
        - NODE creates 10 pruning messages [21:30] and gives them to SELF.  These new messages should
          be active, while [1:10] should become pruned and [11:20] should become inactive.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-global-time-pruning-text")

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # check settings
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        # create 10 pruning messages
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i + 10) for i in xrange(0, 10)]
        node.give_messages(messages)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        inactive = messages
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i + 10) for i in xrange(10, 20)]
        node.give_messages(messages)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        pruned = inactive
        inactive = messages
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i + 10) for i in xrange(20, 30)]
        node.give_messages(messages)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # pruned messages should no longer exist in the database
        for message in pruned:
            try:
                self._dispersy.database.execute(u"SELECT * FROM sync WHERE id = ?", (message.packet_id,)).next()
            except StopIteration:
                pass
            else:
                self.fail("Message should not be in the database")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_remote_creation_of_other_messages_causes_pruning(self):
        """
        NODE creates messages that should cause proper pruning on SELF.

        - NODE creates 10 pruning messages [1:10] and gives them to SELF.  These should be active.
        - NODE creates 10 normal messages [11:20] and gives them to SELF.  The pruning messages [1:10]
          should become inactive.
        - NODE creates 10 normal messages [21:30] and give them to SELF.  The pruning messages [1:10]
          should become pruned.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-global-time-pruning-text")

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # check settings
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        # create 10 pruning messages
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i + 10) for i in xrange(0, 10)]
        node.give_messages(messages)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        _ = [node.create_full_sync_text("Hello World #%d" % i, i + 10) for i in xrange(10, 20)]
        node.give_messages(_)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        _ = [node.create_full_sync_text("Hello World #%d" % i, i + 10) for i in xrange(20, 30)]
        node.give_messages(_)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        for message in messages:
            try:
                self._dispersy.database.execute(u"SELECT * FROM sync WHERE id = ?", (message.packet_id,)).next()
            except StopIteration:
                pass
            else:
                self.fail("Message should not be in the database")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_sync_response_response_filtering_inactive(self):
        """
        Testing the bloom filter sync.

        - SELF creates 20 pruning messages [1:20].  Messages [1:10] will be inactive and [11:20] will
          be active.
        - NODE asks for a sync and receives the active messages [11:20].
        - SELF creates 5 normal messages [21:25].  Messages [1:5] will be pruned, [6:15] will become
          inactive, and [16:20] will become active.
        - NODE asks for a sync and received the active messages [16:20].
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-global-time-pruning-text")

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # check settings
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        # SELF creates 20 messages
        messages = [community.create_full_sync_global_time_pruning_text("Hello World #%d" % i, forward=False) for i in xrange(0, 20)]
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[0:10]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[10:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        node.drop_packets()
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time))
        yield 0.1

        # SELF should return the 10 active messages and nothing more
        responses = [response for _, response in node.receive_messages(message_names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(node.receive_messages(), [])
        self.assertEqual(len(responses), 10)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[10:20], responses)))

        # SELF creates 5 normal messages
        _ = [community.create_full_sync_text("Hello World #%d" % i, forward=False) for i in xrange(20, 25)]
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages[0:5]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[5:15]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[15:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        node.drop_packets()
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time))
        yield 0.1

        # SELF should return the 5 active messages and nothing more
        responses = [response for _, response in node.receive_messages(message_names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(node.receive_messages(), [])
        self.assertEqual(len(responses), 5)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[15:20], responses)))

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
