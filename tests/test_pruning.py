from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestPruning(DispersyTestFunc):

    def _create_prune(self, node, globaltime_start, globaltime_end, store=True):
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i + 10) for i in xrange(globaltime_start, globaltime_end)]
        if store:
            self._dispersy._store(messages)
        return messages

    def _create_normal(self, node, globaltime_start, globaltime_end, store=True):
        messages = [node.create_full_sync_text("Hello World #%d" % i, i + 10) for i in xrange(globaltime_start, globaltime_end)]
        if store:
            self._dispersy._store(messages)
        return messages

    @call_on_dispersy_thread
    def test_local_creation_causes_pruning(self):
        """
        NODE creates messages that should be properly pruned.

        - NODE creates 10 pruning messages [1:10]. These should be active.
        - NODE creates 10 pruning messages [11:20]. [1:10] should become inactive.
        - NODE creates 10 pruning messages [21:30]. [1:10] should be pruned and [11:20] should become inactive.
        """

        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        messages = self._create_prune(node, 0, 10)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        inactive = messages
        messages = self._create_prune(node, 10, 20)

        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        pruned = inactive
        inactive = messages
        messages = self._create_prune(node, 20, 30)

        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # pruned messages should no longer exist in the database
        self.assert_not_stored(messages=pruned)

    @call_on_dispersy_thread
    def test_local_creation_of_other_messages_causes_pruning(self):
        """
        NODE creates messages that should be properly pruned.

        - NODE creates 10 pruning messages [1:10].  These should be active.
        - NODE creates 10 normal messages [11:20].  [1:10] should become inactive.
        - NODE creates 10 normal messages [21:30].  [1:10] should become pruned.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        # create 10 pruning messages
        messages = self._create_prune(node, 0, 10)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        self._create_normal(node, 10, 20)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        self._create_normal(node, 20, 30)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        self.assert_not_stored(messages=messages)

    @call_on_dispersy_thread
    def test_remote_creation_causes_pruning(self):
        """
        NODE creates messages that should cause pruning on OTHER

        - NODE creates 10 pruning messages [1:10] and gives them to OTHER.
        - NODE creates 10 pruning messages [11:20] and gives them to OTHER. [1:10] should become inactive.
        - NODE creates 10 pruning messages [21:30] and gives them to OTHER. [1:10] should become pruned and [11:20] should become inactive.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # TODO: without actual separate databases, this doesn't really test anything
        # create 10 pruning messages
        messages = self._create_prune(node, 0, 10, store=False)
        other.give_messages(messages, node)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        inactive = messages
        messages = self._create_prune(node, 10, 20, store=False)
        other.give_messages(messages, node)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        pruned = inactive
        inactive = messages
        messages = self._create_prune(node, 20, 30, store=False)
        other.give_messages(messages, node)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # pruned messages should no longer exist in the database
        self.assert_not_stored(messages=pruned)

    @call_on_dispersy_thread
    def test_remote_creation_of_other_messages_causes_pruning(self):
        """
        NODE creates messages that should cause pruning on OTHER

        - NODE creates 10 pruning messages [1:10] and gives them to OTHER. 
        - NODE creates 10 normal messages [11:20] and gives them to OTHER. [1:10] should become inactive.
        - NODE creates 10 normal messages [21:30] and give them to OTHER.  [1:10] should become pruned.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # TODO: without actual separate databases, this doesn't really test anything
        # create 10 pruning messages
        messages = self._create_prune(node, 0, 10, store=False)
        other.give_messages(messages, node)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        other.give_messages(self._create_normal(node, 10, 20, store=False), node)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        other.give_messages(self._create_normal(node, 20, 30, store=False), node)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        self.assert_not_stored(messages=messages)

    @call_on_dispersy_thread
    def test_sync_response_response_filtering_inactive(self):
        """
        Testing the bloom filter sync.

        - OTHER creates 20 pruning messages [1:20].  Messages [1:10] will be inactive and [11:20] will
          be active.
        - NODE asks for a sync and receives the active messages [11:20].
        - OTHER creates 5 normal messages [21:25].  Messages [1:5] will be pruned, [6:15] will become
          inactive, and [16:20] will become active.
        - NODE asks for a sync and received the active messages [16:20].
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # OTHER creates 20 messages
        messages = self._create_prune(other, 0, 20)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[0:10]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[10:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        other.give_message(node.create_dispersy_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time), node)
        yield 0.1

        # OTHER should return the 10 active messages
        responses = [response for _, response in node.receive_messages(names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(len(responses), 10)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[10:20], responses)))

        # OTHER creates 5 normal messages
        self._create_normal(other, 20, 25)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages[0:5]), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[5:15]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[15:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        other.give_message(node.create_dispersy_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time), node)
        yield 0.1

        # OTHER should return the 5 active pruning messages
        responses = [response for _, response in node.receive_messages(names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(len(responses), 5)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[15:20], responses)))
