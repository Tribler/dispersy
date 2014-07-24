from .dispersytestclass import DispersyTestFunc


class TestPruning(DispersyTestFunc):

    def _create_prune(self, node, globaltime_start, globaltime_end, store=True):
        messages = [node.create_full_sync_global_time_pruning_text("Hello World #%d" % i, i) for i in xrange(globaltime_start, globaltime_end + 1)]
        if store:
            node.store(messages)
        return messages

    def _create_normal(self, node, globaltime_start, globaltime_end, store=True):
        messages = [node.create_full_sync_text("Hello World #%d" % i, i) for i in xrange(globaltime_start, globaltime_end + 1)]
        if store:
            node.store(messages)
        return messages

    def test_local_creation_causes_pruning(self):
        """
        NODE creates messages that should be properly pruned.

        - NODE creates 10 pruning messages [11:20]. These should be active.
        - NODE creates 10 pruning messages [21:30]. [11:20] should become inactive.
        - NODE creates 10 pruning messages [31:40]. [11:20] should be pruned and [21:30] should become inactive.
        """

        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node, = self.create_nodes(1)

        messages = self._create_prune(node, 11, 20)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        inactive = messages
        messages = self._create_prune(node, 21, 30)

        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        pruned = inactive
        inactive = messages
        messages = self._create_prune(node, 31, 40)

        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # pruned messages should no longer exist in the database
        node.assert_not_stored(messages=pruned)

    def test_local_creation_of_other_messages_causes_pruning(self):
        """
        NODE creates messages that should be properly pruned.

        - NODE creates 10 pruning messages [11:20].  These should be active.
        - NODE creates 10 normal messages [21:30].  [11:20] should become inactive.
        - NODE creates 10 normal messages [31:40].  [11:20] should become pruned.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node, = self.create_nodes(1)

        # create 10 pruning messages
        messages = self._create_prune(node, 11, 20)
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        self._create_normal(node, 21, 30)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        self._create_normal(node, 31, 40)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        node.assert_not_stored(messages=messages)

    def test_remote_creation_causes_pruning(self):
        """
        NODE creates messages that should cause pruning on OTHER

        - NODE creates 10 pruning messages [11:20] and gives them to OTHER.
        - NODE creates 10 pruning messages [21:30] and gives them to OTHER. [11:20] should become inactive.
        - NODE creates 10 pruning messages [31:40] and gives them to OTHER. [11:20] should become pruned and [21:30] should become inactive.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node, other = self.create_nodes(2)

        # create 10 pruning messages
        other.give_messages(self._create_prune(node, 11, 20, store=False), node)

        # we need to let other fetch the messages
        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 pruning messages
        other.give_messages(self._create_prune(node, 21, 30, store=False), node)

        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        should_be_inactive = [message for message in messages if message.distribution.global_time <= 20]
        should_be_active = [message for message in messages if 20 < message.distribution.global_time <= 30]
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in should_be_inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in should_be_active), "all messages should be active")

        # create 10 pruning messages
        messages = self._create_prune(node, 31, 40, store=False)
        other.give_messages(messages, node)

        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        should_be_pruned = [message for message in messages if message.distribution.global_time <= 20]
        should_be_inactive = [message for message in messages if 20 < message.distribution.global_time <= 30]
        should_be_active = [message for message in messages if 30 < message.distribution.global_time <= 40]
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in should_be_pruned), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in should_be_inactive), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in should_be_active), "all messages should be active")

        # pruned messages should no longer exist in the database
        other.assert_not_stored(messages=should_be_pruned)

    def test_remote_creation_of_other_messages_causes_pruning(self):
        """
        NODE creates messages that should cause pruning on OTHER

        - NODE creates 10 pruning messages [11:20] and gives them to OTHER. 
        - NODE creates 10 normal messages [21:30] and gives them to OTHER. [11:20] should become inactive.
        - NODE creates 10 normal messages [31:40] and give them to OTHER.  [11:20] should become pruned.
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node, other = self.create_nodes(2)

        # create 10 pruning messages
        messages = self._create_prune(node, 11, 20, store=False)
        other.give_messages(messages, node)

        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages), "all messages should be active")

        # create 10 normal messages
        other.give_messages(self._create_normal(node, 21, 30, store=False), node)

        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages), "all messages should be inactive")

        # create 10 normal messages
        other.give_messages(self._create_normal(node, 31, 40, store=False), node)

        messages = other.fetch_messages([u"full-sync-global-time-pruning-text", ])
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages), "all messages should be pruned")

        # pruned messages should no longer exist in the database
        other.assert_not_stored(messages=messages)

    def test_sync_response_response_filtering_inactive(self):
        """
        Testing the bloom filter sync.

        - OTHER creates 20 pruning messages [11:30].  Messages [11:20] will be inactive and [21:30] will
          be active.
        - NODE asks for a sync and receives the active messages [21:30].
        - OTHER creates 5 normal messages [31:35].  Messages [11:15] will be pruned, [16:25] will become
          inactive, and [26:30] will become active.
        - NODE asks for a sync and received the active messages [26:30].
        """
        # check settings
        meta = self._community.get_meta_message(u"full-sync-global-time-pruning-text")
        self.assertEqual(meta.distribution.pruning.inactive_threshold, 10, "check message configuration")
        self.assertEqual(meta.distribution.pruning.prune_threshold, 20, "check message configuration")

        node, other = self.create_nodes(2)
        other.send_identity(node)

        # OTHER creates 20 messages
        messages = self._create_prune(other, 11, 30)
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[0:10]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[10:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time), node)

        # OTHER should return the 10 active messages
        responses = [response for _, response in node.receive_messages(names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(len(responses), 10)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[10:20], responses)))

        # OTHER creates 5 normal messages
        self._create_normal(other, 31, 35)
        self.assertTrue(all(message.distribution.pruning.is_pruned() for message in messages[0:5]), "all messages should be pruned")
        self.assertTrue(all(message.distribution.pruning.is_inactive() for message in messages[5:15]), "all messages should be inactive")
        self.assertTrue(all(message.distribution.pruning.is_active() for message in messages[15:20]), "all messages should be active")

        # NODE requests missing messages
        sync = (1, 0, 1, 0, [])
        global_time = 1  # ensure we do not increase the global time, causing further pruning
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, global_time), node)

        # OTHER should return the 5 active pruning messages
        responses = [response for _, response in node.receive_messages(names=[u"full-sync-global-time-pruning-text"])]
        self.assertEqual(len(responses), 5)
        self.assertTrue(all(message.packet == response.packet for message, response in zip(messages[15:20], responses)))
