from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestIdenticalPayload(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_incoming__drop_first(self):
        """
        NODE creates two messages with the same community/member/global-time triplets.

        - One of the two should be dropped
        - Both binary signatures should end up in the bloom filter (temporarily) (NO LONGER THE CASE)
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        # create messages
        global_time = 10
        messages = []
        messages.append(node.create_full_sync_text("Identical payload message", global_time))
        messages.append(node.create_full_sync_text("Identical payload message", global_time))
        self.assertNotEqual(messages[0].packet, messages[1].packet, "the signature must make the messages unique")

        # sort.  we now know that the first message must be dropped
        messages.sort(key=lambda x: x.packet)

        # give messages in different batches
        node.give_message(messages[0])
        yield 0.555
        node.give_message(messages[1])
        yield 0.555

        # only one message may be in the database
        try:
            packet, =  self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                       (community.database_id, node.my_member.database_id, global_time)).next()
        except StopIteration:
            self.fail("neither messages is stored")

        packet = str(packet)
        self.assertEqual(packet, messages[1].packet)

        # 03/11/11 Boudewijn: we no longer store the ranges in memory, hence only the new packet
        # will be in the bloom filter
        #
        # both packets must be in the bloom filter
        # assert_(len(community._sync_ranges) == 1)
        # for message in messages:
        #     for bloom_filter in community._sync_ranges[0].bloom_filters:
        #         assert_(message.packet in bloom_filter)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_incoming__drop_second(self):
        """
        NODE creates two messages with the same community/member/global-time triplets.

        - One of the two should be dropped
        - Both binary signatures should end up in the bloom filter (temporarily) (NO LONGER THE CASE)
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        # create messages
        global_time = 10
        messages = []
        messages.append(node.create_full_sync_text("Identical payload message", global_time))
        messages.append(node.create_full_sync_text("Identical payload message", global_time))
        self.assertNotEqual(messages[0].packet, messages[1].packet, "the signature must make the messages unique")

        # sort.  we now know that the first message must be dropped
        messages.sort(key=lambda x: x.packet)

        # give messages in different batches
        node.give_message(messages[1])
        yield 0.555
        node.give_message(messages[0])
        yield 0.555

        # only one message may be in the database
        try:
            packet, =  self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                       (community.database_id, node.my_member.database_id, global_time)).next()
        except StopIteration:
            self.fail("neither messages is stored")

        packet = str(packet)
        self.assertEqual(packet, messages[1].packet)

        # 03/11/11 Boudewijn: we no longer store the ranges in memory, hence only the new packet
        # will be in the bloom filter
        #
        # both packets must be in the bloom filter
        # assert_(len(community._sync_ranges) == 1)
        # for message in messages:
        #     for bloom_filter in community._sync_ranges[0].bloom_filters:
        #         assert_(message.packet in bloom_filter)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
