from collections import defaultdict

from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestIncomingMissingSequence(DispersyTestFunc):

    @call_on_dispersy_thread
    def incoming_simple_conflict_different_global_time(self):
        """
        A broken NODE creates conflicting messages with the same sequence number that SELF should
        properly filter.

        We use the following messages:
        - M@5#1 :: global time 5, sequence number 1
        - M@6#1 :: global time 6, sequence number 1
        - etc...

        TODO Same payload?  Different signatures?
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"sequence-text")
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # MSGS[GLOBAL-TIME][SEQUENCE-NUMBER]
        with self._dispersy.database:
            msgs = defaultdict(dict)
            for i in xrange(1, 10):
                for j in xrange(1, 10):
                    msgs[i][j] = node.create_sequence_text("M@%d#%d" % (i, j), i, j)

        community.delete_messages(meta.name)
        # SELF must accept M@6#1
        node.give_message(msgs[6][1])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[6][1].packet])

        # SELF must reject M@6#1 (already have this message)
        node.give_message(msgs[6][1])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[6][1].packet])

        # SELF must prefer M@5#1 (duplicate sequence number, prefer lower global time)
        node.give_message(msgs[5][1])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet])

        # SELF must reject M@6#1 (duplicate sequence number, prefer lower global time)
        node.give_message(msgs[6][1])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet])

        # SELF must reject M@4#2 (global time is lower than previous global time in sequence)
        node.give_message(msgs[4][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet])

        # SELF must reject M@5#2 (global time is lower than previous global time in sequence)
        node.give_message(msgs[5][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet])

        # SELF must accept M@7#2
        node.give_message(msgs[7][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[7][2].packet])

        # SELF must reject M@7#2 (already have this message)
        node.give_message(msgs[7][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[7][2].packet])

        # SELF must prefer M@6#2 (duplicate sequence number, prefer lower global time)
        node.give_message(msgs[6][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet])

        # SELF must reject M@7#2 (duplicate sequence number, prefer lower global time)
        node.give_message(msgs[7][2])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet])

        # SELF must reject M@4#3 (global time is lower than previous global time in sequence)
        node.give_message(msgs[4][3])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet])

        # SELF must reject M@6#3 (global time is lower than previous global time in sequence)
        node.give_message(msgs[6][3])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet])

        # SELF must accept M@8#3
        node.give_message(msgs[8][3])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet, msgs[8][3].packet])

        # SELF must accept M@9#4
        node.give_message(msgs[9][4])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet, msgs[8][3].packet, msgs[9][4].packet])

        # SELF must accept M@7#3
        # It would be possible to keep M@9#4, but the way that the code is structures makes this
        # difficult (i.e. M@7#3 has not yet passed all the numerous checks at the point where we
        # have to delete).  In the future we can optimize by pushing the newer messages (such as
        # M@7#3) into the waiting or incoming packet queue, this will allow them to be re-inserted
        # after M@6#2 has been fully accepted.
        node.give_message(msgs[7][3])
        self.assertEqual(community.fetch_packets(meta.name), [msgs[5][1].packet, msgs[6][2].packet, msgs[7][3].packet])

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    def test_requests_1_1(self):
        self.requests(1, [1], (1, 1))

    def test_requests_1_2(self):
        self.requests(1, [10], (10, 10))

    def test_requests_1_3(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 10))

    def test_requests_1_4(self):
        self.requests(1, [3, 4, 5, 6, 7, 8, 9, 10], (3, 10))

    def test_requests_1_5(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7], (1, 7))

    def test_requests_1_6(self):
        self.requests(1, [3, 4, 5, 6, 7], (3, 7))

    def test_requests_2_1(self):
        self.requests(2, [1], (1, 1))

    def test_requests_2_2(self):
        self.requests(2, [10], (10, 10))

    def test_requests_2_3(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 10))

    def test_requests_2_4(self):
        self.requests(2, [3, 4, 5, 6, 7, 8, 9, 10], (3, 10))

    def test_requests_2_5(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7], (1, 7))

    def test_requests_2_6(self):
        self.requests(2, [3, 4, 5, 6, 7], (3, 7))

    def test_requests_3_1(self):
        self.requests(3, [1], (1, 1))

    def test_requests_3_2(self):
        self.requests(3, [10], (10, 10))

    def test_requests_3_3(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 10))

    def test_requests_3_4(self):
        self.requests(3, [3, 4, 5, 6, 7, 8, 9, 10], (3, 10))

    def test_requests_3_5(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7], (1, 7))

    def test_requests_3_6(self):
        self.requests(3, [3, 4, 5, 6, 7], (3, 7))

            # multi-range requests
    def test_requests_1_7(self):
        self.requests(1, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_1_8(self):
        self.requests(1, [1, 2, 3, 4, 5], (1, 4), (2, 5))

    def test_requests_1_9(self):
        self.requests(1, [1, 2, 3, 4, 5], (1, 2), (2, 3), (3, 4), (4, 5))

    def test_requests_1_10(self):
        self.requests(1, [1, 2, 3, 4, 5], (1, 1), (5, 5))

    def test_requests_1_11(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (4, 5), (7, 8))

    def test_requests_1_12(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8, 9], (1, 2), (4, 5), (7, 8), (1, 5), (7, 9))

    def test_requests_2_7(self):
        self.requests(2, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_2_8(self):
        self.requests(2, [1, 2, 3, 4, 5], (1, 4), (2, 5))

    def test_requests_2_9(self):
        self.requests(2, [1, 2, 3, 4, 5], (1, 2), (2, 3), (3, 4), (4, 5))

    def test_requests_2_10(self):
        self.requests(2, [1, 2, 3, 4, 5], (1, 1), (5, 5))

    def test_requests_2_11(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (4, 5), (7, 8))

    def test_requests_2_12(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8, 9], (1, 2), (4, 5), (7, 8), (1, 5), (7, 9))

    def test_requests_3_7(self):
        self.requests(3, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_3_8(self):
        self.requests(3, [1, 2, 3, 4, 5], (1, 4), (2, 5))

    def test_requests_3_9(self):
        self.requests(3, [1, 2, 3, 4, 5], (1, 2), (2, 3), (3, 4), (4, 5))

    def test_requests_3_10(self):
        self.requests(3, [1, 2, 3, 4, 5], (1, 1), (5, 5))

    def test_requests_3_11(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (4, 5), (7, 8))

    def test_requests_3_12(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8, 9], (1, 2), (4, 5), (7, 8), (1, 5), (7, 9))

    # multi-range requests, in different orders
    def test_requests_1_13(self):
        self.requests(1, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_1_14(self):
        self.requests(1, [1, 2, 3, 4, 5], (2, 5), (1, 4))

    def test_requests_1_15(self):
        self.requests(1, [1, 2, 3, 4, 5], (4, 5), (3, 4), (1, 2), (2, 3))

    def test_requests_1_16(self):
        self.requests(1, [1, 2, 3, 4, 5], (5, 5), (1, 1))

    def test_requests_1_17(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (7, 8), (4, 5))

    def test_requests_1_18(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8, 9], (7, 9), (1, 5), (7, 8), (4, 5), (1, 2))

    def test_requests_2_13(self):
        self.requests(2, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_2_14(self):
        self.requests(2, [1, 2, 3, 4, 5], (2, 5), (1, 4))

    def test_requests_2_15(self):
        self.requests(2, [1, 2, 3, 4, 5], (4, 5), (3, 4), (1, 2), (2, 3))

    def test_requests_2_16(self):
        self.requests(2, [1, 2, 3, 4, 5], (5, 5), (1, 1))

    def test_requests_2_17(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (7, 8), (4, 5))

    def test_requests_2_18(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8, 9], (7, 9), (1, 5), (7, 8), (4, 5), (1, 2))

    def test_requests_3_13(self):
        self.requests(3, [1], (1, 1), (1, 1), (1, 1))

    def test_requests_3_14(self):
        self.requests(3, [1, 2, 3, 4, 5], (2, 5), (1, 4))

    def test_requests_3_15(self):
        self.requests(3, [1, 2, 3, 4, 5], (4, 5), (3, 4), (1, 2), (2, 3))

    def test_requests_3_16(self):
        self.requests(3, [1, 2, 3, 4, 5], (5, 5), (1, 1))

    def test_requests_3_17(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8], (1, 2), (7, 8), (4, 5))

    def test_requests_3_18(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8, 9], (7, 9), (1, 5), (7, 8), (4, 5), (1, 2))

    # single range requests, invalid requests
    def test_requests_1_19(self):
        self.requests(1, [10], (10, 11))

    def test_requests_1_20(self):
        self.requests(1, [], (11, 11))

    def test_requests_1_21(self):
        self.requests(1, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 11112))

    def test_requests_1_22(self):
        self.requests(1, [], (1111, 11112))

    def test_requests_2_19(self):
        self.requests(2, [10], (10, 11))

    def test_requests_2_20(self):
        self.requests(2, [], (11, 11))

    def test_requests_2_21(self):
        self.requests(2, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 11112))

    def test_requests_2_22(self):
        self.requests(2, [], (1111, 11112))

    def test_requests_3_19(self):
        self.requests(3, [10], (10, 11))

    def test_requests_3_20(self):
        self.requests(3, [], (11, 11))

    def test_requests_3_21(self):
        self.requests(3, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], (1, 11112))

    def test_requests_3_22(self):
        self.requests(3, [], (1111, 11112))

    # multi-range requests, invalid requests
    def test_requests_1_23(self):
        self.requests(1, [10], (10, 11), (10, 100), (50, 75))

    def test_requests_1_24(self):
        self.requests(1, [], (11, 11), (11, 50), (100, 200))

    def test_requests_2_23(self):
        self.requests(2, [10], (10, 11), (10, 100), (50, 75))

    def test_requests_2_24(self):
        self.requests(2, [], (11, 11), (11, 50), (100, 200))

    def test_requests_3_23(self):
        self.requests(3, [10], (10, 11), (10, 100), (50, 75))

    def test_requests_3_24(self):
        self.requests(3, [], (11, 11), (11, 50), (100, 200))

    def setUp(self):
        """
        SELF generates messages with sequence [1:MESSAGE_COUNT].
        """
        def on_dispersy_thread():
            with self._dispersy.database:
                self._community = DebugCommunity.create_community(self._dispersy, self._my_member)
                self._nodes = [DebugNode(self._community) for _ in xrange(3)]
                for node in self._nodes:
                    node.init_socket()
                    node.init_my_member()

                # create messages
                self._messages = []
                for i in xrange(1, 11):
                    message = self._community.create_sequence_text("Sequence message #%d" % i)
                    assert message.distribution.sequence_number == i
                    self._messages.append(message)

        super(TestIncomingMissingSequence, self).setUp()
        self._dispersy.callback.call(on_dispersy_thread)

    @call_on_dispersy_thread
    def requests(self, node_count, responses, *pairs):
        """
        NODE1 through NODE<NODE_COUNT> requests (non)overlapping sequences, SELF should send back the requested messages
        only once.
        """
        community = self._community
        nodes = self._nodes[:node_count]
        meta = self._messages[0].meta

        # flush incoming socket buffer
        for node in nodes:
            node.drop_packets()

        # request missing
        sequence_numbers = set()
        for low, high in pairs:
            sequence_numbers.update(xrange(low, high + 1))
            for node in nodes:
                node.give_message(node.create_dispersy_missing_sequence(community.my_member, meta, low, high, community.global_time, community.my_candidate), cache=True)
            # one additional yield.  Dispersy should batch these requests together
            yield 0.001

            for node in nodes:
                self.assertEqual(node.receive_messages(message_names=[meta.name]), [], "should not yet have any responses")

        yield 0.11

        # receive response
        for node in nodes:
            for i in responses:
                _, response = node.receive_message(message_names=[meta.name])
                self.assertEqual(response.distribution.sequence_number, i)

        # there should not be any no further responses
        for node in nodes:
            self.assertEqual(node.receive_messages(message_names=[meta.name]), [], "should not yet have any responses")

class TestOutgoingMissingSequence(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_missing(self):
        """
        NODE sends message while SELF doesn't have the prior sequence numbers, SELF should request these messages.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        messages = [node.create_sequence_text("Sequence message #%d" % sequence, sequence + 10, sequence)
                    for sequence
                    in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]

        # NODE gives #5, hence SELF will request [#1:#4]
        node.give_message(messages[4])
        requests = node.receive_messages(message_names=[u"dispersy-missing-sequence"])
        self.assertEqual(len(requests), 1)
        _, request = requests[0]

        self.assertEqual(request.payload.member.public_key, node.my_member.public_key)
        self.assertEqual(request.payload.message.name, u"sequence-text")
        self.assertEqual(request.payload.missing_low, 1)
        self.assertEqual(request.payload.missing_high, 4)

        # NODE gives the missing packets, database should now contain [#1:#5]
        node.give_messages(messages[0:4])
        yield 0.11
        packets = community.fetch_packets(u"sequence-text")
        self.assertEqual(packets, [message.packet for message in messages[0:5]])

        #
        # Lets give the following range and test if it works when there are already (a few) messages in the database
        #

        # NODE gives #10, hence SELF will request [#6:#9]
        node.give_message(messages[9])
        requests = node.receive_messages(message_names=[u"dispersy-missing-sequence"])
        self.assertEqual(len(requests), 1)
        _, request = requests[0]

        self.assertEqual(request.payload.member.public_key, node.my_member.public_key)
        self.assertEqual(request.payload.message.name, u"sequence-text")
        self.assertEqual(request.payload.missing_low, 6)
        self.assertEqual(request.payload.missing_high, 9)

        # NODE gives the missing packets, database should now contain [#1:#5]
        node.give_messages(messages[5:9])
        yield 0.11
        packets = community.fetch_packets(u"sequence-text")
        self.assertEqual(packets, [message.packet for message in messages])
