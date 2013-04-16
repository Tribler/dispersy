from collections import defaultdict

from ..debugcommunity import DebugCommunity
from ..debugcommunity import DebugNode
from .dispersytestclass import DispersyTestClass, call_on_dispersy_thread

class TestSequence(DispersyTestClass):
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
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()

        # MSGS[GLOBAL-TIME][SEQUENCE-NUMBER]
        msgs = defaultdict(dict)
        for i in xrange(1, 10):
            for j in xrange(1, 10):
                msgs[i][j] = node.create_sequence_test_message("M@%d#%d" % (i, j), i, j)

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

    def test_missing_sequence(self):
        # set up
        self.requests_setup(3, 10)

        for node_count in [1, 2, 3]:
            self.requests(node_count, [1], (1, 1))
            self.requests(node_count, [10], (10, 10))
            self.requests(node_count, [1,2,3,4,5,6,7,8,9,10], (1, 10))
            self.requests(node_count, [3,4,5,6,7,8,9,10], (3, 10))
            self.requests(node_count, [1,2,3,4,5,6,7], (1, 7))
            self.requests(node_count, [3,4,5,6,7], (3, 7))

            # multi-range requests
            self.requests(node_count, [1], (1,1), (1,1), (1,1))
            self.requests(node_count, [1,2,3,4,5], (1,4), (2,5))
            self.requests(node_count, [1,2,3,4,5], (1,2), (2,3), (3,4), (4,5))
            self.requests(node_count, [1,2,3,4,5], (1,1), (5,5))
            self.requests(node_count, [1,2,3,4,5,6,7,8], (1,2), (4,5), (7,8))
            self.requests(node_count, [1,2,3,4,5,6,7,8,9], (1,2), (4,5), (7,8), (1,5), (7,9))

            # multi-range requests, in different orders
            self.requests(node_count, [1], (1,1), (1,1), (1,1))
            self.requests(node_count, [1,2,3,4,5], (2,5), (1,4))
            self.requests(node_count, [1,2,3,4,5], (4,5), (3,4), (1,2), (2,3))
            self.requests(node_count, [1,2,3,4,5], (5,5), (1,1))
            self.requests(node_count, [1,2,3,4,5,6,7,8], (1,2), (7,8), (4,5))
            self.requests(node_count, [1,2,3,4,5,6,7,8,9], (7,9), (1,5), (7,8), (4,5), (1,2))

            # single range requests, invalid requests
            self.requests(node_count, [10], (10, 11))
            self.requests(node_count, [], (11, 11))
            self.requests(node_count, [1,2,3,4,5,6,7,8,9,10], (1, 11112))
            self.requests(node_count, [], (1111, 11112))

            # multi-range requests, invalid requests
            self.requests(node_count, [10], (10, 11), (10, 100), (50, 75))
            self.requests(node_count, [], (11, 11), (11, 50), (100, 200))

        # tear down
        self.requests_teardown()

    @call_on_dispersy_thread
    def requests_setup(self, node_count, message_count):
        """
        SELF generates messages with sequence [1:MESSAGE_COUNT].
        """
        self._community = DebugCommunity.create_community(self._dispersy, self._my_member)
        self._nodes = [DebugNode() for _ in xrange(node_count)]
        for node in self._nodes:
            node.init_socket()
            node.set_community(self._community)
            node.init_my_member()

        # create messages
        self._messages = []
        for i in xrange(1, message_count + 1):
            message = self._community.create_sequence_text("Sequence message #%d" % i)
            self.assertEqual(message.distribution.sequence_number, i)
            self._messages.append(message)

    @call_on_dispersy_thread
    def requests_teardown(self):
        """
        Cleanup.
        """
        self._community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(self._community.cid).unload_community()

    @call_on_dispersy_thread
    def requests(self, node_count, responses, *pairs):
        """
        NODE1 and NODE2 requests (non)overlapping sequences, SELF should send back the requested
        messages only once.
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
                node.give_message(node.create_dispersy_missing_sequence_message(community.my_member, meta, low, high, community.global_time, community.my_candidate), cache=True)
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
