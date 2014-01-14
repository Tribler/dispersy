from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class NonRandomYieldDebugCommunity(DebugCommunity):

    def dispersy_yield_verified_candidates(self):
        """
        Yields unique active candidates.

        The returned candidates will be sorted to avoid randomness in the tests.
        """

        return sorted(DebugCommunity.dispersy_yield_verified_candidates(self))


class TestNeighborhood(DispersyTestFunc):

    def test_forward_1(self):
        return self.forward(1)

    def test_forward_10(self):
        return self.forward(10)

    def test_forward_2(self):
        return self.forward(2)

    def test_forward_3(self):
        return self.forward(3)

    def test_forward_20(self):
        return self.forward(20)

    def test_forward_0_targeted_5(self):
        return self.forward(0, 5)

    def test_forward_0_targeted_20(self):
        return self.forward(0, 20)

    def test_forward_5_targeted_2(self):
        return self.forward(5, 2)

    def test_forward_2_targeted_5(self):
        return self.forward(2, 5)

    @call_on_dispersy_thread
    def forward(self, non_targeted_node_count, targeted_node_count=0):
        """
        SELF should forward created messages at least to the specified targets.

        - Multiple (NODE_COUNT) nodes connect to SELF
        - SELF creates a new message
        - At most `target_count` + `meta.destination.node_count` NODES should receive the message once
        - All `target_count` NODES must receive the message once
        - At least `meta.destination.node_count` nodes must receive the message once provided there are enough nodes
        """

        community = NonRandomYieldDebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # check configuration
        self.assertEqual(meta.destination.node_count, 10)

        total_node_count = non_targeted_node_count + targeted_node_count

        # provide SELF with a neighborhood
        nodes = [DebugNode(community) for _ in xrange(total_node_count)]
        for node in nodes:
            node.init_socket()
            node.init_my_member()

        # SELF creates a message
        candidates = tuple((node.candidate for node in nodes[:targeted_node_count]))
        message = community.create_targeted_full_sync_text("Hello World!", candidates)
        yield 0.01

        # check if sufficient NODES received the message (at least the first `target_count` ones)
        forwarded_node_count = 0
        for node in nodes:
            forwarded = [m for _, m in node.receive_messages(message_names=[u"full-sync-text"])]
            if node in nodes[:targeted_node_count]:
                # They MUST have received the message
                self.assertEqual(len(forwarded), 1)
            else:
                # They MAY have received the message
                self.assertIn(len(forwarded), (0, 1))
            if len(forwarded) == 1:
                self.assertEqual(forwarded[0].packet, message.packet)
                forwarded_node_count += 1

        # We should never send to more than node_count + targeted_node_count nodes
        self.assertEqual(forwarded_node_count, min(total_node_count, meta.destination.node_count + targeted_node_count))

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
