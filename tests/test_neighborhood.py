from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


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

    @call_on_dispersy_thread
    def forward(self, node_count):
        """
        SELF should forward created messages to its neighbors.

        - Multiple (NODE_COUNT) nodes connect to SELF
        - SELF creates a new message
        - At most 10 NODES should receive the message once
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # check configuration
        self.assertEqual(meta.destination.node_count, 10)

        # provide SELF with a neighbourhood
        nodes = [DebugNode(community) for _ in xrange(node_count)]
        for node in nodes:
            node.init_socket()
            node.init_my_member()

        # SELF creates a message
        message = community.create_full_sync_text("Hello World!")
        yield 0.1

        # ensure sufficient NODES received the message
        forwarded_node_count = 0
        for node in nodes:
            forwarded = [m for _, m in node.receive_messages(message_names=[u"full-sync-text"])]
            self.assertIn(len(forwarded), (0, 1))
            if len(forwarded) == 1:
                self.assertEqual(forwarded[0].packet, message.packet)
                forwarded_node_count += 1

        self.assertEqual(forwarded_node_count, min(node_count, meta.destination.node_count))

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
