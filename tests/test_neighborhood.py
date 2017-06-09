from .debugcommunity.community import DebugCommunity
from .dispersytestclass import DispersyTestFunc


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

    def forward(self, non_targeted_node_count, targeted_node_count=0):
        """
        SELF should forward created messages at least to the specified targets.

        - Multiple (NODE_COUNT) nodes connect to SELF
        - SELF creates a new message
        - At most `target_count` + `meta.destination.node_count` NODES should receive the message once
        - All `target_count` NODES must receive the message once
        - At least `meta.destination.node_count` nodes must receive the message once provided there are enough nodes
        """

        def dispersy_yield_verified_candidates():
            """
            Yields unique active candidates.

            The returned candidates will be sorted to avoid randomness in the tests.
            """
            return sorted(DebugCommunity.dispersy_yield_verified_candidates(self._community))

        self._community.dispersy_yield_verified_candidates = dispersy_yield_verified_candidates

        # check configuration
        meta = self._community.get_meta_message(u"full-sync-text")
        self.assertEqual(meta.destination.node_count, 10)

        total_node_count = non_targeted_node_count + targeted_node_count

        # provide CENTRAL with a neighborhood
        nodes = self.create_nodes(total_node_count)

        # SELF creates a message
        candidates = tuple((node.my_candidate for node in nodes[:targeted_node_count]))
        message = self._mm.create_targeted_full_sync_text("Hello World!", destination=candidates,  global_time=42)
        self._dispersy._forward([message])

        # check if sufficient NODES received the message (at least the first `target_count` ones)
        forwarded_node_count = 0
        for node in nodes:
            forwarded = [m for _, m in node.receive_messages(names=[u"full-sync-text"], timeout=0.1)]
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

    def test_forward_hop_timeout(self):
        """
        Test an n-hop-sync timeout.

        This test uses a CommunityDestination of fan out 1 and depth 1.
        In other words only 1 candidate should receive this message.
        """
        other, another = self.clean_community_candidates(2)

        # Create the message
        meta = self._community.get_meta_message(u"n-hop-sync-text")
        message = meta.impl(authentication=(self._mm.my_member,),
                            distribution=(42,),
                            payload=("Hello World!",))

        # Forward the message
        self._mm.community.dispersy._forward([message, ])

        # Check if we did not send to ourselves
        receive0 = list(self._mm.receive_message(names=[u"n-hop-sync-text", ], timeout=1.0))
        self.assertEqual(receive0, [])
        # Check if this arrived at a single other node
        receive1 = list(other.receive_message(names=[u"n-hop-sync-text", ], timeout=1.0))
        receive2 = list(another.receive_message(names=[u"n-hop-sync-text", ], timeout=1.0))
        received = receive1 + receive2
        _, message = received[0]

        self.assertEqual(message.destination.depth, 0)

        # Forward the message
        self._mm.community.dispersy._forward([message, ])

        # Check if this message has indeed not been forwarded
        receive0 = list(self._mm.receive_message(names=[u"n-hop-sync-text", ]))
        receive1 = list(other.receive_message(names=[u"n-hop-sync-text", ]))
        receive2 = list(another.receive_message(names=[u"n-hop-sync-text", ]))

        # self._mm has the packet in his database
        # But only one other node should receive this message
        self.assertEqual(receive0, [])
        self.assertEqual(receive1, [])
        self.assertEqual(receive2, [])

    def clean_community_candidates(self, node_count):
        """
        Add certain nodes to the community and disallow walking to other nodes.

        :param nodes: the DebugNodes which should be a part of the community
        """
        # Disallow community walking
        self._community.cancel_pending_task("take step")
        self._community.candidates.clear()

        # Create the nodes
        nodes = self.create_nodes(node_count)
        for node in nodes:
            self._mm.send_identity(node)
            node.process_packets()
        self._mm.process_packets()

        return nodes
