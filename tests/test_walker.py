import logging
logger = logging.getLogger(__name__)

from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread

class TestWalker(DispersyTestFunc):

    def test_one_walker(self): return self.check_walker([""])
    def test_two_walker(self): return self.check_walker(["", ""])
    def test_many_walker(self): return self.check_walker([""] * 22)
    def test_one_t_walker(self): return self.check_walker(["t"])
    def test_two_t_walker(self): return self.check_walker(["t", "t"])
    def test_many_t_walker(self): return self.check_walker(["t"] * 22)
    def test_two_mixed_walker_a(self): return self.check_walker(["", "t"])
    def test_many_mixed_walker_a(self): return self.check_walker(["", "t"] * 11)
    def test_two_mixed_walker_b(self): return self.check_walker(["t", ""])
    def test_many_mixed_walker_b(self): return self.check_walker(["t", ""] * 11)

    def create_nodes(self, community, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)
        def generator():
            for flags in all_flags:
                node = DebugNode(community)
                node.init_socket("t" in flags)
                node.init_my_member(candidate=False)
                yield node
        return list(generator())

    @call_on_dispersy_thread
    def check_walker(self, all_flags):
        """
        All nodes will perform a introduction request to SELF in one batch.
        """
        logger.debug("<newline>")
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)

        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        nodes = self.create_nodes(community, all_flags)

        # create all requests
        requests = [node.create_dispersy_introduction_request(community.my_candidate,
                                                              node.lan_address,
                                                              node.wan_address,
                                                              True,
                                                              u"unknown",
                                                              None,
                                                              identifier,
                                                              42)
                    for identifier, node
                    in enumerate(nodes, 1)]

        # give all requests in one batch to dispersy
        self._dispersy.on_incoming_packets([(node.candidate, request.packet)
                                             for node, request
                                             in zip(nodes, requests)])

        is_tunnelled_map = dict([(node.lan_address, node.tunnel) for node in nodes])
        num_tunnelled_nodes = len([node for node in nodes if node.tunnel])
        num_non_tunnelled_nodes = len([node for node in nodes if not node.tunnel])

        for node in nodes:
            _, response = node.receive_message()
            logger.debug("SELF responded to %s's request with LAN:%s WAN:%s", node.candidate, response.payload.lan_introduction_address, response.payload.wan_introduction_address)

            if node.tunnel:
                # NODE is behind a tunnel, SELF can introduce tunnelled and non-tunnelled nodes to NODE.  This is
                # because both the tunnelled (SwiftEndpoint) and non-tunnelled (StandaloneEndpoint) nodes can handle
                # incoming messages with the FFFFFFFF prefix)
                if num_tunnelled_nodes + num_non_tunnelled_nodes == 1:
                    self.assertEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                if num_tunnelled_nodes + num_non_tunnelled_nodes > 1:
                    self.assertNotEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertNotEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                    # it must be any known node
                    self.assertIn(response.payload.lan_introduction_address, is_tunnelled_map)

            else:
                # NODE is -not- behind a tunnel, SELF can only introduce non-tunnelled nodes to NODE.  This is because
                # only non-tunnelled (StandaloneEndpoint) nodes can handle incoming messages -without- the FFFFFFFF
                # prefix.
                if num_non_tunnelled_nodes == 1:
                    self.assertEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                if num_non_tunnelled_nodes > 1:
                    self.assertNotEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertNotEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                    # it may only be non-tunnelled
                    self.assertFalse(is_tunnelled_map[response.payload.lan_introduction_address])
