from .dispersytestclass import DispersyTestFunc


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

    def create_others(self, all_flags):
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)

        nodes = []
        for flags in all_flags:
            node, = self.create_nodes(tunnel="t" in flags)
            nodes.append(node)

        return nodes

    def check_walker(self, all_flags):
        """
        All nodes will perform a introduction request to SELF in one batch.
        """
        assert isinstance(all_flags, list)
        assert all(isinstance(flags, str) for flags in all_flags)

        nodes = self.create_others(all_flags)

        # create all requests
        requests = [node.create_introduction_request(self._mm.my_candidate,
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
        self._mm.call(self._dispersy.on_incoming_packets, [(node.my_candidate, node.encode_message(request))
                                             for node, request
                                             in zip(nodes, requests)])

        is_tunnelled_map = dict([(node.lan_address, node.tunnel) for node in nodes])
        num_tunnelled_nodes = len([node for node in nodes if node.tunnel])
        num_non_tunnelled_nodes = len([node for node in nodes if not node.tunnel])

        for node in nodes:
            _, response = node.receive_message().next()

            # MM must not introduce NODE to itself
            self.assertNotEquals(response.payload.lan_introduction_address, node.lan_address)
            self.assertNotEquals(response.payload.wan_introduction_address, node.wan_address)

            if node.tunnel:
                if num_tunnelled_nodes + num_non_tunnelled_nodes > 1:
                    self.assertNotEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertNotEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                    # it must be any known node
                    self.assertIn(response.payload.lan_introduction_address, is_tunnelled_map)

            else:
                # NODE is -not- behind a tunnel, MM can only introduce non-tunnelled nodes to NODE.  This is because
                # only non-tunnelled (StandaloneEndpoint) nodes can handle incoming messages -without- the FFFFFFFF
                # prefix.

                if num_non_tunnelled_nodes > 1:
                    self.assertNotEquals(response.payload.lan_introduction_address, ("0.0.0.0", 0))
                    self.assertNotEquals(response.payload.wan_introduction_address, ("0.0.0.0", 0))

                    # it may only be non-tunnelled
                    self.assertFalse(is_tunnelled_map[response.payload.lan_introduction_address], response.payload.lan_introduction_address)
