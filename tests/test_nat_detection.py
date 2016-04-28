from time import time

from .dispersytestclass import DispersyTestFunc
from ..util import call_on_reactor_thread, address_is_lan_without_netifaces

class TestNATDetection(DispersyTestFunc):

    """
    Tests NAT detection.

    These unit tests should cover all methods which are related to detecting the NAT type of a peer.
    """

    def _emulate_connection_type__unknown(self, community):
        self._logger.debug("Emulating connection type: UNKNOWN")
        address = ("140.0.0.2", 1)
        candidate = community.create_candidate(address, False, address, address, u"unknown")
        community._dispersy.wan_address_vote(("1.1.1.1", 1), candidate)

        # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
        # the current code this results in the CANDIDATE to remain 'obsolete'.
        self.assertIsNone(candidate.get_category(time()))

        self.assertNotEqual(community._dispersy.lan_address, community._dispersy.wan_address)
        self.assertEqual(community._dispersy.connection_type, u"unknown")

    def _emulate_connection_type__public(self, community):
        self._logger.debug("Emulating connection type: PUBLIC")
        for i in range(5):
            address = ("140.0.0.3", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            community._dispersy.wan_address_vote(community._dispersy.lan_address, candidate)

            # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
            # the current code this results in the CANDIDATE to remain 'obsolete'.
            self.assertIsNone(candidate.get_category(time()))

            # one vote is enough, but more won't hurt
            self.assertEqual(community._dispersy.lan_address, community._dispersy.wan_address)
            self.assertEqual(community._dispersy.connection_type, u"public")

    def _emulate_connection_type__symmetric_nat(self, community):
        self._logger.debug("Emulating connection type: SYMMETRIC-NAT")
        for i in range(5):
            address = ("140.0.0.4", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            community._dispersy.wan_address_vote(("1.1.1.2", i + 1), candidate)

            # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
            # the current code this results in the CANDIDATE to remain 'obsolete'.
            self.assertIsNone(candidate.get_category(time()))

            if i > 0:
                # two votes are needed, but more won't hurt
                self.assertNotEqual(community._dispersy.lan_address, community._dispersy.wan_address)
                self.assertEqual(community._dispersy.connection_type, u"symmetric-NAT")

    def _clear_votes(self, community):
        self._logger.debug("Cleanup votes")
        self.assertGreater(community.cleanup_candidates(), 0)
        self.assertEqual(len(community._dispersy._wan_address_votes), 0)

    @call_on_reactor_thread
    def test_connection_type(self, *types):
        """
        Tests the transition between connection types based on external votes.
        """
        self._emulate_connection_type__public(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__unknown(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__public(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__symmetric_nat(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__unknown(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__symmetric_nat(self._community)
        self._clear_votes(self._community)
        self._emulate_connection_type__public(self._community)

    @call_on_reactor_thread
    def test_symmetric_vote(self):
        """
        Tests symmetric-NAT detection.

        1. After receiving two votes from different candidates A and B for different port numbers, a peer must change
           it's connection type to symmetric-NAT.

        2. After candidate A and B are gone and a only votes for the same port number remains, a peer must change it's
           connection type back to unknown or public.
        """
        for i in range(2):
            address = ("140.0.0.2", i + 1)
            candidate = self._community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("1.0.0.1", i + 1), candidate)
        self.assertEqual(self._dispersy.connection_type, u"symmetric-NAT")

        # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
        # the current code this results in the CANDIDATE to remain 'obsolete'.
        self.assertIsNone(candidate.get_category(time()))
        self.assertEqual(self._community.cleanup_candidates(), 2)

        for i in range(2):
            address = ("140.0.0.3", i + 1)
            candidate = self._community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("1.0.0.1", 1), candidate)
        self.assertEqual(self._dispersy.connection_type, u"unknown")


class TestAddressEstimation(DispersyTestFunc):
    def test_address_in_lan_function(self):
        # Positive cases:
        assert address_is_lan_without_netifaces("192.168.1.5")
        assert address_is_lan_without_netifaces("10.42.42.42")
        assert address_is_lan_without_netifaces("192.168.0.7")
        assert address_is_lan_without_netifaces("172.31.255.255")
        #Negative cases:
        self.assertFalse(address_is_lan_without_netifaces("192.169.1.5"))
        self.assertFalse(address_is_lan_without_netifaces("11.42.42.42"))
        self.assertFalse(address_is_lan_without_netifaces("192.0.0.7"))
        self.assertFalse(address_is_lan_without_netifaces("172.32.0.0"))
        self.assertFalse(address_is_lan_without_netifaces("123.123.123.123"))
        self.assertFalse(address_is_lan_without_netifaces("42.42.42.42"))

    def test_estimate_addresses_within_LAN(self):
        """
        Tests the estimate_lan_and_wan_addresses method while NODE and OTHER are within the same LAN.

        NODE will pretend that its LAN and WAN are invalid/unknown, OTHER should inform NODE of its
        correct LAN address.  OTHER will not be able to determine the WAN address for NODE, hence
        this should remain unchanged.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        incorrect_LAN = ("0.0.0.0", 0)
        incorrect_WAN = ("0.0.0.0", 0)

        # NODE contacts OTHER with incorrect addresses
        other.give_message(node.create_introduction_request(other.my_candidate,
                                                            incorrect_LAN,
                                                            incorrect_WAN,
                                                            True,
                                                            u"unknown",
                                                            None,
                                                            42,
                                                            42),
                           node)

        # NODE should receive an introduction-response with the corrected LAN address
        responses = node.receive_messages(names=[u"dispersy-introduction-response"])
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.payload.destination_address, node.lan_address)

        # OTHER should have a candidate instance representing NODE. This Candidate instance should
        # have the correct sock_addr and lan_address. However, wan_address should be whatever NODE
        # said
        candidates = [candidate
                      for candidate
                      in other._community.dispersy_yield_candidates()
                      if candidate.sock_addr == node.lan_address]

        self.assertEqual(len(candidates), 1)
        for candidate in candidates:
            self.assertEqual(candidate.sock_addr, node.lan_address)
            self.assertEqual(candidate.lan_address, node.lan_address)
            self.assertEqual(candidate.wan_address, incorrect_WAN)


