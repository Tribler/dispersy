from time import time

from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)

class TestNATDetection(DispersyTestFunc):
    """
    Tests NAT detection.

    These unit tests should cover all methods which are related to detecting the NAT type of a peer.
    """

    def _emulate_connection_type__unknown(self, community):
        logger.debug("Emulating connection type: UNKNOWN")
        address = ("140.0.0.2", 1)
        candidate = community.create_candidate(address, False, address, address, u"unknown")
        self._dispersy.wan_address_vote(("1.1.1.1", 1), candidate)

        # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
        # the current code this results in the CANDIDATE to remain 'obsolete'.
        self.assertTrue(candidate.is_obsolete(time()))

        self.assertNotEqual(self._dispersy.lan_address, self._dispersy.wan_address)
        self.assertEqual(self._dispersy.connection_type, u"unknown")

    def _emulate_connection_type__public(self, community):
        logger.debug("Emulating connection type: PUBLIC")
        for i in range(5):
            address = ("140.0.0.3", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(self._dispersy.lan_address, candidate)

            # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
            # the current code this results in the CANDIDATE to remain 'obsolete'.
            self.assertTrue(candidate.is_obsolete(time()))

            # one vote is enough, but more won't hurt
            self.assertEqual(self._dispersy.lan_address, self._dispersy.wan_address)
            self.assertEqual(self._dispersy.connection_type, u"public")

    def _emulate_connection_type__symmetric_nat(self, community):
        logger.debug("Emulating connection type: SYMMETRIC-NAT")
        for i in range(5):
            address = ("140.0.0.4", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("1.1.1.2", i + 1), candidate)

            # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
            # the current code this results in the CANDIDATE to remain 'obsolete'.
            self.assertTrue(candidate.is_obsolete(time()))

            if i > 0:
                # two votes are needed, but more won't hurt
                self.assertNotEqual(self._dispersy.lan_address, self._dispersy.wan_address)
                self.assertEqual(self._dispersy.connection_type, u"symmetric-NAT")

    def _clear_votes(self, community):
        logger.debug("Cleanup votes")
        self.assertGreater(community.cleanup_candidates(), 0)
        self.assertEqual(len(self._dispersy._wan_address_votes), 0)

    @call_on_dispersy_thread
    def test_connection_type(self, *types):
        """
        Tests the transition between connection types based on external votes.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        self._emulate_connection_type__public(community)
        self._clear_votes(community)
        self._emulate_connection_type__unknown(community)
        self._clear_votes(community)
        self._emulate_connection_type__public(community)
        self._clear_votes(community)
        self._emulate_connection_type__symmetric_nat(community)
        self._clear_votes(community)
        self._emulate_connection_type__unknown(community)
        self._clear_votes(community)
        self._emulate_connection_type__symmetric_nat(community)
        self._clear_votes(community)
        self._emulate_connection_type__public(community)

    @call_on_dispersy_thread
    def test_symmetric_vote(self):
        """
        Tests symmetric-NAT detection.

        1. After receiving two votes from different candidates A and B for different port numbers, a peer must change
           it's connection type to summetric-NAT.

        2. After candidate A and B are gone and a only votes for the same port number remains, a peer must change it's
           connection type back to unknown or public.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        for i in range(2):
            address = ("140.0.0.2", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("1.0.0.1", i + 1), candidate)
        self.assertEqual(self._dispersy.connection_type, u"symmetric-NAT")

        # because we CANDIDATE didn't send any messages to COMMUNITY, the CANDIDATE timestamps have never been set.  In
        # the current code this results in the CANDIDATE to remain 'obsolete'.
        self.assertTrue(candidate.is_obsolete(time()))
        self.assertEqual(community.cleanup_candidates(), 2)

        for i in range(2):
            address = ("140.0.0.3", i + 1)
            candidate = community.create_candidate(address, False, address, address, u"unknown")
            self._dispersy.wan_address_vote(("1.0.0.1", 1), candidate)
        self.assertEqual(self._dispersy.connection_type, u"unknown")

class TestAddressEstimation(DispersyTestFunc):
    @call_on_dispersy_thread
    def test_estimate_addresses_within_LAN(self):
        """
        Tests the estimate_lan_and_wan_addresses method while NODE and SELF are within the same LAN.

        NODE will pretend that its LAN and WAN are invalid/unknown, SELF should inform NODE of its
        correct LAN address.  SELF will not be able to determine the WAN address for NODE, hence
        this should remain unchanged.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False)

        incorrect_LAN = ("0.0.0.0", 0)
        incorrect_WAN = ("0.0.0.0", 0)
        # NODE contacts SELF with incorrect addresses
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate,
                                                                    incorrect_LAN,
                                                                    incorrect_WAN,
                                                                    True,
                                                                    u"unknown",
                                                                    None,
                                                                    42,
                                                                    42))

        # NODE should receive an introduction-response with the corrected LAN address
        responses = node.receive_messages(message_names=[u"dispersy-introduction-response"])
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.payload.destination_address, node.lan_address)

        # SELF should have a candidate instance representing NODE.  This Candidate instance should
        # have the correct sock_addr and lan_address.  however, wan_address should be whatever NODE
        # said
        candidates = [candidate
                      for candidate
                      in community.dispersy_yield_candidates()
                      if candidate.sock_addr == node.lan_address]
        self.assertEqual(len(candidates), 1)
        for candidate in candidates:
            self.assertEqual(candidate.sock_addr, node.lan_address)
            self.assertEqual(candidate.lan_address, node.lan_address)
            self.assertEqual(candidate.wan_address, incorrect_WAN)

    @call_on_dispersy_thread
    def test_estimate_addresses_within_WAN(self):
        """
        Tests the estimate_lan_and_wan_addresses method while NODE and SELF are -not- within the
        same LAN.

        NODE will pretend that its LAN and WAN are invalid/unknown.  SELF will not be able to
        determine the LAN address for NODE, hence this should remain unchanged.

        In contrast to test_estimate_addresses_within_LAN it is not possible to receive the
        introduction-response, since this is sent to a faked address.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False)

        fake_sock = ("6.6.6.6", 666)
        incorrect_LAN = ("0.0.0.0", 0)
        incorrect_WAN = ("0.0.0.0", 0)
        # NODE contacts SELF with incorrect addresses
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate,
                                                                    incorrect_LAN,
                                                                    incorrect_WAN,
                                                                    True,
                                                                    u"unknown",
                                                                    None,
                                                                    42,
                                                                    42),
                          source_sock_addr=fake_sock)

        # NODE should -not- receive an introduction-response since this message should have been
        # sent to the fake address
        responses = node.receive_messages(message_names=[u"dispersy-introduction-response"])
        self.assertEqual(len(responses), 0)

        # SELF should have a candidate instance representing NODE.  This Candidate instance should
        # have the fake sock_addr, and wan_address.  however, lan_address should be whatever NODE
        # said
        candidates = [candidate
                      for candidate
                      in community.dispersy_yield_candidates()
                      if candidate.sock_addr == fake_sock]
        self.assertEqual(len(candidates), 1)
        for candidate in candidates:
            self.assertEqual(candidate.sock_addr, fake_sock)
            self.assertEqual(candidate.lan_address, incorrect_LAN)
            self.assertEqual(candidate.wan_address, fake_sock)
