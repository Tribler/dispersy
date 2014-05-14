from collections import defaultdict
from os import environ
from pprint import pformat
from time import time
from unittest import skipUnless

from nose.twistedtools import reactor

from ..community import Community
from ..conversion import DefaultConversion
from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.conversion import DebugCommunityConversion
from .dispersytestclass import DispersyTestFunc
from ..util import call_on_reactor_thread


logger = get_logger(__name__)
summary = get_logger("test-overlay-summary")


class TestOverlay(DispersyTestFunc):

    @skipUnless(environ.get("TEST_OVERLAY_ALL_CHANNEL") == "yes", "This 'unittest' tests the health of a live overlay, as such, this is not part of the code review process")
    def test_all_channel_community(self):
        return self.check_live_overlay(cid_hex="8164f55c2f828738fa779570e4605a81fec95c9d",
                                       version="\x01",
                                       enable_fast_walker=False)

    @skipUnless(environ.get("TEST_OVERLAY_BARTER") == "yes", "This 'unittest' tests the health of a live overlay, as such, this is not part of the code review process")
    def test_barter_community(self):
        return self.check_live_overlay(cid_hex="4fe1172862c649485c25b3d446337a35f389a2a2",
                                       version="\x01",
                                       enable_fast_walker=False)

    @skipUnless(environ.get("TEST_OVERLAY_SEARCH") == "yes", "This 'unittest' tests the health of a live overlay, as such, this is not part of the code review process")
    def test_search_community(self):
        return self.check_live_overlay(cid_hex="2782dc9253cef6cc9272ee8ed675c63743c4eb3a",
                                       version="\x01",
                                       enable_fast_walker=True)

    @call_on_reactor_thread
    def check_live_overlay(self, cid_hex, version, enable_fast_walker):
        class Conversion(DebugCommunityConversion):
            # there are overlays that modify the introduction request, ensure that the returned offset 'consumed' all
            # bytes in the packet
            def _decode_introduction_request(self, placeholder, offset, data):
                _, payload = super(Conversion, self)._decode_introduction_request(placeholder, offset, data)
                return len(data), payload

        class WCommunity(DebugCommunity):
            def __init__(self, dispersy, master):
                super(WCommunity, self).__init__(dispersy, master)

            def initiate_conversions(self):
                return [DefaultConversion(self), Conversion(self, version)]

            def dispersy_claim_sync_bloom_filter(self, request_cache):
                # we only want to walk in the community, not exchange data
                return None

            def take_step(self):
                for sleep in Community.take_step(self):
                    yield sleep

            @property
            def dispersy_enable_fast_candidate_walker(self):
                return enable_fast_walker


        class Info(object):
            pass

        assert isinstance(cid_hex, str)
        assert len(cid_hex) == 40
        assert isinstance(enable_fast_walker, bool)
        cid = cid_hex.decode("HEX")

        self._dispersy.statistics.enable_debug_statistics(True)
        community = WCommunity(self._dispersy, self._dispersy.get_member(mid=cid), self._mm.my_member)
        summary.info(community.cid.encode("HEX"))

        history = []
        begin = time()
        for _ in xrange(60 * 15):
            yield 1.0
            now = time()
            info = Info()
            info.diff = now - begin
            info.candidates = [(candidate, candidate.get_category(now)) for candidate in community._candidates.itervalues()]
            info.verified_candidates = [(candidate, candidate.get_category(now)) for candidate in community.dispersy_yield_verified_candidates()]
            info.lan_address = self._dispersy.lan_address
            info.wan_address = self._dispersy.wan_address
            info.connection_type = self._dispersy.connection_type
            history.append(info)

            summary.info("after %.1f seconds there are %d verified candidates [w%d:s%d:i%d:n%d]",
                         info.diff,
                         len([_ for _, category in info.candidates if category in (u"walk", u"stumble")]),
                         len([_ for _, category in info.candidates if category == u"walk"]),
                         len([_ for _, category in info.candidates if category == u"stumble"]),
                         len([_ for _, category in info.candidates if category == u"intro"]),
                         len([_ for _, category in info.candidates if category is None]))

        helper_requests = defaultdict(lambda: defaultdict(int))
        helper_responses = defaultdict(lambda: defaultdict(int))

        for destination, requests in self._dispersy.statistics.outgoing_introduction_request.iteritems():
            responses = self._dispersy.statistics.incoming_introduction_response[destination]

            # who introduced me to DESTINATION?
            for helper, introductions in self._dispersy.statistics.received_introductions.iteritems():
                if destination in introductions:
                    helper_requests[helper][destination] = requests
                    helper_responses[helper][destination] = responses

        l = [(100.0 * sum(helper_responses[helper].itervalues()) / sum(helper_requests[helper].itervalues()),
              sum(helper_requests[helper].itervalues()),
              sum(helper_responses[helper].itervalues()),
              helper_requests[helper],
              helper_responses[helper],
              helper)
             for helper
             in helper_requests]

        for ratio, req, res, req_dict, res_dict, helper, in sorted(l):
            summary.debug("%.1f%% %3d %3d %15s:%-4d  #%d %s", ratio, req, res, helper[0], helper[1],
                          len(req_dict),
                          "; ".join("%s:%d:%d/%d" % (addr[0], addr[1], res_dict[addr], req_dict[addr])
                                    for addr
                                    in req_dict))

        self._dispersy.statistics.update()
        summary.debug("\n%s", pformat(self._dispersy.statistics.get_dict()))

        # write graph statistics
        with open("%s_connections.txt" % cid_hex, "w+") as handle:
            handle.write("TIME VERIFIED_CANDIDATES WALK_CANDIDATES STUMBLE_CANDIDATES INTRO_CANDIDATES NONE_CANDIDATES INCOMING_WALKS LAN_ADDRESS WAN_ADDRESS CONNECTION_TYPE\n")
            for info in history:
                handle.write("%f   %d   %d   %d   %d   %d   %d   %s   %s   \"%s\"\n" % (
                        info.diff,
                        len(info.verified_candidates),
                        len([_ for _, category in info.candidates if category == u"walk"]),
                        len([_ for _, category in info.candidates if category == u"stumble"]),
                        len([_ for _, category in info.candidates if category == u"intro"]),
                        len([_ for _, category in info.candidates if category is None]),
                        info.incoming_walks,
                        "%s:%d" % info.lan_address,
                        "%s:%d" % info.wan_address,
                        info.connection_type))

        average_verified_candidates = 1.0 * sum(len(info.verified_candidates) for info in history) / len(history)
        average_walk_candidates = 1.0 * sum(len([_ for _, category in info.candidates if category == u"walk"]) for info in history) / len(history)
        average_stumble_candidates = 1.0 * sum(len([_ for _, category in info.candidates if category == u"stumble"]) for info in history) / len(history)
        average_intro_candidates = 1.0 * sum(len([_ for _, category in info.candidates if category == u"intro"]) for info in history) / len(history)
        average_none_candidates = 1.0 * sum(len([_ for _, category in info.candidates if category is None]) for info in history) / len(history)

        # write results for this run
        with open("%s_results.txt" % cid_hex, "w+") as handle:
            # take the last history, this reflects the total bootstrap_attempts, ..., total incoming_walks
            info = history[-1]
            import socket

            handle.write("TIMESTAMP HOSTNAME CID_HEX AVG_VERIFIED_CANDIDATES AVG_WALK_CANDIDATES AVG_STUMBLE_CANDIDATES AVG_INTRO_CANDIDATES AVG_NONE_CANDIDATES INCOMING_WALKS LAN_ADDRESS WAN_ADDRESS CONNECTION_TYPE\n")
            handle.write("%f \"%s\" %s %f %f %f %f %f %d %s %s \"%s\"\n" % (
                    time(),
                    socket.gethostname(),
                    cid_hex,
                    average_verified_candidates,
                    average_walk_candidates,
                    average_stumble_candidates,
                    average_intro_candidates,
                    average_none_candidates,
                    info.incoming_walks,
                    "%s:%d" % info.lan_address,
                    "%s:%d" % info.wan_address,
                    info.connection_type))

        # determine test success or failure (hard coded for 10.0 or higher being a success)
        summary.debug("Average verified candidates: %.1f", average_verified_candidates)
        self.assertGreater(average_verified_candidates, 10.0)
