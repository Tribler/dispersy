from os import environ
from pprint import pformat
from time import time
from unittest import skipUnless
import logging

from nose.twistedtools import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater

from ..conversion import DefaultConversion
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint
from ..util import blocking_call_on_reactor_thread
from .debugcommunity.community import DebugCommunity
from .debugcommunity.conversion import DebugCommunityConversion
from .dispersytestclass import DispersyTestFunc


summary_logger = logging.getLogger("test-overlay-summary")


class TestOverlay(DispersyTestFunc):

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def setUp(self):
        yield super(DispersyTestFunc, self).setUp()

        self.dispersy_objects = []

    @skipUnless(environ.get("TEST_OVERLAY_ALL_CHANNEL") == "yes", "This 'unittest' tests the health of a live overlay, as such, this is not part of the code review process")
    def test_all_channel_community(self):
        return self.check_live_overlay(cid_hex="8164f55c2f828738fa779570e4605a81fec95c9d",
                                       version="\x01",
                                       enable_fast_walker=False)

    @skipUnless(environ.get("TEST_OVERLAY_SEARCH") == "yes", "This 'unittest' tests the health of a live overlay, as such, this is not part of the code review process")
    def test_search_community(self):
        return self.check_live_overlay(cid_hex="2782dc9253cef6cc9272ee8ed675c63743c4eb3a",
                                       version="\x01",
                                       enable_fast_walker=True)

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def check_live_overlay(self, cid_hex, version, enable_fast_walker):
        class Conversion(DebugCommunityConversion):
            # there are overlays that modify the introduction request, ensure that the returned offset 'consumed' all
            # bytes in the packet

            def _decode_introduction_request(self, placeholder, offset, data):
                _, payload = super(Conversion, self)._decode_introduction_request(placeholder, offset, data)
                return len(data), payload

        class WCommunity(DebugCommunity):

            def initiate_conversions(self):
                return [DefaultConversion(self), Conversion(self, version)]

            @property
            def dispersy_enable_fast_candidate_walker(self):
                return enable_fast_walker

            @property
            def dispersy_enable_candidate_walker(self):
                # disable candidate walker
                return True

            @property
            def dispersy_enable_bloom_filter_sync(self):
                return False

        class Info(object):
            pass

        assert isinstance(cid_hex, str)
        assert len(cid_hex) == 40
        assert isinstance(enable_fast_walker, bool)
        cid = cid_hex.decode("HEX")

        dispersy = Dispersy(StandaloneEndpoint(0), u".", u":memory:")
        dispersy.start(autoload_discovery=True)
        dispersy.statistics.enable_debug_statistics(True)
        self.dispersy_objects.append(dispersy)
        community = WCommunity.init_community(dispersy, dispersy.get_member(mid=cid), dispersy.get_new_member())
        summary_logger.info(community.cid.encode("HEX"))
        history = []
        begin = time()
        for _ in xrange(60 * 15):
            yield deferLater(reactor, 1, lambda: None)
            now = time()
            info = Info()
            info.diff = now - begin
            info.candidates = [(candidate, candidate.get_category(now)) for candidate in community._candidates.itervalues()]
            info.verified_candidates = [(candidate, candidate.get_category(now)) for candidate in community.dispersy_yield_verified_candidates()]
            info.incoming_walks = dispersy.statistics.incoming_intro_count
            info.outgoing_intro_count = dispersy.statistics.outgoing_intro_count
            info.walk_success_count = dispersy.statistics.walk_success_count
            info.lan_address = dispersy.lan_address
            info.wan_address = dispersy.wan_address
            info.connection_type = dispersy.connection_type
            history.append(info)

            summary_logger.info("after %.1f seconds there are %d verified candidates [e%d:w%d:s%d:i%d:d%d:n%d]",
                                info.diff,
                                len([_ for _, category in info.candidates if category in (u"walk", u"stumble")]),
                                len([_ for candidate,_ in info.candidates if candidate.is_eligible_for_walk(now)]),
                                len([_ for _, category in info.candidates if category == u"walk"]),
                                len([_ for _, category in info.candidates if category == u"stumble"]),
                                len([_ for _, category in info.candidates if category == u"intro"]),
                                len([_ for _, category in info.candidates if category == u"discovered"]),
                                len([_ for _, category in info.candidates if category is None]))

        dispersy.statistics.update()
        summary_logger.debug("\n%s", pformat(dispersy.statistics.get_dict()))

        # write graph statistics
        with open("%s_connections.txt" % cid_hex, "w+") as handle:
            handle.write("TIME VERIFIED_CANDIDATES WALK_CANDIDATES STUMBLE_CANDIDATES INTRO_CANDIDATES NONE_CANDIDATES INCOMING_WALKS OUTGOING_WALKS WALK_SUCCESS LAN_ADDRESS WAN_ADDRESS CONNECTION_TYPE\n")
            for info in history:
                handle.write("%f   %d   %d   %d   %d   %d   %d   %d   %d   %s   %s   \"%s\"\n" % (
                        info.diff,
                        len(info.verified_candidates),
                        len([_ for _, category in info.candidates if category == u"walk"]),
                        len([_ for _, category in info.candidates if category == u"stumble"]),
                        len([_ for _, category in info.candidates if category == u"intro"]),
                        len([_ for _, category in info.candidates if category is None]),
                        info.incoming_walks,
                        info.outgoing_intro_count,
                        info.walk_success_count,
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
        summary_logger.debug("Average verified candidates: %.1f", average_verified_candidates)
        self.assertGreater(average_verified_candidates, 10.0)
