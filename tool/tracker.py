#!/usr/bin/python

# Python 2.5 features
from __future__ import with_statement

"""
Run Dispersy in standalone tracker mode.


Concerning the relative imports, from PEP 328:
http://www.python.org/dev/peps/pep-0328/

   Relative imports use a module's __name__ attribute to determine that module's position in the
   package hierarchy. If the module's name does not contain any package information (e.g. it is set
   to '__main__') then relative imports are resolved as if the module were a top level module,
   regardless of where the module is actually located on the file system.
"""

from random import random
from time import time
import errno
import optparse
import signal
import sys

from callback import Callback
from candidate import WalkCandidate, BootstrapCandidate
from community import Community
from conversion import BinaryConversion
from crypto import ec_generate_key, ec_to_public_bin, ec_to_private_bin
from dispersy import Dispersy
from dprint import dprint
from endpoint import StandaloneEndpoint
from member import DummyMember, Member

if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035    # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK

class BinaryTrackerConversion(BinaryConversion):
    pass

class TrackerCommunity(Community):
    """
    This community will only use dispersy-candidate-request and dispersy-candidate-response messages.
    """
    def __init__(self, *args, **kargs):
        super(TrackerCommunity, self).__init__(*args, **kargs)
        # communities are cleaned based on a 'strike' rule.  periodically, we will check is there
        # are active candidates, when there are 'strike' is set to zero, otherwise it is incremented
        # by one.  once 'strike' reaches a predefined value the community is cleaned
        self._strikes = 0

    def _initialize_meta_messages(self):
        super(TrackerCommunity, self)._initialize_meta_messages()

        # remove all messages that we should not be using
        meta_messages = self._meta_messages
        self._meta_messages = {}
        for name in [u"dispersy-introduction-request",
                     u"dispersy-introduction-response",
                     u"dispersy-puncture-request",
                     u"dispersy-puncture",
                     u"dispersy-identity",
                     u"dispersy-missing-identity"]:
            self._meta_messages[name] = meta_messages[name]

    @property
    def dispersy_auto_download_master_member(self):
        return False

    def update_strikes(self, now):
        # does the community have any active candidates
        for candidate in self._dispersy.candidates:
            if candidate.is_active(self, now):
                self._strikes = 0
                break
        else:
            self._strikes += 1
        return self._strikes

    def initiate_meta_messages(self):
        return []

    def initiate_conversions(self):
        return [BinaryTrackerConversion(self, "\x00")]

    def dispersy_claim_sync_bloom_filter(self, identifier):
        # disable the sync mechanism
        return None

    def get_conversion(self, prefix=None):
        if not prefix in self._conversions:

            # the dispersy version MUST BE available.  Currently we
            # only support \x00: BinaryConversion
            if prefix[0] == "\x00":
                self._conversions[prefix] = BinaryTrackerConversion(self, prefix[1])

            else:
                raise KeyError("Unknown conversion")

            # use highest version as default
            if None in self._conversions:
                if self._conversions[None].version < self._conversions[prefix].version:
                    self._conversions[None] = self._conversions[prefix]
            else:
                self._conversions[None] = self._conversions[prefix]

        return self._conversions[prefix]

class TrackerDispersy(Dispersy):
    @classmethod
    def get_instance(cls, *args, **kargs):
        kargs["singleton_placeholder"] = Dispersy
        return super(TrackerDispersy, cls).get_instance(*args, **kargs)

    def __init__(self, callback, statedir, port):
        assert isinstance(port, int)
        assert 0 <= port
        super(TrackerDispersy, self).__init__(callback, statedir)

        # non-autoload nodes
        self._non_autoload = set()
        self._non_autoload.update(host for host, _ in self._bootstrap_candidates.iterkeys())
        # leaseweb machines, some are running boosters, they never unload a community
        self._non_autoload.update(["95.211.105.65", "95.211.105.67", "95.211.105.69", "95.211.105.71", "95.211.105.73", "95.211.105.75", "95.211.105.77", "95.211.105.79", "95.211.105.81", "85.17.81.36"])

        # generate a new my-member
        ec = ec_generate_key(u"very-low")
        self._my_member = Member(ec_to_public_bin(ec), ec_to_private_bin(ec))

        callback.register(self._unload_communities)
        callback.register(self._bandwidth_statistics)

    def get_community(self, cid, load=False, auto_load=True):
        try:
            return super(TrackerDispersy, self).get_community(cid, True, True)
        except KeyError:
            self._communities[cid] = TrackerCommunity.join_community(DummyMember(cid), self._my_member)
            return self._communities[cid]

    def _convert_packets_into_batch(self, packets):
        """
        Ensure that communities are loaded when the packet is received from a non-bootstrap node,
        otherwise, load and auto-load are disabled.
        """
        def filter_non_bootstrap_nodes():
            for candidate, packet in packets:
                cid = packet[2:22]

                if not cid in self._communities and candidate.sock_addr[0] in self._non_autoload:
                    if __debug__:
                        dprint("drop a ", len(packet), " byte packet (received from non-autoload node) from ", candidate, level="warning", force=1)
                        self._statistics.drop("_convert_packets_into_batch:from bootstrap node for unloaded community", len(packet))
                    continue

                yield candidate, packet

        packets = list(filter_non_bootstrap_nodes())
        if packets:
            return super(TrackerDispersy, self)._convert_packets_into_batch(packets)

        else:
            return []

    def yield_random_candidates(self, community):
        # the regular yield_random_candidates includes a security mechanism where we first choose
        # the category (walk or stumble) and than a candidate.  this results in a problem with flash
        # crowds, we solve this by removing the security mechanism.  this mechanism is not useful
        # for trackers as they will always receive a steady supply of valid connections as well.
        now = time()
        candidates = self._candidates.values()
        for length in xrange(len(candidates), 0, -1):
            candidate = candidates.pop(int(random() * length))
            if candidate.in_community(community, now) and candidate.is_any_active(now):
                yield candidate
        # candidates = [candidate for candidate in self._candidates.itervalues() if candidate.in_community(community, now) and candidate.is_any_active(now)]
        # for length in xrange(len(candidates), 0, -1):
        #     yield candidates.pop(int(random() * length))

    def _unload_communities(self):
        def is_active(community, now):
            # check 1: does the community have any active candidates
            if community.update_strikes(now) < 3:
                return True

            # check 2: does the community have any cached messages waiting to be processed
            for meta in self._batch_cache.iterkeys():
                if meta.community == community:
                    return True

            # the community is inactive
            return False

        while True:
            yield 180.0
            now = time()
            inactive = [community for community in self._communities.itervalues() if not is_active(community, now)]
            if __debug__: dprint("cleaning ", len(inactive), "/", len(self._communities), " communities")
            for community in inactive:
                community.unload_community()

    def _bandwidth_statistics(self):
        while True:
            yield 300.0
            print "BANDWIDTH", self._endpoint.total_up, self._endpoint.total_down

    def create_introduction_request(self, destination, forward=True):
        # prevent steps towards other trackers
        if not isinstance(destination, BootstrapCandidate):
            return super(TrackerDispersy, self).create_introduction_request(destination, forward)

    def on_introduction_request(self, messages):
        hex_cid = messages[0].community.cid.encode("HEX")
        for message in messages:
            host, port = message.candidate.sock_addr
            print "REQ_IN2", hex_cid, message.authentication.member.mid.encode("HEX"), ord(message.conversion.dispersy_version), ord(message.conversion.community_version), host, port
        return super(TrackerDispersy, self).on_introduction_request(messages)

    def on_introduction_response(self, messages):
        hex_cid = messages[0].community.cid.encode("HEX")
        for message in messages:
            host, port = message.candidate.sock_addr
            print "RES_IN2", hex_cid, message.authentication.member.mid.encode("HEX"), ord(message.conversion.dispersy_version), ord(message.conversion.community_version), host, port
        return super(TrackerDispersy, self).on_introduction_response(messages)

def main():
    command_line_parser = optparse.OptionParser()
    command_line_parser.add_option("--statedir", action="store", type="string", help="Use an alternate statedir", default=".")
    command_line_parser.add_option("--ip", action="store", type="string", default="0.0.0.0", help="Dispersy uses this ip")
    command_line_parser.add_option("--port", action="store", type="int", help="Dispersy uses this UDL port", default=6421)

    # parse command-line arguments
    opt, _ = command_line_parser.parse_args()
    print "Press Ctrl-C to stop Dispersy"

    # start Dispersy
    dispersy = TrackerDispersy.get_instance(Callback(), unicode(opt.statedir), opt.port)
    dispersy.endpoint = StandaloneEndpoint(dispersy, opt.port, opt.ip)
    dispersy.endpoint.start()
    dispersy.define_auto_load(TrackerCommunity)

    def signal_handler(sig, frame):
        print "Received", sig, "signal in", frame
        dispersy.callback.stop(wait=False)
    signal.signal(signal.SIGINT, signal_handler)

    # wait forever
    dispersy.callback.loop()
    dispersy.endpoint.stop()

if __name__ == "__main__":
    main()
