from collections import defaultdict
from copy import copy
from os import environ, getcwd, path
from socket import getfqdn
from subprocess import Popen, PIPE, STDOUT
from threading import Thread
from time import time, sleep
from unittest import skip, skipUnless
import logging

from nose.twistedtools import reactor
from twisted.internet.defer import Deferred, inlineCallbacks, returnValue
from twisted.internet.task import deferLater

from ..candidate import Candidate
from ..dispersy import Dispersy
from ..endpoint import StandaloneEndpoint
from ..message import Message, DropMessage
from ..util import blockingCallFromThread
from .debugcommunity.community import DebugCommunity
from .dispersytestclass import DispersyTestFunc


summary_logger = logging.getLogger("test-bootstrap-summary")

PING_COUNT = 10
MAX_RTT = 0.5


class TestBootstrapServers(DispersyTestFunc):

    def test_tracker(self):
        """
        Runs tracker.py and connects to it.
        """

        # we want to spawn the tracker from the dispersy parent dir to work around the crazy relative import stuff.
        # .../dispersy/test/test_bootstrap.py
        # .../dispersy/test/../..
        # .../ <- there!
        tracker_path = path.abspath(path.join(path.dirname(path.abspath(__file__)), '..', '..'))

        self._logger.debug("using tracker cwd \"%s\"", tracker_path)

        tracker_address = (self._dispersy.wan_address[0], 14242)
        args = ["twistd", "-n", "tracker",
                "--statedir", ".",
                "--port", str(tracker_address[1])]
        self._logger.debug("starting tracker: %s", args)

        def logstream(stream, loggercb):
            while True:
                out = stream.readline()
                if out:
                    loggercb(out.rstrip())
                else:
                    break
        # Twistd needs to be able to import from dispersy module
        env = copy(environ)
        dispersy_path = path.abspath(path.join(tracker_path, 'dispersy'))
        if 'PYTHONPATH' in env:
            env['PYTHONPATH'] += ":" + dispersy_path
        else:
            env['PYTHONPATH'] = dispersy_path

        self._logger.debug("PYTHONPATH is now: %s", env['PYTHONPATH'])
        tracker = Popen(args, cwd=tracker_path, stdout=PIPE, stderr=STDOUT, env=env)
        tracker_logging_thread = Thread(name="TrackerLoggingThread", target=logstream,
                                        args=(tracker.stdout, lambda s: self._logger.info("tracker is printing: " + s)))
        tracker_logging_thread.start()

        # can take a few seconds to start on older machines (or when running on a remote file
        # system)
        sleep(5)

        try:
            class Community(DebugCommunity):

                @property
                def dispersy_enable_candidate_walker(self):
                    return False

                @property
                def dispersy_enable_candidate_walker_responses(self):
                    return True

            node, = self.create_nodes(1, community_class=Community, autoload_discovery=True)

            # node sends introduction request
            destination = Candidate(tracker_address, False)
            node.send_message(node.create_introduction_request(destination=destination,
                                                               source_lan=node.lan_address,
                                                               source_wan=node.wan_address,
                                                               advice=True,
                                                               connection_type=u"unknown",
                                                               sync=None,
                                                               identifier=4242,
                                                               global_time=42),
                              destination)

            # node receives missing identity
            _, message = node.receive_message(names=[u"dispersy-missing-identity"]).next()
            self.assertEqual(message.payload.mid, node.my_member.mid)

            packet = node.fetch_packets([u"dispersy-identity", ], node.my_member.mid)[0]
            node.send_packet(packet, destination)

            node.process_packets()

            _, message = node.receive_message(names=[u"dispersy-identity"]).next()

        finally:
            self._logger.debug("terminate tracker")

            tracker.terminate()  # sends SIGTERM
            self.assertEqual(tracker.wait(), 0), tracker.returncode

    @skipUnless(environ.get("TEST_BOOTSTRAP") == "yes", "This 'unittest' tests the external bootstrap processes, as such, this is not part of the code review process")
    def test_servers_are_up(self):
        """
        Sends a dispersy-introduction-request to the trackers and counts how long it takes until the
        dispersy-introduction-response is received.
        """
        class PingCommunity(DebugCommunity):

            def __init__(self, *args, **kargs):
                super(PingCommunity, self).__init__(*args, **kargs)

                self._pings_done = 0
                self._request = defaultdict(dict)
                self._summary = defaultdict(list)
                self._hostname = {}
                self._identifiers = defaultdict(str)
                self._pcandidates = []

                self.test_d = Deferred()

            @property
            def dispersy_enable_candidate_walker(self):
                # disable candidate walker
                return True

            @inlineCallbacks
            def start_walking(self):
                for _ in xrange(10):
                    if self._dispersy._discovery_community and self._dispersy._discovery_community.bootstrap.are_resolved:
                        self._pcandidates = [self.get_candidate(address) for address in
                                             set(self._dispersy._discovery_community.bootstrap.candidate_addresses)]
                        break
                    yield deferLater(reactor, 1, lambda: None)
                else:
                    test.fail("No candidates discovered")

                for candidate in self._pcandidates:
                    for (host, port), b_candidate in self._dispersy._discovery_community.bootstrap._candidates.iteritems():
                        if candidate == b_candidate:
                            self._hostname[candidate.sock_addr] = host
                self._pcandidates.sort(cmp=lambda a, b: cmp(a.sock_addr, b.sock_addr))

                for _ in xrange(PING_COUNT):
                    self.ping(time())
                    yield deferLater(reactor, 1, lambda: None)
                    self.summary()
                self.test_d.callback(None)

            def on_introduction_response(self, messages):
                now = time()
                self._logger.debug("PONG")
                for message in messages:
                    candidate = message.candidate
                    if candidate.sock_addr in self._request:
                        request_stamp = self._request[candidate.sock_addr].pop(message.payload.identifier, 0.0)
                        self._summary[candidate.sock_addr].append(now - request_stamp)
                        self._identifiers[candidate.sock_addr] = message.authentication.member.mid
                return super(DebugCommunity, self).on_introduction_response(messages)

            def ping(self, now):
                self._logger.debug("PING")
                self._pings_done += 1
                for candidate in self._pcandidates:
                    request = self.create_introduction_request(candidate, False)
                    self._request[candidate.sock_addr][request.payload.identifier] = now

            def summary(self):
                for candidate in self._pcandidates:
                    sock_addr = candidate.sock_addr
                    rtts = self._summary[sock_addr]
                    if rtts:
                        summary_logger.info("%s %15s:%-5d %-30s %dx %.1f avg  [%s]",
                                            self._identifiers[sock_addr].encode("HEX"),
                                            sock_addr[0],
                                            sock_addr[1],
                                            self._hostname[sock_addr],
                                            len(rtts),
                                            sum(rtts) / len(rtts),
                                            ", ".join(str(round(rtt, 1)) for rtt in rtts[-10:]))
                    else:
                        summary_logger.warning("%s:%d %s missing",
                                               sock_addr[0], sock_addr[1], self._hostname[sock_addr])

            def finish(self, request_count, min_response_count, max_rtt):
                # write graph statistics
                handle = open("summary.txt", "w+")
                handle.write("HOST_NAME ADDRESS REQUESTS RESPONSES\n")
                for candidate in self._pcandidates:
                    sock_addr = candidate.sock_addr
                    rtts = self._summary[sock_addr]

                    handle.write("%s %s:%d %d %d\n" %
                                 (self._hostname[sock_addr], sock_addr[0], sock_addr[1], self._pings_done, len(rtts)))
                handle.close()

                handle = open("walk_rtts.txt", "w+")
                handle.write("HOST_NAME ADDRESS RTT\n")
                for candidate in self._pcandidates:
                    sock_addr = candidate.sock_addr
                    rtts = self._summary[sock_addr]

                    for rtt in rtts:
                        handle.write("%s %s:%d %f\n" % (self._hostname[sock_addr], sock_addr[0], sock_addr[1], rtt))
                handle.close()

                for candidate in self._pcandidates:
                    sock_addr = candidate.sock_addr
                    rtts = self._summary[sock_addr]

                    test.assertLessEqual(min_response_count, len(rtts), "Only received %d/%d responses from %s:%d" %
                                         (len(rtts), request_count, sock_addr[0], sock_addr[1]))
                    test.assertLessEqual(sum(rtts) / len(rtts), max_rtt, "Average RTT %f from %s:%d is more than allowed %f" %
                                         (sum(rtts) / len(rtts), sock_addr[0], sock_addr[1], max_rtt))

        test = self

        @inlineCallbacks
        def do_pings():
            dispersy = Dispersy(StandaloneEndpoint(0), u".", u":memory:")
            dispersy.start(autoload_discovery=True)
            self.dispersy_objects.append(dispersy)
            community = PingCommunity.create_community(dispersy, dispersy.get_new_member())
            yield community.test_d
            dispersy.stop()
            returnValue(community)

        assert_margin = 0.9
        community = blockingCallFromThread(reactor, do_pings)
        community.finish(PING_COUNT, PING_COUNT * assert_margin, MAX_RTT)

    # TODO(emilon): port this to twisted
    @skip("The stress test is not actually a unittest")
    def test_perform_heavy_stress_test(self):
        """
        Sends many a dispersy-introduction-request messages to a single tracker and counts how long
        it takes until the dispersy-introduction-response messages are received.
        """
        class PingCommunity(DebugCommunity):

            def __init__(self, master, candidates):
                super(PingCommunity, self).__init__(master)

                self._original_my_member = self._my_member

                self._request = {}
                self._summary = {}
                self._hostname = {}
                self._identifiers = {}
                self._pcandidates = candidates
                self._queue = []
                # self._pcandidates = self._dispersy._bootstrap_candidates.values()
                # self._pcandidates = [Candidate(("130.161.211.198", 6431))]

                for candidate in self._pcandidates:
                    self._request[candidate.sock_addr] = {}
                    self._summary[candidate.sock_addr] = []
                    self._hostname[candidate.sock_addr] = getfqdn(candidate.sock_addr[0])
                    self._identifiers[candidate.sock_addr] = ""

            def _initialize_meta_messages(self):
                super(PingCommunity, self)._initialize_meta_messages()

                # replace the callbacks for the dispersy-introduction-response message
                meta = self._meta_messages[u"dispersy-introduction-response"]
                self._meta_messages[meta.name] = Message(meta.community,
                                                         meta.name,
                                                         meta.authentication,
                                                         meta.resolution,
                                                         meta.distribution,
                                                         meta.destination,
                                                         meta.payload,
                                                         self.check_introduction_response,
                                                         meta.handle_callback,
                                                         meta.undo_callback,
                                                         meta.batch)

            @property
            def dispersy_enable_candidate_walker(self):
                return False

            @property
            def dispersy_enable_candidate_walker_responses(self):
                return True

            def dispersy_take_step(self):
                test.fail("we disabled the walker")

            def create_dispersy_identity(self, sign_with_master=False, store=True, update=True, member=None):
                self._my_member = member if member else self._original_my_member
                try:
                    return super(PingCommunity, self).create_dispersy_identity(sign_with_master, store, update)
                finally:
                    self._my_member = self._original_my_member

            def check_introduction_response(self, messages):
                now = time()
                for message in messages:
                    candidate = message.candidate
                    if candidate.sock_addr in self._request:
                        request_stamp = self._request[candidate.sock_addr].pop(message.payload.identifier, 0.0)
                        if request_stamp:
                            self._summary[candidate.sock_addr].append(now - request_stamp)
                            self._identifiers[candidate.sock_addr] = message.authentication.member.mid
                        else:
                            self._logger.warning("identifier clash %s", message.payload.identifier)

                    yield DropMessage(message, "not doing anything in this script")

            def prepare_ping(self, member):
                self._my_member = member
                try:
                    for candidate in self._pcandidates:
                        request = self._dispersy.create_introduction_request(self, candidate, False, forward=False)
                        self._queue.append((request.payload.identifier, request.packet, candidate))
                finally:
                    self._my_member = self._original_my_member

            def ping_from_queue(self, count):
                for identifier, packet, candidate in self._queue[:count]:
                    self._dispersy.endpoint.send([candidate], [packet])
                    self._request[candidate.sock_addr][identifier] = time()

                self._queue = self._queue[count:]

            def ping(self, member):
                self._my_member = member
                try:
                    for candidate in self._pcandidates:
                        request = self._dispersy.create_introduction_request(self, candidate, False)
                        self._request[candidate.sock_addr][request.payload.identifier] = time()
                finally:
                    self._my_member = self._original_my_member

            def summary(self):
                for sock_addr, rtts in sorted(self._summary.iteritems()):
                    if rtts:
                        self._logger.info("%s %15s:%-5d %-30s %dx %.1f avg  [%s]",
                                          self._identifiers[sock_addr].encode("HEX"),
                                          sock_addr[0],
                                          sock_addr[1],
                                          self._hostname[sock_addr],
                                          len(rtts),
                                          sum(rtts) / len(rtts),
                                          ", ".join(str(round(rtt, 1)) for rtt in rtts[-10:]))
                    else:
                        self._logger.warning("%s:%d %s missing", sock_addr[0], sock_addr[1], self._hostname[sock_addr])

        MEMBERS = 10000  # must be a multiple of 100
        COMMUNITIES = 1
        ROUNDS = 10

        self._logger.info("prepare communities, members, etc")
        with self._dispersy.database:
            candidates = [Candidate(("130.161.211.245", 6429), False)]
            communities = [PingCommunity.create_community(self._dispersy, self._my_member, candidates)
                           for _ in xrange(COMMUNITIES)]
            members = [self._dispersy.get_new_member(u"low") for _ in xrange(MEMBERS)]

            for community in communities:
                for member in members:
                    community.create_dispersy_identity(member=member)

        self._logger.info("prepare request messages")
        for _ in xrange(ROUNDS):
            for community in communities:
                for member in members:
                    community.prepare_ping(member)

            sleep(5)
        sleep(15)

        self._logger.info("ping-ping")
        BEGIN = time()
        for _ in xrange(ROUNDS):
            for community in communities:
                for _ in xrange(MEMBERS / 100):
                    community.ping_from_queue(100)
                    sleep(0.1)

            for community in communities:
                community.summary()
        END = time()

        sleep(10)
        self._logger.info("--- did %d requests per community", ROUNDS * MEMBERS)
        self._logger.info("--- spread over %.2f seconds", END - BEGIN)
        for community in communities:
            community.summary()

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
