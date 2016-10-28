"""
Run Dispersy in standalone tracker mode.

Outputs statistics every 300 seconds:
- BANDWIDTH BYTES-UP BYTES-DOWN
- COMMUNITY COUNT(OVERLAYS) COUNT(KILLED-OVERLAYS)
- CANDIDATE COUNT(ALL_CANDIDATES)                       18/07/13 no longer used
- CANDIDATE2 COUNT(VERIFIED_CANDIDATES)                 18/07/13 replaces CANDIDATE

Outputs incoming candidates info:
- REQ_IN2 HEX(COMMUNITY) hex(MEMBER) DISPERSY-VERSION OVERLAY-VERSION ADDRESS PORT
- RES_IN2 HEX(COMMUNITY) hex(MEMBER) DISPERSY-VERSION OVERLAY-VERSION ADDRESS PORT

Outputs destroyed communities whenever notified by a candidate:
- DESTROY_IN HEX(COMMUNITY) hex(MEMBER) DISPERSY-VERSION OVERLAY-VERSION ADDRESS PORT
- DESTROY_OUT HEX(COMMUNITY) hex(MEMBER) DISPERSY-VERSION OVERLAY-VERSION ADDRESS PORT

Note that there is no output for REQ_IN2 for destroyed overlays.  Instead a DESTROY_OUT is given
whenever a introduction request is received for a destroyed overlay.
"""
import errno
import os
import signal
import sys
from time import time

from dispersy.candidate import LoopbackCandidate
from dispersy.crypto import NoVerifyCrypto, NoCrypto
from dispersy.discovery.community import DiscoveryCommunity
from dispersy.dispersy import Dispersy
from dispersy.endpoint import StandaloneEndpoint
from dispersy.exception import CommunityNotFoundException
from dispersy.tracker.community import TrackerCommunity, TrackerHardKilledCommunity
from twisted.application.service import IServiceMaker, MultiService
from twisted.conch import manhole_tap
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, maybeDeferred, DeferredList
from twisted.internet.task import LoopingCall
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.python.log import msg, ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile
from twisted.python.threadable import isInIOThread
from zope.interface import implements

from tool.clean_observers import clean_twisted_observers

# Register yappi profiler
from utils import twistd_yappi

COMMUNITY_CLEANUP_INTERVAL = 180.0

if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035  # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK


clean_twisted_observers()


class TrackerDispersy(Dispersy):

    def __init__(self, endpoint, working_directory, silent=False, crypto=NoVerifyCrypto()):
        super(TrackerDispersy, self).__init__(endpoint, working_directory, u":memory:", crypto)

        # location of persistent storage
        self._persistent_storage_filename = os.path.join(working_directory, "persistent-storage.data")
        self._silent = silent
        self._my_member = None

    def start(self):
        assert isInIOThread()
        if super(TrackerDispersy, self).start():
            self._create_my_member()
            self._load_persistent_storage()

            self.register_task("unload inactive communities",
                               LoopingCall(self.unload_inactive_communities)).start(COMMUNITY_CLEANUP_INTERVAL)

            self.define_auto_load(TrackerCommunity, self._my_member)
            self.define_auto_load(TrackerHardKilledCommunity, self._my_member)

            if not self._silent:
                self._statistics_looping_call = LoopingCall(self._report_statistics)
                self._statistics_looping_call.start(300)

            return True
        return False

    def _create_my_member(self):
        # generate a new my-member
        ec = self.crypto.generate_key(u"very-low")
        self._my_member = self.get_member(private_key=self.crypto.key_to_bin(ec))

    @property
    def persistent_storage_filename(self):
        return self._persistent_storage_filename

    def get_community(self, cid, load=False, auto_load=True):
        try:
            return super(TrackerDispersy, self).get_community(cid, True, True)
        except CommunityNotFoundException:
            return TrackerCommunity.init_community(self, self.get_member(mid=cid), self._my_member)

    def _load_persistent_storage(self):
        # load all destroyed communities
        try:
            packets = [pkt.decode("HEX") for _, pkt in (line.split() for
                                                        line in open(self._persistent_storage_filename, "r") if not
                                                        line.startswith("#"))]
        except IOError:
            pass
        else:
            candidate = LoopbackCandidate()
            for pkt in reversed(packets):
                try:
                    self.on_incoming_packets([(candidate, pkt)], cache=False, timestamp=time())
                except:
                    self._logger.exception("Error while loading from persistent-destroy-community.data")

    def unload_inactive_communities(self):
        def is_active(community, now):
            # check 1: DiscoveryCommunity is always active
            if isinstance(community, DiscoveryCommunity):
                return True

            # check 2: does the community have any active candidates
            if community.update_strikes(now) < 3:
                return True

            return False

        now = time()
        inactive = [community for community in self._communities.itervalues() if not is_active(community, now)]
        print "#cleaned %d/%d communities" % (len(inactive), len(self._communities))

        deferred_list = []
        for community in inactive:
            deferred_list.append(maybeDeferred(community.unload_community))
        return DeferredList(deferred_list)

    def _report_statistics(self):
        mapping = {TrackerCommunity: [0,0], TrackerHardKilledCommunity: [0,0], DiscoveryCommunity: [0,0]}
        for community in self._communities.itervalues():
            mapping[type(community)][0] += 1
            mapping[type(community)][1] += len(list(community.dispersy_yield_verified_candidates())) 

        print "BANDWIDTH", self._statistics.total_up, self._statistics.total_down
        print "COMMUNITY", mapping[TrackerCommunity][0], mapping[TrackerHardKilledCommunity][0], mapping[DiscoveryCommunity][0]
        print "CANDIDATE2", mapping[TrackerCommunity][1], mapping[TrackerHardKilledCommunity][1], mapping[DiscoveryCommunity][1]

        if self._statistics.msg_statistics.outgoing_dict:
            for key, value in self._statistics.msg_statistics.outgoing_dict.iteritems():
                print "OUTGOING", key, value


class Options(usage.Options):
    optFlags = [
        ["memory-dump", "d", "use meliae to dump the memory periodically"],
        ["silent"     , "s", "Prevent tracker printing to console"],
    ]
    optParameters = [
        ["statedir", "s", "."       ,     "Use an alternate statedir"                                    , str],
        ["ip"      , "i", "0.0.0.0" ,     "Dispersy uses this ip"                                        , str],
        ["port"    , "p", 6421      ,     "Dispersy uses this UDL port"                                  , int],
        ["crypto"  , "c", "ECCrypto",     "The Crypto object type Dispersy is going to use"              , str],
        ["manhole" , "m", 0         ,     "Enable manhole telnet service listening at the specified port", int],
        ["logfile" , "l", "dispersy.log", "Use an alternate dispersy log file name",                       str],
    ]


class TrackerMultiService(MultiService):

    def __init__(self, log_file, log_dir):
        MultiService.__init__(self)
        self.log_file = log_file
        self.log_dir = log_dir

    def setServiceParent(self, parent):
        MultiService.setServiceParent(self, parent)
        # user daily logging
        log_file = DailyLogFile(self.log_file, self.log_dir)
        logger = FileLogObserver(log_file)
        parent.setComponent(ILogObserver, logger.emit)


class TrackerServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "tracker"
    description = "A Dispersy tracker"
    options = Options

    def makeService(self, options):
        """
        Construct a dispersy service.
        """
        tracker_service = TrackerMultiService(options["logfile"], options["statedir"])
        tracker_service.setName("Dispersy Tracker")

        # crypto
        if options["crypto"] == 'NoCrypto':
            crypto = NoCrypto()
        else:
            crypto = NoVerifyCrypto()

        container = [None]
        manhole_namespace = {}
        if options["manhole"]:
            port = options["manhole"]
            manhole = manhole_tap.makeService({
                'namespace': manhole_namespace,
                'telnetPort': 'tcp:%d:interface=127.0.0.1' % port,
                'sshPort': None,
                'passwd': os.path.join(os.path.dirname(__file__), 'passwd'),
            })
            tracker_service.addService(manhole)
            manhole.startService()

        def run():
            # setup
            dispersy = TrackerDispersy(StandaloneEndpoint(options["port"],
                                                          options["ip"]),
                                       unicode(options["statedir"]),
                                       bool(options["silent"]),
                                       crypto)
            container[0] = dispersy
            manhole_namespace['dispersy'] = dispersy

            self._stopping=False
            def signal_handler(sig, frame):
                msg("Received signal '%s' in %s (shutting down)" % (sig, frame))
                if not self._stopping:
                    self._stopping = True
                    try:
                        dispersy.stop()
                    except Exception, e:
                        msg("Got exception when stopping dispersy: %s" % e)
                    reactor.stop()
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)

            # start
            if not dispersy.start():
                raise RuntimeError("Unable to start Dispersy")

        # wait forever
        reactor.exitCode = 0
        reactor.callWhenRunning(run)
        # TODO: exit code
        return tracker_service


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = TrackerServiceMaker()
