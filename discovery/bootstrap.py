from random import shuffle
from threading import Lock
import logging

from twisted.internet import reactor
from twisted.internet.abstract import isIPAddress
from twisted.internet.defer import gatherResults, inlineCallbacks, returnValue
from twisted.internet.task import LoopingCall

from ..candidate import Candidate


# Note that some the following DNS entries point to the same IP addresses.  For example, currently
# both DISPERSY1.TRIBLER.ORG and DISPERSY1.ST.TUDELFT.NL point to 130.161.211.245.  Once these two
# DNS entries are resolved only a single Candidate is made.  This requires a potential
# attacker to disrupt the DNS servers for both domains at the same time.
_DEFAULT_ADDRESSES = [
    # DNS entries on tribler.org
    (u"dispersy1.tribler.org", 6421),
    (u"130.161.211.245"      , 6421),
    (u"dispersy2.tribler.org", 6422),
    (u"130.161.211.245"      , 6422),
    (u"dispersy3.tribler.org", 6423),
    (u"131.180.27.155"       , 6423),
    (u"dispersy4.tribler.org", 6424),
    (u"83.149.70.6"          , 6424),
    (u"dispersy7.tribler.org", 6427),
    (u"95.211.155.142"       , 6427),
    (u"dispersy8.tribler.org", 6428),
    (u"95.211.155.131"       , 6428),

    # DNS entries on st.tudelft.nl
    (u"dispersy1.st.tudelft.nl", 6421),
    (u"dispersy2.st.tudelft.nl", 6422),
    (u"dispersy3.st.tudelft.nl", 6423),
    (u"dispersy4.st.tudelft.nl", 6424),
]
# 04/12/13 Boudewijn: We are phasing out the dispersy{1-9}b entries.  Note that older clients will
# still assume these entries exist!
# (u"dispersy1b.tribler.org", 6421),
# (u"dispersy2b.tribler.org", 6422),
# (u"dispersy3b.tribler.org", 6423),
# (u"dispersy4b.tribler.org", 6424),
# (u"dispersy5b.tribler.org", 6425),
# (u"dispersy6b.tribler.org", 6426),
# (u"dispersy7b.tribler.org", 6427),
# (u"dispersy8b.tribler.org", 6428),

# _DEFAULT_ADDRESSES = _DEFAULT_ADDRESSES + tuple((u"rotten.dns.entry%d.org" % i, 1234) for i in xrange(8))


class Bootstrap(object):

    @staticmethod
    def load_addresses_from_file(filename):
        """
        Reads FILENAME and returns the hosts therein, otherwise returns an empty list.
        """
        addresses = []
        try:
            for line in open(filename, "r"):
                line = line.strip()
                if not line.startswith("#"):
                    host, port = line.split()
                    addresses.append((host.decode("UTF-8"), int(port)))
        except:
            pass

        return addresses

    @staticmethod
    def get_default_addresses():
        """
        Returns the predefined default addresses.
        """
        return _DEFAULT_ADDRESSES

    def __init__(self, addresses):
        assert isinstance(addresses, (tuple, list)), type(addresses)
        assert all(isinstance(address, tuple) for address in addresses), [type(address) for address in addresses]
        assert all(len(address) == 2 for  address in addresses), [len(address) for address in addresses]
        assert all(isinstance(host, unicode) for host, _ in addresses), [type(host) for host, _ in addresses]
        assert all(isinstance(port, int) for _, port in addresses), [type(port) for _, port in addresses]
        super(Bootstrap, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._lock = Lock()
        self._candidates = dict((address, None) for address in addresses)
        self._resolution_lc = None

    @property
    def are_resolved(self):
        """
        Returns True when all addresses are resolved.

        Note: this method is thread safe.
        """
        with self._lock:
            return all(self._candidates.itervalues())

    @property
    def candidates(self):
        """
        Returns all *resolved* ip, port pairs.

        Note: this method is thread safe.
        """
        with self._lock:
            candidates = self._candidates.values()
            shuffle(candidates)
            return [candidate for candidate in candidates if candidate]

    @property
    def candidate_addresses(self):
        with self._lock:
            return [candidate.sock_addr for candidate in self._candidates.itervalues() if candidate]

    @property
    def progress(self):
        """
        Returns a (resolved_count, total_count) tuple.

        Note: this method is thread safe.
        """
        with self._lock:
            return (len([candidate for candidate in self._candidates.itervalues() if candidate]),
                    len(self._candidates))

    def reset(self):
        """
        Removes all previously resolved addresses.

        Note: this method is thread safe.
        """
        with self._lock:
            self._candidates = dict((address, None) for address in self._candidates.iterkeys())

    @inlineCallbacks
    def resolve(self):
        """
        Resolve all unresolved trackers asynchronously.

        """
        success = False
        if self.are_resolved:
            success = True
        else:
            addresses = [address for address, candidate in self._candidates.items() if not candidate]
            shuffle(addresses)

            def add_candidate(ip, host, port):
                self._logger.info("Resolved %s into %s:%d", host, ip, port)
                self._candidates[(host, port)] = Candidate((str(ip), port), False)

            def no_candidate(host, port):
                self._logger.warning("Could not resolve bootstrap candidate: %s:%s", host, port)

            deferreds = []
            for host, port in addresses:
                if isIPAddress(host):
                    add_candidate(host, host, port)
                else:
                    deferred = reactor.resolve(host)
                    deferred.addCallback(lambda ip, host=host, port=port: add_candidate(ip, host, port))
                    deferred.addErrback(lambda _, host=host, port=port: no_candidate(host, port))
                    deferreds.append(deferred)

            yield gatherResults(deferreds)
        returnValue(success)

    def resolve_until_success(self, interval=300, now=False, callback=None):
        def resolution_lc():
            if self.are_resolved:
                self._resolution_lc.stop()
                self._resolution_lc = None

            else:
                self._logger.info("Resolving bootstrap addresses")
                deferred = self.resolve()
                if callback:
                    deferred.addCallback(callback)

        # TODO(emilon): use taskmanager for this
        if not self._resolution_lc:
            self._resolution_lc = LoopingCall(resolution_lc)
            self._resolution_lc.start(interval, now)
        return self._resolution_lc

    def stop(self):
        if self._resolution_lc and self._resolution_lc.running:
            self._resolution_lc.stop()
