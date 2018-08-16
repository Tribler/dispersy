import logging
from random import shuffle
from threading import Lock

from twisted.internet import reactor
from twisted.internet.abstract import isIPAddress
from twisted.internet.defer import gatherResults, succeed, inlineCallbacks
from twisted.internet.task import LoopingCall

from ..candidate import Candidate
from ..taskmanager import TaskManager
from ..util import blocking_call_on_reactor_thread

# Note that some the following DNS entries point to the same IP addresses.  For example, currently
# both DISPERSY1.TRIBLER.ORG and DISPERSY1.ST.TUDELFT.NL point to 130.161.211.245.  Once these two
# DNS entries are resolved only a single Candidate is made.  This requires a potential
# attacker to disrupt the DNS servers for both domains at the same time.
_DEFAULT_ADDRESSES = [
    # DNS entries on tribler.org
    ("dispersy1.tribler.org", 6421),
    ("130.161.119.206"      , 6421),
    ("dispersy2.tribler.org", 6422),
    ("130.161.119.206"      , 6422),
    ("dispersy3.tribler.org", 6423),
    ("131.180.27.155"       , 6423),
    ("dispersy4.tribler.org", 6424),
    ("83.149.70.6"          , 6424),
    ("dispersy7.tribler.org", 6427),
    ("95.211.155.142"       , 6427),
    ("dispersy8.tribler.org", 6428),
    ("95.211.155.131"       , 6428),

    # DNS entries on st.tudelft.nl
    ("dispersy1.st.tudelft.nl", 6421),
    ("dispersy2.st.tudelft.nl", 6422),
    ("dispersy3.st.tudelft.nl", 6423),
    #(u"dispersy4.st.tudelft.nl", 6424),
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


class Bootstrap(TaskManager):

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
        assert all(isinstance(host, str) for host, _ in addresses), [type(host) for host, _ in addresses]
        assert all(isinstance(port, int) for _, port in addresses), [type(port) for _, port in addresses]
        super(Bootstrap, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._lock = Lock()
        self._candidates = dict((address, None) for address in addresses)

    @property
    def all_resolved(self):
        """
        Returns True when all addresses are resolved.

        Note: this method is thread safe.
        """
        with self._lock:
            return all(self._candidates.values())

    @property
    def candidates(self):
        """
        Returns all *resolved* ip, port pairs.

        Note: this method is thread safe.
        """
        with self._lock:
            candidates = list(self._candidates.values())
            shuffle(candidates)
            return [candidate for candidate in candidates if candidate]

    @property
    def candidate_addresses(self):
        with self._lock:
            return [candidate.sock_addr for candidate in self._candidates.values() if candidate]

    @property
    def progress(self):
        """
        Returns a (resolved_count, total_count) tuple.

        Note: this method is thread safe.
        """
        with self._lock:
            return (len([candidate for candidate in self._candidates.values() if candidate]),
                    len(self._candidates))

    def reset(self):
        """
        Removes all previously resolved addresses.

        Note: this method is thread safe.
        """
        with self._lock:
            self._candidates = dict((address, None) for address in self._candidates.keys())

    def resolve(self):
        """
        Resolve all unresolved trackers asynchronously.

        """
        if self.all_resolved:
            self.cancel_pending_task('task_resolving_bootstrap_address')
            self._logger.debug("Resolved all bootstrap addresses")
            return succeed(None)
        else:
            self._logger.info("Resolving bootstrap addresses")

            addresses = [address for address, candidate in list(self._candidates.items()) if not candidate]
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
                    self.register_task("resolve_%s_%s" % (host, port), deferred)
                    deferred.addCallback(lambda ip, host=host, port=port: add_candidate(ip, host, port))
                    deferred.addErrback(lambda _, host=host, port=port: no_candidate(host, port))
                    deferreds.append(deferred)

            return gatherResults(deferreds)

    def start(self, interval=300):
        """
        Resolves a bootstrap address by scheduling a LoopingCall and
        calls a callback with the result of the resolve if passed.
        :param interval: The interval of the LoopingCall
        :param now: A boolean indicating if the LoopingCall should start immediately.
        :param callback: The callback that should be called with the result of the resolve function.
        :return: A deferred which fires once the resolving of the bootstrap servers has been started.
        """

        if not self.is_pending_task_active('task_resolving_bootstrap_address'):
            self.register_task('task_resolving_bootstrap_address',
                               LoopingCall(self.resolve)).start(interval, now=False)

        return self.resolve()

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def stop(self):
        """
        Clears all pending tasks scheduled on the TaskManager
        """
        yield self.wait_for_deferred_tasks()
        self.cancel_all_pending_tasks()
