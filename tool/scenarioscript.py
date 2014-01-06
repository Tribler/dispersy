try:
    from scipy.stats import poisson, expon
except ImportError:
    poisson = expon = None
    print "Unable to import from scipy.  ScenarioPoisson and ScenarioExpon are disabled"

try:
    from psutil import Process, cpu_percent
except ImportError:
    Process = cpu_percent = None
    print "Unable to import from psutil.  Process statistics are disabled"

import sqlite3
from itertools import count
from abc import ABCMeta, abstractproperty
from collections import defaultdict, namedtuple
from hashlib import sha1
from os import getpid, uname, path
from random import random, uniform
from re import compile as re_compile
from sys import maxsize
from time import time, sleep

from ..dispersydatabase import DispersyDatabase
from ..logger import get_logger
from ..script import ScriptBase
from ..tests.debugcommunity.node import DebugNode
from .ldecoder import Parser, NextFile
logger = get_logger(__name__)


class ScenarioScript(ScriptBase):

    __metaclass__ = ABCMeta

    def __init__(self, *args, **kargs):
        super(ScenarioScript, self).__init__(*args, **kargs)
        self._my_member = None
        self._master_member = None
        self._cid = sha1(self.master_member_public_key).digest()
        self._is_joined = False

        # _SCENARIO_CALLS contains all the scenario methods that have been called.  This allows
        # scenario methods to enforce dependencies.  Contains SCENARIO_NAME:CALL_COUNT pairs.
        self._scenario_calls = defaultdict(int)

        self.log("scenario-init", peernumber=int(self._kargs["peernumber"]), hostname=uname()[1])

        if self.enable_statistics:
            self._dispersy.callback.register(self._periodically_log_statistics)

    @property
    def enable_wait_for_wan_address(self):
        return False

    @property
    def enable_statistics(self):
        return 30.0

    def run(self):
        self.add_testcase(self._run_scenario)

    def _run_scenario(self):
        for deadline, _, call, args in self.parse_scenario():
            yield max(0.0, deadline - time())
            logger.debug(call.__name__)
            before = time()
            try:
                result = call(*args)
            finally:
                after = time()
                self.log("scenario-run", call=call.__name__, args=args, skew=deadline-before, delay=after-before)

            # update dependencies
            self._scenario_calls[call.__name__] += 1

            if result == "END":
                return

    @property
    def my_member_security(self):
        return u"low"

    @abstractproperty
    def master_member_public_key(self):
        pass
            # if False:
            # when crypto.py is disabled a public key is slightly
            # different...
            #     master_public_key = ";".join(("60", master_public_key[:60].encode("HEX"), ""))
        # return "3081a7301006072a8648ce3d020106052b81040027038192000404668ed626c6d6bf4a280cf4824c8cd31fe4c7c46767afb127129abfccdf8be3c38d4b1cb8792f66ccb603bfed395e908786049cb64bacab198ef07d49358da490fbc41f43ade33e05c9991a1bb7ef122cda5359d908514b3c935fe17a3679b6626161ca8d8d934d372dec23cc30ff576bfcd9c292f188af4142594ccc5f6376e2986e1521dc874819f7bcb7ae3ce400".decode("HEX")

    @abstractproperty
    def community_class(self):
        pass

    @property
    def community_args(self):
        return ()

    @property
    def community_kargs(self):
        return {}

    def log(self, _message, **kargs):
        pass

    def _periodically_log_statistics(self):
        statistics = self._dispersy.statistics
        process = Process(getpid()) if Process else None

        while True:
            statistics.update()

            # CPU
            if cpu_percent:
                self.log("scenario-cpu", percentage=cpu_percent(interval=0, percpu=True))

            # memory
            if process:
                rss, vms = process.get_memory_info()
                self.log("scenario-memory", rss=rss, vms=vms)

            # bandwidth
            self.log("scenario-bandwidth",
                     up=self._dispersy.endpoint.total_up,
                     down=self._dispersy.endpoint.total_down,
                     drop_count=self._dispersy.statistics.drop_count,
                     delay_count=statistics.delay_count,
                     delay_send=statistics.delay_send,
                     delay_success=statistics.delay_success,
                     delay_timeout=statistics.delay_timeout,
                     success_count=statistics.success_count,
                     received_count=statistics.received_count)

            # dispersy statistics
            self.log("scenario-connection",
                     connection_type=statistics.connection_type,
                     lan_address=statistics.lan_address,
                     wan_address=statistics.wan_address)

            # communities
            for community in statistics.communities:
                self.log("scenario-community",
                         hex_cid=community.hex_cid,
                         classification=community.classification,
                         global_time=community.global_time,
                         sync_bloom_new=community.sync_bloom_new,
                         sync_bloom_reuse=community.sync_bloom_reuse,
                         candidates=[dict(zip(["lan_address", "wan_address", "global_time"], tup)) for tup in community.candidates])

            # wait
            yield self.enable_statistics

    def parse_scenario(self):
        """
        Returns a list with (TIMESTAMP, FUNC, ARGS) tuples, where TIMESTAMP is the time when FUNC
        must be called.

        [@+][H:]M:S[-[H:]M:S] METHOD [ARG1 [ARG2 ..]] [{PEERNR1 [, PEERNR2, ...] [, PEERNR3-PEERNR6, ...]}]
        ^^^^
        use @ to schedule events based on experiment startstamp
        use + to schedule events based on peer startstamp
            ^^^^^^^^^^^^^^^^^
            schedule event hours:minutes:seconds after @ or +
            or add another hours:minutes:seconds pair to schedule uniformly chosen between the two
                              ^^^^^^^^^^^^^^^^^^^^^^^
                              calls script.schedule_METHOD(ARG1, ARG2)
                              the arguments are passed as strings
                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                      apply event only to peer 1 and 2, and peers in
                                                      range 3-6 (including both 3 and 6)
        """
        scenario = []
        re_line = re_compile("".join(("^",
                                      "(?P<origin>[@+])",
                                      "\s*",
                                      "(?:(?P<beginH>\d+):)?(?P<beginM>\d+):(?P<beginS>\d+)",
                                      "(?:\s*-\s*",
                                      "(?:(?P<endH>\d+):)?(?P<endM>\d+):(?P<endS>\d+)",
                                      ")?",
                                      "\s+",
                                      "(?P<method>\w+)(?P<args>\s+(.+?))??",
                                      "(?:\s*{(?P<peers>\s*!?\d+(?:-\d+)?(?:\s*,\s*!?\d+(?:-\d+)?)*\s*)})?",
                                      "\s*(?:\n)?$")))
        peernumber = int(self._kargs["peernumber"])
        filename = self._kargs["scenario"]
        origin = {"@": float(self._kargs["startstamp"]) if "startstamp" in self._kargs else time(),
                  "+": time()}

        for lineno, line in enumerate(open(filename, "r")):
            match = re_line.match(line)
            if match:
                # remove all entries that are None (allows us to get default per key)
                dic = dict((key, value) for key, value in match.groupdict().iteritems() if not value is None)

                # get the peers, if any, for which this line applies
                yes_peers = set()
                no_peers = set()
                for peer in dic.get("peers", "").split(","):
                    peer = peer.strip()
                    if peer:
                        # if the peer number (or peer number pair) is preceded by '!' it negates the result
                        if peer.startswith("!"):
                            peer = peer[1:]
                            peers = no_peers
                        else:
                            peers = yes_peers
                        # parse the peer number (or peer number pair)
                        if "-" in peer:
                            low, high = peer.split("-")
                            peers.update(xrange(int(low), int(high) + 1))
                        else:
                            peers.add(int(peer))

                if not (yes_peers or no_peers) or (yes_peers and peernumber in yes_peers) or (no_peers and not peernumber in no_peers):
                    begin = int(dic.get("beginH", 0)) * 3600.0 + int(dic.get("beginM", 0)) * 60.0 + int(dic.get("beginS", 0))
                    end = int(dic.get("endH", 0)) * 3600.0 + int(dic.get("endM", 0)) * 60.0 + int(dic.get("endS", 0))
                    assert end == 0.0 or begin <= end, "when end time is given it must be at or after the start time"
                    scenario.append((origin[dic.get("origin", "@")] + begin + (random() * (end - begin) if end else 0.0),
                                     lineno,
                                     getattr(self, "scenario_" + dic.get("method", "print")),
                                     tuple(dic.get("args", "").split())))

        assert scenario, "scenario is empty"
        assert any(func.__name__ == "scenario_end" for _, _, func, _ in scenario), "scenario end is not defined"
        assert any(func.__name__ == "scenario_start" for _, _, func, _ in scenario), "scenario start is not defined"
        scenario.sort()

        for deadline, _, func, args in scenario:
            logger.debug("scenario: @%.2fs %s", int(deadline - origin["@"]), func.__name__)
            self.log("scenario-schedule", deadline=int(deadline - origin["@"]), func=func.__name__, args=args)

        return scenario

    def has_community(self, load=False, auto_load=False):
        try:
            return self._dispersy.get_community(self._cid, load=load, auto_load=auto_load)
        except KeyError:
            return None

    def scenario_start(self, filepath="", *select_methods):
        """
        Start the scenario.
        """
        # dependencies
        if not (self._scenario_calls["scenario_start"] <= 0):
            raise RuntimeError("scenario_start must be called only once")

        if self._my_member is None:
            self._my_member = self._dispersy.get_new_member(self.my_member_security)
        if self._master_member is None:
            self._master_member = self._dispersy.get_member(self.master_member_public_key)

        if filepath:
            source_database_filename = path.join(self._kargs["localcodedir"], filepath)
            self.log("scenario-start-copy", state="load", source=source_database_filename)
            community = self.scenario_churn("online")
            assert community

            # read all packets from the database
            source_database = DispersyDatabase(source_database_filename)
            source_database.open(initial_statements=False, prepare_visioning=False)

            for select_method in select_methods:
                message_name, selection = select_method.split(":")
                meta = community.get_meta_message(unicode(message_name))

                if selection == "all":
                    packets = [str(packet)
                               for packet,
                               in source_database.execute(u"SELECT packet FROM sync WHERE meta_message = ? ORDER BY global_time",
                                                          (meta.database_id,))]

                elif selection == "divided-equally":
                    count_total, = source_database.execute(u"SELECT COUNT(*) FROM sync WHERE meta_message = ?",
                                                           (meta.database_id,)).next()
                    limit = int(count_total / int(self._kargs["peercount"]))
                    offset = limit * int(self._kargs["peernumber"])
                    packets = [str(packet)
                               for packet,
                               in source_database.execute(u"SELECT packet FROM sync WHERE meta_message = ? ORDER BY global_time LIMIT ? OFFSET ?",
                                                          (meta.database_id, limit, offset))]

                else:
                    raise RuntimeError("unknown select_method \"%s\"" % select_method)

            source_database.close()

            # process all packets
            self.log("scenario-start-copy", state="inject", count=len(packets))
            node = DebugNode(community)
            node.init_socket()
            node.init_my_member(candidate=False)

            prev_count_sync, = self._dispersy.database.execute(u"SELECT COUNT(*) FROM sync").next()
            node.give_packets(packets)

            # verify that len(PACKETS) new packets are in the database
            count_sync, = self._dispersy.database.execute(u"SELECT COUNT(*) FROM sync").next()
            if count_sync < prev_count_sync + len(packets):
                raise RuntimeError("INJECTION FAILED [prev:%d; current:%d; expected:%d]" %
                                   (prev_count_sync, count_sync, prev_count_sync + len(packets)))

            self.scenario_churn("offline")
            self.log("scenario-start-copy", state="done")

        self.log("scenario-start", my_mid=self._my_member.mid, my_public_key=self._my_member.public_key, my_private_key=self._my_member.private_key, master_mid=self._master_member.mid, classification=self.community_class.get_classification(), lan_address=self._dispersy.lan_address)

    def scenario_end(self):
        logger.debug("END")
        self.log("scenario-end")
        return "END"

    def scenario_print(self, *args):
        logger.info(" ".join(str(arg) for arg in args))

    def scenario_churn(self, state, duration=None):
        # dependencies
        if not (0 < self._scenario_calls["scenario_start"]):
            raise RuntimeError("scenario_churn must be called AFTER scenario_start")

        assert isinstance(state, str), type(state)
        assert state in ("online", "offline"), state
        assert duration is None or isinstance(duration, (str, float)), type(duration)

        duration = None if duration == None else float(duration)
        community = self.has_community()

        if state == "online":
            if community is None:
                logger.debug("online for the next %.2f seconds", duration)
                self.log("scenario-churn", state="online", duration=duration)

                if self._is_joined:
                    self.community_class.load_community(self._dispersy, self._master_member, *self.community_args, **self.community_kargs)

                else:
                    logger.debug("join community %s as %s", self._master_member.mid.encode("HEX"), self._my_member.mid.encode("HEX"))
                    community = self.community_class.join_community(self._dispersy, self._master_member, self._my_member, *self.community_args, **self.community_kargs)
                    community.auto_load = False
                    self._is_joined = True

            else:
                logger.debug("online for the next %.2f seconds (we are already online)", duration)
                self.log("scenario-churn", state="stay-online", duration=duration)

        elif state == "offline":
            if community is None:
                logger.debug("offline (we are already offline)")
                self.log("scenario-churn", state="stay-offline")

            else:
                logger.debug("offline")
                self.log("scenario-churn", state="offline")
                community.unload_community()

        else:
            raise ValueError("state must be either 'online' or 'offline'")

        return community

if poisson:
    class ScenarioPoisson(object):

        def __init__(self, *args, **kargs):
            super(ScenarioPoisson, self).__init__()
            self.__poisson_online_mu = 0.0
            self.__poisson_offline_mu = 0.0

        def __poisson_churn(self):
            while True:
                delay = float(poisson.rvs(self.__poisson_online_mu))
                self.scenario_churn("online", delay)
                yield delay

                delay = float(poisson.rvs(self.__poisson_offline_mu))
                self.scenario_churn("offline", delay)
                yield delay

        def scenario_poisson_churn(self, online_mu, offline_mu):
            self.__poisson_online_mu = float(online_mu)
            self.__poisson_offline_mu = float(offline_mu)
            self.log("scenario-poisson-churn", online_mu=self.__poisson_online_mu, offline_mu=self.__poisson_offline_mu)
            self._dispersy.callback.persistent_register(u"scenario-poisson-identifier", self.__poisson_churn)

if expon:
    class ScenarioExpon(object):
        def __init__(self, *args, **kargs):
            super(ScenarioExpon, self).__init__()
            self.__expon_online_beta = 0.0
            self.__expon_offline_beta = 0.0
            self.__expon_online_threshold = 0.0
            self.__expon_min_online = 0.0
            self.__expon_max_online = 0.0
            self.__expon_offline_threshold = 0.0
            self.__expon_max_offline = 0.0
            self.__expon_min_offline = 0.0

        def __expon_churn(self):
            while True:
                delay = expon.rvs(scale=self.__expon_online_beta)
                if delay >= self.__expon_online_threshold:
                    delay = float(min(self.__expon_max_online, max(self.__expon_min_online, delay)))
                    self.scenario_churn("online", delay)
                    yield delay

                delay = expon.rvs(scale=self.__expon_offline_beta)
                if delay >= self.__expon_offline_threshold:
                    delay = float(min(self.__expon_max_offline, max(self.__expon_min_offline, delay)))
                    self.scenario_churn("offline", delay)
                    yield delay

        def scenario_expon_churn(self, online_beta, offline_beta, online_threshold="DEF", min_online="DEF", max_online="DEF", offline_threshold="DEF", min_offline="DEF", max_offline="DEF"):
            self.__expon_online_beta = float(online_beta)
            self.__expon_offline_beta = float(offline_beta)
            self.__expon_online_threshold = float("5.0" if online_threshold == "DEF" else online_threshold)
            self.__expon_min_online = float("5.0" if min_online == "DEF" else min_online)
            self.__expon_max_online = float(maxsize if max_online == "DEF" else max_online)
            self.__expon_offline_threshold = float("5.0" if offline_threshold == "DEF" else offline_threshold)
            self.__expon_min_offline = float("5.0" if min_offline == "DEF" else min_offline)
            self.__expon_max_offline = float(maxsize if max_offline == "DEF" else max_offline)
            self.log("scenario-expon-churn", online_beta=self.__expon_online_beta, offline_beta=self.__expon_offline_beta, online_threshold=self.__expon_online_threshold, min_online=self.__expon_min_online, max_online=self.__expon_max_online, offline_threshold=self.__expon_offline_threshold, min_offline=self.__expon_min_offline, max_offline=self.__expon_max_offline)
            self._dispersy.callback.persistent_register(u"scenario-expon-identifier", self.__expon_churn)

class ScenarioUniform(object):
    def __init__(self, *args, **kargs):
        super(ScenarioUniform, self).__init__()
        self.__uniform_online_low = 0.0
        self.__uniform_online_high = 0.0
        self.__uniform_offline_low = 0.0
        self.__uniform_offline_high = 0.0

    def __uniform_churn(self):
        while True:
            delay = float(uniform(self.__uniform_online_low, self.__uniform_online_high))
            self.scenario_churn("online", delay)
            yield delay

            delay = float(uniform(self.__uniform_offline_low, self.__uniform_offline_high))
            self.scenario_churn("offline", delay)
            yield float(delay)

    def scenario_uniform_churn(self, online_mean, online_mod="DEF", offline_mean="DEF", offline_mod="DEF"):
        online_mean = float(online_mean)
        online_mod = float("0.50" if online_mod == "DEF" else online_mod)
        offline_mean = float("120.0" if offline_mean == "DEF" else offline_mean)
        offline_mod = float("0.0" if offline_mod == "DEF" else offline_mod)
        self.__uniform_online_low = online_mean * (1.0 - online_mod)
        self.__uniform_online_high = online_mean * (1.0 + online_mod)
        self.__uniform_offline_low = offline_mean * (1.0 - offline_mod)
        self.__uniform_offline_high = offline_mean * (1.0 + offline_mod)
        self.log("scenario-uniform-churn", online_low=self.__uniform_online_low, online_high=self.__uniform_online_high, offline_low=self.__uniform_offline_low, offline_high=self.__uniform_offline_high)
        self._dispersy.callback.persistent_register(u"scenario-uniform-identifier", self.__uniform_churn)

class ScenarioPredefined(object):
    """
    Handles predefined information.

    1. identity: peer, identity, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key
    2. churn: peer, identity, online, offline
    """

    def __init__(self, *args, **kargs):
        super(ScenarioPredefined, self).__init__()
        self._identities = dict()
        self._churn = []

    def _open_database(self, filepath):
        filename = path.join(self._kargs["localcodedir"], filepath)
        if not path.isfile(filename):
            raise RuntimeError("Unable to open [%s]" % filename)

        db = sqlite3.connect(filename)
        return db, db.cursor()

    def scenario_predefined_identities(self, filepath, table="identity"):
        assert isinstance(filepath, str)
        assert isinstance(table, str)

        Identity = namedtuple("Identity", ["identity", "public_key", "private_key"])
        db, cur = self._open_database(filepath)
        peernumber = int(self._kargs["peernumber"])
        identities = dict((identity, Identity(identity, public_key, private_key))
                          for identity, public_key, private_key
                          in cur.execute(u"SELECT identity, public_key, private_key FROM " + table + " WHERE peer = ?",
                                         (peernumber,)))

        self._identities.update(identities)

    def scenario_predefined_churn(self, filepath, table="churn"):
        assert isinstance(filepath, str)
        assert isinstance(table, str)

        Churn = namedtuple("Churn", ["identity", "online", "offline"])
        db, cur = self._open_database(filepath)
        peernumber = int(self._kargs["peernumber"])
        startstamp = float(self._kargs["startstamp"])
        churn = [Churn(identity, online + startstamp, offline + startstamp)
                 for identity, online, offline
                 in cur.execute(u"SELECT identity, online, offline FROM " + table + " WHERE peer = ?",
                                (peernumber,))]

        self._churn.extend(churn)
        self._churn.sort(self._churn, key=lambda churn: churn.online)

    def scenario_dispersy_start(self, prefix=""):
        assert isinstance(prefix, str)
        self._prefix = unicode(prefix)

        assert self._dispersy is None, "Dispersy is already running"
        assert Dispersy.has_instance() is None, "Dispersy is already running"
        assert DispersyDatabase.has_instance() is None, "Dispersy database is already loaded"
        self._dispersy = Dispersy.get_instance(self._callback, self._state_dir, self._prefix + u"dispersy.db")

    def set_identity(self, public_key, private_key):
        if not public_key == self._my_member.public_key:
            # TODO cleanup previous identity
            self._my_member = Member(public_key, private_key)


class ScenarioShareDatabase(object):
    def __init__(self, *args, **kargs):
        super(ScenarioShareDatabase, self).__init__()
        self._share_connection_cache = {}
        self._share_identity_cls = namedtuple("Identity", ["peer_number", "hostname", "lan_address", "wan_address", "public_key", "private_key"])
        self._sql_identities = u"""
CREATE TABLE IF NOT EXISTS identities (
 peer_number INTEGER PRIMARY KEY,
 hostname TEXT,
 lan_host TEXT,
 lan_port INTEGER,
 wan_host TEXT,
 wan_port INTEGER,
 public_key BLOB,
 private_key BLOB)"""
        self._sql_ready = u"""
CREATE TABLE IF NOT EXISTS ready (peer_number INTEGER PRIMARY KEY)
"""

    def _share_connect(self, filename, delay):
        if filename in self._share_connection_cache:
            return self._share_connection_cache[filename]

        else:
            for i in count(1):
                try:
                    con = sqlite3.connect(filename)
                    cur = con.cursor()

                except sqlite3.OperationalError as exception:
                    logger.debug("retry #%d [%s]", i, exception)
                    sleep(delay)

                else:
                    self._share_connection_cache[filename] = (con, cur)
                    return (con, cur)

    def _share_execute(self, filename, statement, bindings, commit, delay):
        con, cur = self._share_connect(filename, delay)

        for i in count(1):
            try:
                if isinstance(bindings, tuple):
                    results = list(cur.execute(statement, bindings))

                elif isinstance(bindings, list):
                    results = list(cur.executemany(statement, bindings))

                else:
                    raise ValuesError("BINDINGS must be either a tuple (calls execute) or list (calls executemany)")

                if commit:
                    con.commit()

            except sqlite3.OperationalError as exception:
                logger.debug("retry #%d [%s]", i, exception)
                sleep(delay)

            else:
                return results

    def _share_connect_local(self, delay=0.1):
        return self._share_connect(path.join(self._kargs["localcodedir"], "shared.db"), delay)

    def _share_execute_local(self, statement, bindings=(), commit=True, delay=0.1):
        return self._share_execute(path.join(self._kargs["localcodedir"], "shared.db"), statement, bindings, commit, delay)

    def _share_connect_remote(self, delay=0.1):
        return self._share_connect(path.join(self._kargs["resultdir"], "shared.db"), delay)

    def _share_execute_remote(self, statement, bindings=(), commit=True, delay=0.1):
        return self._share_execute(path.join(self._kargs["resultdir"], "shared.db"), statement, bindings, commit, delay)

    def _share_connect_memory(self, delay=0.1):
        return self._share_connect(":memory:", delay)

    def _share_execute_memory(self, statement, bindings=(), commit=True, delay=0.1):
        return self._share_execute(":memory:", statement, bindings, commit, delay)

    def scenario_share_identities(self):
        """
        Add an entry to the identities table in $RESULTDIR/shared.db.

        The identities table contains:
        - peer_number
        - lan_host
        - lan_port
        - wan_host (according to one or more trackers, requires self.enable_wait_for_wan_address)
        - wan_port (according to one or more trackers, requires self.enable_wait_for_wan_address)
        - public_key
        - private_key
        """
        # dependencies
        if not (0 < self._scenario_calls["scenario_start"]):
            raise RuntimeError("scenario_share_identities must be called AFTER scenario_start")
        if not (self._scenario_calls["scenario_share_synchronize"] <= 0):
            raise RuntimeError("scenario_share_identities must be called BEFORE scenario_share_synchronize")
        if not self.enable_wait_for_wan_address:
            raise RuntimeError("self.enable_wait_for_wan_address must be enabled")

        peer_number = int(self._kargs["peernumber"])
        peer_count = int(self._kargs["peercount"])
        lan_host, lan_port = self._dispersy.lan_address
        wan_host, wan_port = self._dispersy.wan_address
        public_key = self._my_member.public_key
        private_key = self._my_member.private_key

        self.log("scenario-share-identities", state="init", peer_number=peer_number)

        # ensure that the table exists
        self._share_execute_local(self._sql_identities)

        # insert our identity
        self._share_execute_local(u"INSERT INTO identities (peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                  (peer_number, uname()[1], lan_host, lan_port, wan_host, wan_port, buffer(public_key), buffer(private_key)))

        self.log("scenario-share-identities", state="done", peer_number=peer_number)

    def scenario_share_synchronize(self):
        # dependencies
        if not (0 < self._scenario_calls["scenario_start"]):
            raise RuntimeError("scenario_share_identities must be called AFTER scenario_start")
        if not (self._scenario_calls["scenario_expon_churn"] <= 0):
            raise RuntimeError("scenario_share_identities must be called BEFORE scenario_expon_churn")

        peer_number = int(self._kargs["peernumber"])
        peer_count = int(self._kargs["peercount"])
        low_peer_number = int(self._kargs["lowpeernumber"])
        high_peer_number = int(self._kargs["highpeernumber"])

        # ensure that the table exists
        self.log("scenario-share-synchronize", state="init", peer_number=peer_number)
        self._share_execute_local(self._sql_ready)

        # mark ourselves as ready
        self._share_execute_local(u"INSERT INTO ready (peer_number) VALUES (?)", (peer_number,))

        # if we are the last peer on this node we will share with the remote database
        if peer_number == high_peer_number:
            # wait until all local data is available
            self.log("scenario-share-synchronize", state="special-wait-1")
            while True:
                count, = self._share_execute_local(u"SELECT COUNT(*) FROM ready", commit=False)[0]
                if count >= high_peer_number - low_peer_number + 1:
                    break
                sleep(0.1)
                self.log("scenario-share-synchronize", state="special-wait-1", count=count, limit=high_peer_number - low_peer_number + 1)

            # ensure that the remote tables exists
            self.log("scenario-share-synchronize", state="special-init")
            self._share_execute_remote(self._sql_identities)
            self._share_execute_remote(self._sql_ready)

            # copy all local identities to the remote database
            self.log("scenario-share-synchronize", state="special-copy-1")
            self._share_execute_remote(u"INSERT INTO identities (peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                       self._share_execute_local(u"SELECT peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key FROM identities"))
            self._share_execute_remote(u"INSERT INTO ready (peer_number) VALUES (?)",
                                       self._share_execute_local(u"SELECT peer_number FROM ready"))

            # wait until all remote data is available
            self.log("scenario-share-synchronize", state="special-wait-2")
            while True:
                count, = self._share_execute_remote(u"SELECT COUNT(*) FROM ready", commit=False)[0]
                if count >= peer_count:
                    break
                sleep(0.1)
                self.log("scenario-share-synchronize", state="special-wait-2", count=count, peer_count=peer_count)

            # copy all remote identities to the local database
            self.log("scenario-share-synchronize", state="special-copy-2")
            self._share_execute_local(u"INSERT OR IGNORE INTO identities (peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                      self._share_execute_remote(u"SELECT peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key FROM identities"))
            self._share_execute_local(u"INSERT OR IGNORE INTO ready (peer_number) VALUES (?)",
                                      self._share_execute_remote(u"SELECT peer_number FROM ready"))

            self.log("scenario-share-synchronize", state="special-done")

        # wait until everyone is ready
        self.log("scenario-share-synchronize", state="wait")
        while True:
            count, = self._share_execute_local(u"SELECT COUNT(*) FROM ready", commit=False)[0]
            if count >= peer_count:
                break
            sleep(0.1)

        # copy all to a local database
        self.log("scenario-share-synchronize", state="copy")
        con_local, _ = self._share_connect_local()
        con_memory, _ = self._share_connect_memory()
        con_memory.executescript("".join(line for line in con_local.iterdump()))
        self.log("scenario-share-synchronize", state="done")

    def get_peer_from_candidate(self, candidate):
        # dependencies
        if not (0 < self._scenario_calls["scenario_start"]):
            raise RuntimeError("get_peer_from_candidate must be called AFTER scenario_start")
        if not (0 < self._scenario_calls["scenario_share_synchronize"]):
            raise RuntimeError("get_peer_from_candidate must be called AFTER scenario_share_synchronize")

        tuples = self._share_execute_memory(u"SELECT * FROM identities WHERE lan_host = ? AND lan_port = ? LIMIT 1", candidate.lan_address)
        if tuples:
            peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key = tuples[0]
            return self._share_identity_cls(peer_number, hostname, (lan_host, lan_port), (wan_host, wan_port), str(public_key), str(private_key))
        else:
            #print "get_peer_from_candidate", candidate.lan_address, tuples
            #for tup for self._share_execute_memory(u"SELECT * FROM identities"):
            #    print tup
            assert False, "could not find candidate"
            raise RuntimeError("could not find candidate")

    def get_peer_from_number(self, peer_number):
        # dependencies
        if not (0 < self._scenario_calls["scenario_start"]):
            raise RuntimeError("get_peer_from_candidate must be called AFTER scenario_start")
        if not (0 < self._scenario_calls["scenario_share_synchronize"]):
            raise RuntimeError("get_peer_from_candidate must be called AFTER scenario_share_synchronize")

        tuples = self._share_execute_memory(u"SELECT * FROM identities WHERE peer_number = ? LIMIT 1", (peer_number,))
        if tuples:
            peer_number, hostname, lan_host, lan_port, wan_host, wan_port, public_key, private_key = tuples[0]
            return self._share_identity_cls(peer_number, hostname, (lan_host, lan_port), (wan_host, wan_port), str(public_key), str(private_key))
        else:
            assert False, "could not find candidate"
            raise RuntimeError("could not find candidate")

class ScenarioDatabaseChurn(object):
    def scenario_database_churn(self, filepath, begin="0", end="0", multiplier="1.0"):
        db = sqlite3.connect(path.join(self._kargs["localcodedir"], filepath))
        cur = db.cursor()
        maxpeerid, minonline, maxonline = next(cur.execute(u"SELECT MAX(session.peer), MIN(session.online), MAX(session.online) FROM session"))

        begin = int(begin)
        end = int(end) if int(end) > 0 else maxonline
        multiplier = float(multiplier)
        peernumber = int(self._kargs["peernumber"]) % maxpeerid
        startstamp = float(self._kargs["startstamp"])

        churn = [((online - minonline - begin) * multiplier + startstamp, (offline - online - max((begin-online), 0)) * multiplier)
                 for online, offline
                 in cur.execute(u"SELECT online, offline FROM session WHERE peer = ? AND offline >= ? AND online <= ? ORDER BY online", (peernumber, begin, end))]

        if churn:
            self._dispersy.callback.register(self._database_churn_helper, (churn,))
        else:
            return "end"

    def _database_churn_helper(self, churn):
        for online, duration in churn:
            delay = max(0.0, online - time())
            logger.debug("will go online in %.2f seconds", delay)
            yield delay
            self.scenario_churn("online", duration)

            yield duration
            self.scenario_churn("offline")

class ScenarioParser1(Parser):
    """
    First phase scenario parser.

    This parser looks for log entries called scenario-init and scenario-start in multiple log files.
    Each log file results in an entry in the peer table, see below:

    CREATE TABLE peer (
     id INTEGER PRIMARY KEY,    -- number corresponding to the peer_number.  note that the first one starts at zero.
     hostname TEXT,             -- the hostname of the server running the peer
     public_key BLOB,           -- the peers' public key
     lan_host TEXT,             -- the peers' LAN IP address
     lan_port INTEGER)          -- the peers' LAN port

    Because the scenario-init and scenario-start only occur once at the beginning of the log file,
    this parser stops parsing after the scenario-start entry is parsed.
    """
    def __init__(self, database):
        super(ScenarioParser1, self).__init__()

        self.peer_id = 0
        self.db = database
        self.cur = database.cursor()
        self.cur.execute(u"""
CREATE TABLE peer (
 id INTEGER PRIMARY KEY,    -- number corresponding to the peer_number.  note that the first one starts at zero.
 hostname TEXT,             -- the hostname of the server running the peer
 public_key BLOB,           -- the peers' public key
 lan_host TEXT,             -- the peers' LAN IP address
 lan_port INTEGER)          -- the peers' LAN port
""")

        self.mapto(self.scenario_init, "scenario-init")
        self.mapto(self.scenario_start, "scenario-start")

    def scenario_init(self, timestamp, name, peernumber, hostname):
        self.peer_id = peernumber
        self.cur.execute(u"INSERT INTO peer (id, hostname) VALUES (?, ?)", (peernumber, hostname))

    def scenario_start(self, timestamp, name, my_public_key, classification, lan_address, **kargs):
        lan_host, lan_port = lan_address
        self.cur.execute(u"UPDATE peer SET public_key = ?, lan_host = ?, lan_port = ? WHERE id = ?", (buffer(my_public_key), lan_host, lan_port, self.peer_id))
        raise NextFile()

    def parse_directory(self, *args, **kargs):
        try:
            super(ScenarioParser1, self).parse_directory(*args, **kargs)
        finally:
            self.db.commit()

class ScenarioParser2(Parser):
    """
    Second phase scenario parser.

    This parser looks for log entries called scenario-{init, start, end, churn, cpu, memory,
    bandwidth, community} in multiple log files.  As log entries are parsed, the database tables
    below are filled:

    CREATE TABLE cpu (timestamp FLOAT, peer INTEGER, percentage FLOAT);
    CREATE TABLE memory (timestamp FLOAT, peer INTEGER, rss INTEGER, vms INTEGER);
    CREATE TABLE bandwidth (timestamp FLOAT, peer INTEGER, up INTEGER, down INTEGER, drop_count INTEGER, delay_count INTEGER, delay_send INTEGER, delay_success INTEGER, delay_timeout INTEGER, success_count INTEGER, received_count INTEGER);
    CREATE TABLE bandwidth_rate (timestamp FLOAT, peer INTEGER, up INTEGER, down INTEGER);
    CREATE TABLE churn (peer INTEGER, online FLOAT, offline FLOAT);
    CREATE TABLE community (timestamp FLOAT, peer INTEGER, hex_cid TEXT, classification TEXT, global_time INTEGER, sync_bloom_new INTEGER, sync_bloom_reuse INTEGER, candidate_count INTEGER);
    """
    def __init__(self, database):
        super(ScenarioParser2, self).__init__()

        self.db = database
        self.cur = database.cursor()
        self.cur.executescript(u"""
CREATE TABLE cpu (
 timestamp FLOAT,
 peer INTEGER,
 percentage FLOAT);

CREATE TABLE memory (
 timestamp FLOAT,
 peer INTEGER,
 rss INTEGER,
 vms INTEGER);

CREATE TABLE bandwidth (
 timestamp FLOAT,
 peer INTEGER,
 up INTEGER,
 down INTEGER,
 drop_count INTEGER,
 delay_count INTEGER,
 delay_send INTEGER,
 delay_success INTEGER,
 delay_timeout INTEGER,
 success_count INTEGER,
 received_count INTEGER);

CREATE TABLE bandwidth_rate (
 timestamp FLOAT,
 peer INTEGER,
 up INTEGER,
 down INTEGER);

CREATE TABLE churn (
 peer INTEGER,
 online FLOAT,
 offline FLOAT);

CREATE TABLE community (
 timestamp FLOAT,
 peer INTEGER,
 hex_cid TEXT,
 classification TEXT,
 global_time INTEGER,
 sync_bloom_new INTEGER,
 sync_bloom_reuse INTEGER,
 candidate_count INTEGER);
""")

        self.lan_address_cache = {}
        self.public_key_cache = {}
        self.mid_cache = {}
        self.hostname = ""
        self.public_key = ""
        self.mid = ""
        self.peer_id = 0

        self.online_timestamp = 0.0
        self.bandwidth_timestamp = 0
        self.bandwidth_up = 0
        self.bandwidth_down = 0

        self.io_timestamp = 0.0
        self.io_read_bytes = 0
        self.io_read_count = 0
        self.io_write_bytes = 0
        self.io_write_count = 0

        self.mapto(self.scenario_init, "scenario-init")
        self.mapto(self.scenario_start, "scenario-start")
        self.mapto(self.scenario_end, "scenario-end")
        self.mapto(self.scenario_churn, "scenario-churn")
        self.mapto(self.scenario_cpu, "scenario-cpu")
        self.mapto(self.scenario_memory, "scenario-memory")
        self.mapto(self.scenario_bandwidth, "scenario-bandwidth")
        self.mapto(self.scenario_community, "scenario-community")

    def start_parser(self, filename):
        """Called once before starting to parse FILENAME"""
        super(ScenarioParser2, self).start_parser(filename)

        self.online_timestamp = 0.0
        self.bandwidth_timestamp = 0
        self.bandwidth_up = 0
        self.bandwidth_down = 0

    def get_peer_id_from_lan_address(self, lan_address, or_create=False):
        assert isinstance(lan_address, tuple), type(lan_address)
        assert len(lan_address) == 2, len(lan_address)
        assert isinstance(lan_address[0], str), type(lan_address[0])
        assert isinstance(lan_address[1], int), type(lan_address[1])
        assert isinstance(or_create, bool), type(or_create)
        try:
            return self.lan_address_cache[lan_address]
        except KeyError:
            try:
                peer_id, = self.cur.execute(u"SELECT id FROM peer WHERE lan_host = ? AND lan_port = ?", lan_address).next()
            except StopIteration:
                self.cur.execute(u"INSERT INTO peer (lan_host, lan_port) VALUES (?, ?)", lan_address)
                peer_id = self.lan_address_cache[lan_address] = self.cur.lastrowid
                return peer_id
            else:
                if peer_id is None:
                    assert False, "all peers should be known at this point!"
                    raise ValueError(lan_address)
                else:
                    self.lan_address_cache[lan_address] = peer_id
                    return peer_id

    def get_peer_id_from_public_key(self, public_key):
        assert isinstance(public_key, str), type(public_key)
        assert len(public_key) > 20, len(public_key)
        try:
            return self.public_key_cache[public_key]
        except KeyError:
            try:
                peer_id, = self.cur.execute(u"SELECT id FROM peer WHERE public_key = ?", (buffer(public_key),)).next()
            except StopIteration:
                assert False, "all peers should be known at this point! [%s]" % (sha1(public_key).digest().encode("HEX"),)
                raise ValueError(public_key.encode("HEX"))
            else:
                if peer_id is None:
                    assert False, "all peers should be known at this point!"
                    raise ValueError(public_key.encode("HEX"))
                else:
                    self.public_key_cache[public_key] = peer_id
                    return peer_id

    def get_peer_id_from_mid(self, mid):
        assert isinstance(mid, str), type(mid)
        assert len(mid) == 20, len(mid)
        try:
            return self.mid_cache[mid]
        except KeyError:
            for peer_id, public_key in self.cur.execute(u"SELECT id, public_key FROM peer"):
                self.mid_cache[sha1(str(public_key)).digest()] = peer_id

        try:
            return self.mid_cache[mid]
        except KeyError:
            assert False, "all peers should be known at this point! [%s]" % (mid.encode("HEX"),)
            raise ValueError(mid.encode("HEX"))

    def scenario_init(self, timestamp, _, peernumber, hostname):
        self.hostname = hostname
        self.peer_id = peernumber
        self.bandwidth_timestamp = timestamp

    def scenario_start(self, timestamp, _, my_public_key, my_mid, **kargs):
        self.mid = my_mid
        self.public_key = my_public_key

    def scenario_end(self, timestamp, _):
        if self.online_timestamp:
            self.cur.execute(u"INSERT INTO churn (peer, online, offline) VALUES (?, ?, ?)", (self.peer_id, self.online_timestamp, timestamp))

    def scenario_churn(self, timestamp, _, state, **kargs):
        if state == "online":
            self.online_timestamp = timestamp

        elif state == "offline":
            assert self.online_timestamp
            self.cur.execute(u"INSERT INTO churn (peer, online, offline) VALUES (?, ?, ?)", (self.peer_id, self.online_timestamp, timestamp))
            self.online_timestamp = 0.0

    def scenario_cpu(self, timestamp, _, percentage):
        self.cur.execute(u"INSERT INTO cpu (timestamp, peer, percentage) VALUES (?, ?, ?)", (timestamp, self.peer_id, sum(percentage) / len(percentage)))

    def scenario_memory(self, timestamp, _, vms, rss):
        self.cur.execute(u"INSERT INTO memory (timestamp, peer, rss, vms) VALUES (?, ?, ?, ?)", (timestamp, self.peer_id, rss, vms))

    def scenario_bandwidth(self, timestamp, _, up, down, drop_count, delay_count, delay_send, delay_success, delay_timeout, success_count, received_count):
        self.cur.execute(u"INSERT INTO bandwidth (timestamp, peer, up, down, drop_count, delay_count, delay_send, delay_success, delay_timeout, success_count, received_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (timestamp, self.peer_id, up, down, drop_count, delay_count, delay_send, delay_success, delay_timeout, success_count, received_count))

        delta = timestamp - self.bandwidth_timestamp
        self.cur.execute(u"INSERT INTO bandwidth_rate (timestamp, peer, up, down) VALUES (?, ?, ?, ?)",
                         (timestamp, self.peer_id, (up-self.bandwidth_up)/delta, (down-self.bandwidth_down)/delta))
        self.bandwidth_timestamp = timestamp
        self.bandwidth_up = up
        self.bandwidth_down = down

    def scenario_community(self, timestamp, _, hex_cid, classification, global_time, sync_bloom_new, sync_bloom_reuse, candidates):
        self.cur.execute(u"INSERT INTO community (timestamp, peer, hex_cid, classification, global_time, sync_bloom_new, sync_bloom_reuse, candidate_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (timestamp, self.peer_id, hex_cid, classification, global_time, sync_bloom_new, sync_bloom_reuse, len(candidates)))

    def parse_directory(self, *args, **kargs):
        try:
            super(ScenarioParser2, self).parse_directory(*args, **kargs)
        finally:
            self.db.commit()
