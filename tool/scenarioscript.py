try:
    from scipy.stats import poisson, expon
except ImportError:
    poisson = expon = None
    print "Unable to import scipy.  ScenarioPoisson and ScenarioExpon are disabled"

from os import getpid, uname
from psutil import Process, cpu_percent
from random import random, uniform
from re import compile as re_compile
from sys import maxsize
from time import time

from ..crypto import ec_generate_key, ec_to_public_bin, ec_to_private_bin
from ..dprint import dprint
from ..member import Member
from ..script import ScriptBase

class ScenarioScript(ScriptBase):
    def __init__(self, *args, **kargs):
        super(ScenarioScript, self).__init__(*args, **kargs)
        self._master_member = None
        self._community = None
        self._process = Process(getpid()) if self.enable_cpu_statistics or self.enable_memory_statistics else None

        if self.enable_cpu_statistics:
            self._dispersy.callback.register(self._periodically_log_cpu_statistics)

        if self.enable_memory_statistics:
            self._dispersy.callback.register(self._periodically_log_memory_statistics)

        if self.enable_bandwidth_statistics:
            self._dispersy.callback.register(self._periodically_log_bandwidth_statistics)

    @property
    def enable_wait_for_wan_address(self):
        return False

    @property
    def enable_cpu_statistics(self):
        return 5.0

    @property
    def enable_memory_statistics(self):
        return 5.0

    @property
    def enable_bandwidth_statistics(self):
        return 5.0

    def run(self):
        self.add_testcase(self._run_scenario)

    def _run_scenario(self):
        for deadline, _, call, args in self.parse_scenario():
            while True:
                remaining = deadline - time()
                if remaining > 0.1:
                    yield min(10.0, remaining)

                else:
                    if __debug__: dprint(call.__name__)
                    if call(*args) == "END":
                        return
                    break

    @property
    def my_member_security(self):
        return u"low"

    @property
    def master_member_public_key(self):
        raise NotImplementedError("must return an experiment specific master member public key")
            # if False:
            #     # when crypto.py is disabled a public key is slightly
            #     # different...
            #     master_public_key = ";".join(("60", master_public_key[:60].encode("HEX"), ""))
        # return "3081a7301006072a8648ce3d020106052b81040027038192000404668ed626c6d6bf4a280cf4824c8cd31fe4c7c46767afb127129abfccdf8be3c38d4b1cb8792f66ccb603bfed395e908786049cb64bacab198ef07d49358da490fbc41f43ade33e05c9991a1bb7ef122cda5359d908514b3c935fe17a3679b6626161ca8d8d934d372dec23cc30ff576bfcd9c292f188af4142594ccc5f6376e2986e1521dc874819f7bcb7ae3ce400".decode("HEX")

    @property
    def community_class(self):
        raise NotImplementedError("must return an experiment community class")

    @property
    def community_args(self):
        return ()

    @property
    def community_kargs(self):
        return {}

    def log(self, _message, **kargs):
        pass

    def _periodically_log_cpu_statistics(self):
        hostname = uname()[1]
        while True:
            self.log("scenario-cpu", hostname=hostname, percentage=cpu_percent(interval=0, percpu=True))
            yield self.enable_cpu_statistics

    def _periodically_log_memory_statistics(self):
        while True:
            rss, vms = self._process.get_memory_info()
            self.log("scenario-memory", rss=rss, vms=vms)
            yield self.enable_memory_statistics

    def _periodically_log_bandwidth_statistics(self):
        while True:
            up, down = self._dispersy.endpoint.total_up, self._dispersy.endpoint.total_down
            self.log("scenario-bandwidth", up=up, down=down)
            yield self.enable_bandwidth_statistics

    def _periodically_log_io_statistics(self):
        while True:
            read_count, write_count, read_bytes, write_bytes = self._process.get_io_counters()
            self.log("scenario-io", read_count=read_count, write_count=write_count, read_bytes=read_bytes, write_bytes=write_bytes)
            yield self.enable_io_statistics

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
                                      "(?:\s*{(?P<peers>\s*\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*\s*)})?",
                                      "\s*(?:\n)?$")))
        peernumber = int(self._kargs["peernumber"])
        filename = self._kargs["scenario"]
        origin = {"@":float(self._kargs["startstamp"]) if "startstamp" in self._kargs else time(),
                  "+":time()}

        for lineno, line in enumerate(open(filename, "r")):
            match = re_line.match(line)
            if match:
                # remove all entries that are None (allows us to get default per key)
                dic = dict((key, value) for key, value in match.groupdict().iteritems() if not value is None)

                # get the peers, if any, for which this line applies
                peers = set()
                for peer in dic.get("peers", "").split(","):
                    peer = peer.strip()
                    if peer:
                        if "-" in peer:
                            low, high = peer.split("-")
                            peers.update(xrange(int(low), int(high)+1))
                        else:
                            peers.add(int(peer))

                if not peers or peernumber in peers:
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
            if __debug__: dprint("scenario: @", int(deadline - origin["@"]), "s ", func.__name__)
            self.log("scenario-schedule", deadline=int(deadline - origin["@"]), func=func.__name__, args=args)

        return scenario

    def scenario_start(self):
        assert self._community is None
        ec = ec_generate_key(self.my_member_security)
        my_member = Member(ec_to_public_bin(ec), ec_to_private_bin(ec))
        self._master_member = Member(self.master_member_public_key)
        if __debug__: dprint("join community ", self._master_member.mid.encode("HEX"), " as ", my_member.mid.encode("HEX"))
        self.log("scenario-start", my_member=my_member.mid, master_member=self._master_member.mid, classification=self.community_class.get_classification())
        self._community = self.community_class.join_community(self._master_member, my_member, *self.community_args, **self.community_kargs)
        self._community.auto_load = False

    def scenario_end(self):
        if __debug__: dprint("END")
        self.log("scenario-end")
        return "END"

    def scenario_print(self, *args):
        dprint(*args, glue=" ", force=True)

if poisson:
    class ScenarioPoisson(object):
        def __init__(self, *args, **kargs):
            self.__poisson_online_mu = 0.0
            self.__poisson_offline_mu = 0.0

        def __poisson_churn(self):
            while True:
                delay = poisson.rvs(self.__poisson_online_mu)
                if self._community is None:
                    if __debug__: dprint("poisson wants us online for the next ", delay, " seconds")
                    self.log("scenario-poisson", state="online", duration=delay)
                    self._community = self.community_class.load_community(self._master_member, *self.community_args, **self.community_kargs)
                else:
                    if __debug__: dprint("poisson wants us online for the next ", delay, " seconds (we are already online)")
                    self.log("scenario-poisson", state="stay-online", duration=delay)
                yield float(delay)

                delay = poisson.rvs(self.__poisson_offline_mu)
                if self._community is None:
                    if __debug__: dprint("poisson wants us offline for the next ", delay, " seconds (we are already offline)")
                    self.log("scenario-poisson", state="stay-offline", duration=delay)
                else:
                    if __debug__: dprint("poisson wants us offline for the next ", delay, " seconds")
                    self.log("scenario-poisson", state="offline", duration=delay)
                    self._community.unload_community()
                    self._community = None
                yield float(delay)

        def scenario_poisson_churn(self, online_mu, offline_mu):
            self.__poisson_online_mu = float(online_mu)
            self.__poisson_offline_mu = float(offline_mu)
            self._dispersy.callback.persistent_register("scenario-poisson-identifier", self.__poisson_churn)

if expon:
    class ScenarioExpon(object):
        def __init__(self, *args, **kargs):
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
                    delay = min(self.__expon_max_online, max(self.__expon_min_online, delay))
                    if self._community is None:
                        if __debug__: dprint("expon wants us online for the next ", delay, " seconds")
                        self.log("scenario-expon", state="online", duration=delay)
                        self._community = self.community_class.load_community(self._master_member, *self.community_args, **self.community_kargs)
                    else:
                        if __debug__: dprint("expon wants us online for the next ", delay, " seconds (we are already online)")
                        self.log("scenario-expon", state="stay-online", duration=delay)
                    yield float(delay)

                delay = expon.rvs(scale=self.__expon_offline_beta)
                if delay >= self.__expon_offline_threshold:
                    delay = min(self.__expon_max_offline, max(self.__expon_min_offline, delay))
                    if self._community is None:
                        if __debug__: dprint("expon wants us offline for the next ", delay, " seconds (we are already offline)")
                        self.log("scenario-expon", state="stay-offline", duration=delay)
                    else:
                        if __debug__: dprint("expon wants us offline for the next ", delay, " seconds")
                        self.log("scenario-expon", state="offline", duration=delay)
                        self._community.unload_community()
                        self._community = None
                    yield float(delay)

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
            self._dispersy.callback.persistent_register("scenario-expon-identifier", self.__expon_churn)

class ScenarioUniform(object):
    def __init__(self, *args, **kargs):
        self.__uniform_online_low = 0.0
        self.__uniform_online_high = 0.0
        self.__uniform_offline_low = 0.0
        self.__uniform_offline_high = 0.0

    def __uniform_churn(self):
        while True:
            delay = uniform(self.__uniform_online_low, self.__uniform_online_high)
            if self._community is None:
                if __debug__: dprint("uniform wants us online for the next ", delay, " seconds")
                self.log("scenario-uniform", state="online", duration=delay)
                self._community = self.community_class.load_community(self._master_member, *self.community_args, **self.community_kargs)
            else:
                if __debug__: dprint("uniform wants us online for the next ", delay, " seconds (we are already online)")
                self.log("scenario-uniform", state="stay-online", duration=delay)
            yield float(delay)

            delay = uniform(self.__uniform_offline_low, self.__uniform_offline_high)
            if self._community is None:
                if __debug__: dprint("uniform wants us offline for the next ", delay, " seconds (we are already offline)")
                self.log("scenario-uniform", state="stay-offline", duration=delay)
            else:
                if __debug__: dprint("uniform wants us offline for the next ", delay, " seconds")
                self.log("scenario-uniform", state="offline", duration=delay)
                self._community.unload_community()
                self._community = None
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
        self._dispersy.callback.persistent_register("scenario-uniform-identifier", self.__uniform_churn)

class ScenarioChurn(object):
    def scenario_online(self, chance):
        if self._community is None:
            chance = float(chance) / 100.0
            if random() < chance:
                if __debug__: dprint("going back online")
                self.log("scenario-churn", state="online", chance=chance)
                self._community = self.community_class.load_community(self._master_member, *self.community_args, **self.community_kargs)

    def scenario_offline(self, chance):
        if not self._community is None:
            assert not self._community.auto_load
            chance = float(chance) / 100.0
            if random() < chance:
                if __debug__: dprint("going offline (", chance, ")")
                self.log("scenario-churn", state="offline", chance=chance)
                self._community.unload_community()
                self._community = None
