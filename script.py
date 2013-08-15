import logging
logger = logging.getLogger(__name__)

from abc import ABCMeta, abstractmethod
from time import time

from .tests.debugcommunity.community import DebugCommunity
from .dispersy import Dispersy
from .tool.lencoder import log, make_valid_key


def assert_(value, *args):
    if not value:
        raise AssertionError(*args)


class ScriptBase(object):

    __metaclass__ = ABCMeta

    def __init__(self, dispersy, **kargs):
        assert isinstance(dispersy, Dispersy), type(dispersy)
        super(ScriptBase, self).__init__()
        self._kargs = kargs
        self._testcases = []
        self._dispersy = dispersy
        self._dispersy_database = self._dispersy.database
        # self._dispersy.callback.register(self.run)
        if self.enable_wait_for_wan_address:
            self.add_testcase(self.wait_for_wan_address)

        self.run()

    def add_testcase(self, func, args=()):
        assert callable(func)
        assert isinstance(args, tuple)
        self._testcases.append((func, args))

    def next_testcase(self, result=None):
        if isinstance(result, Exception):
            logger.error("exception! shutdown")
            self._dispersy.callback.stop(timeout=0.0, exception=result)

        elif self._testcases:
            call, args = self._testcases.pop(0)
            logger.info("start %s", call)
            if args:
                logger.info("arguments %s", args)
            if call.__doc__:
                logger.info(call.__doc__)
            self._dispersy.callback.register(call, args, callback=self.next_testcase)

        else:
            logger.debug("shutdown")
            self._dispersy.callback.stop(timeout=0.0)

    def caller(self, run, args=()):
        assert callable(run)
        assert isinstance(args, tuple)
        logger.warning("depricated: use add_testcase instead")
        return self.add_testcase(run, args)

    @abstractmethod
    def run(self):
        pass

    @property
    def enable_wait_for_wan_address(self):
        return True

    def wait_for_wan_address(self):
        my_member = self._dispersy.get_new_member(u"low")
        community = DebugCommunity.create_community(self._dispersy, my_member)

        while self._dispersy.wan_address[0] == "0.0.0.0":
            yield 0.1

        community.unload_community()


class ScenarioScriptBase(ScriptBase):
    # TODO: all bartercast references should be converted to some universal style

    def __init__(self, dispersy, logfile, **kargs):
        ScriptBase.__init__(self, dispersy, **kargs)

        self._timestep = float(kargs.get('timestep', 1.0))
        self._stepcount = 0
        self._logfile = logfile

        self._my_name = None
        self._my_address = None

        self._nr_peers = self.__get_nr_peers()

        if 'starting_timestamp' in kargs:
            self._starting_timestamp = int(kargs['starting_timestamp'])
            log(self._logfile, "Using %d as starting timestamp, will wait for %d seconds" % (self._starting_timestamp, self._starting_timestamp - int(time())))
        else:
            self._starting_timestamp = int(time())
            log(self._logfile, "No starting_timestamp specified, using currentime")

    @property
    def enable_wait_for_wan_address(self):
        return False

    def get_peer_ip_port(self, peer_id):
        assert isinstance(peer_id, int), type(peer_id)

        line_nr = 1
        for line in open('data/peers'):
            if line_nr == peer_id:
                ip, port = line.split()
                return ip, int(port)
            line_nr += 1

    def __get_nr_peers(self):
        line_nr = 0
        for line in open('data/peers'):
            line_nr += 1

        return line_nr

    def set_online(self):
        """ Restore on_socket_endpoint and _send functions of
        dispersy back to normal.

        This simulates a node coming online, since it's able to send
        and receive messages.
        """
        log(self._logfile, "Going online")
        self._dispersy.on_incoming_packets = self.original_on_incoming_packets
        self._dispersy.endpoint.send = self.original_send

    def set_offline(self):
        """ Replace on_socket_endpoint and _sends functions of
        dispersy with dummies

        This simulates a node going offline, since it's not able to
        send or receive any messages
        """
        def dummy_on_socket(*params):
            return

        def dummy_send(*params):
            return False

        log(self._logfile, "Going offline")
        self._dispersy.on_socket_endpoint = dummy_on_socket
        self._dispersy.endpoint.send = dummy_send

    def get_commands_from_fp(self, fp, step):
        """ Return a list of commands from file handle for step

        Read lines from fp and return all the lines starting at
        timestamp equal to step. If we read the end of the file,
        without commands to return, then I return -1.
        """
        commands = []
        if fp:
            while True:
                cursor_position = fp.tell()
                line = fp.readline().strip()
                if not line:
                    if commands:
                        return commands
                    else:
                        return -1

                cmdstep, command = line.split(' ', 1)

                cmdstep = int(cmdstep)
                if cmdstep < step:
                    continue
                elif cmdstep == step:
                    commands.append(command)
                else:
                    # restore cursor position and break
                    fp.seek(cursor_position)
                    break

        return commands

    def sleep(self):
        """ Calculate the time to sleep.
        """
        # when should we start the next step?
        expected_time = self._starting_timestamp + (self._timestep * (self._stepcount + 1))
        diff = expected_time - time()

        delay = max(0.0, diff)
        return delay

    def log_desync(self, desync):
        log(self._logfile, "sleep", desync=desync, stepcount=self._stepcount)

    @abstractmethod
    def join_community(self, my_member):
        pass

    @abstractmethod
    def execute_scenario_cmds(self, commands):
        pass

    def run(self):
        self.add_testcase(self._run)

    def _run(self):
        if __debug__:
            log(self._logfile, "start-scenario-script")

        #
        # Read our configuration from the peer.conf file
        # name, ip, port, public and private key
        #
        with open('data/peer.conf') as fp:
            self._my_name, ip, port, _ = fp.readline().split()
            self._my_address = (ip, int(port))

        log(self._logfile, "Read config done", my_name=self._my_name, my_address=self._my_address)

        # create my member
        my_member = self._dispersy.get_new_member(u"low")
        logger.info("-my member- %d %d %s", my_member.database_id, id(my_member), my_member.mid.encode("HEX"))

        self.original_on_incoming_packets = self._dispersy.on_incoming_packets
        self.original_send = self._dispersy.endpoint.send

        # join the community with the newly created member
        self._community = self.join_community(my_member)
        logger.debug("Joined community %s", self._community._my_member)

        log("dispersy.log", "joined-community", time=time(), timestep=self._timestep, sync_response_limit=self._community.dispersy_sync_response_limit, starting_timestamp=self._starting_timestamp)

        self._stepcount = 0

        # wait until we reach the starting time
        self._dispersy.callback.register(self.do_steps, delay=self.sleep())
        self._dispersy.callback.register(self.do_log)

        # I finished the scenario execution. I should stay online
        # until killed. Note that I can still sync and exchange
        # messages with other peers.
        while True:
            # wait to be killed
            yield 100.0

    def do_steps(self):
        self._dispersy._statistics.reset()
        scenario_fp = open('data/bartercast.log')
        try:
            availability_fp = open('data/availability.log')
        except:
            availability_fp = None

        self._stepcount += 1

        # start the scenario
        while True:
            # get commands
            scenario_cmds = self.get_commands_from_fp(scenario_fp, self._stepcount)
            availability_cmds = self.get_commands_from_fp(availability_fp, self._stepcount)

            # if there is a start in the avaibility_cmds then go
            # online
            if availability_cmds != -1 and 'start' in availability_cmds:
                self.set_online()

            # if there are barter_cmds then execute them
            if scenario_cmds != -1:
                self.execute_scenario_cmds(scenario_cmds)

            # if there is a stop in the availability_cmds then go offline
            if availability_cmds != -1 and 'stop' in availability_cmds:
                self.set_offline()

            sleep = self.sleep()
            if sleep < 0.5:
                self.log_desync(1.0 - sleep)
            yield sleep
            self._stepcount += 1

    def do_log(self):
        def print_on_change(name, prev_dict, cur_dict):
            new_values = {}
            changed_values = {}
            if cur_dict:
                for key, value in cur_dict.iteritems():
                    if not isinstance(key, (basestring, int, long)):
                        key = str(key)

                    key = make_valid_key(key)
                    new_values[key] = value
                    if prev_dict.get(key, None) != value:
                        changed_values[key] = value

            if changed_values:
                log("dispersy.log", name, **changed_values)
                return new_values
            return prev_dict

        prev_statistics = {}
        prev_total_received = {}
        prev_total_dropped = {}
        prev_total_delayed = {}
        prev_total_outgoing = {}
        prev_total_fail = {}
        prev_endpoint_recv = {}
        prev_endpoint_send = {}
        prev_created_messages = {}
        prev_bootstrap_candidates = {}

        while True:
            # print statistics
            self._dispersy.statistics.update()

            bloom = [(c.classification, c.sync_bloom_reuse, c.sync_bloom_skip) for c in self._dispersy.statistics.communities]
            candidates = [(c.classification, len(c.candidates) if c.candidates else 0) for c in self._dispersy.statistics.communities]
            statistics_dict = {'received_count': self._dispersy.statistics.received_count,
                               'total_up': self._dispersy.statistics.total_up,
                               'total_down': self._dispersy.statistics.total_down,
                               'drop_count': self._dispersy.statistics.drop_count,
                              'total_send': self._dispersy.statistics.total_send,
                              'cur_sendqueue': self._dispersy.statistics.cur_sendqueue,
                              'delay_count': self._dispersy.statistics.delay_count,
                              'delay_success': self._dispersy.statistics.delay_success,
                              'delay_timeout': self._dispersy.statistics.delay_timeout,
                              'walk_attempt': self._dispersy.statistics.walk_attempt,
                              'walk_success': self._dispersy.statistics.walk_success,
                              'walk_reset': self._dispersy.statistics.walk_reset,
                              'conn_type': self._dispersy.statistics.connection_type,
                              'bloom': bloom,
                              'candidates': candidates}

            prev_statistics = print_on_change("statistics", prev_statistics, statistics_dict)
            prev_total_received = print_on_change("statistics-successful-messages", prev_total_received, self._dispersy.statistics.success)
            prev_total_dropped = print_on_change("statistics-dropped-messages", prev_total_dropped, self._dispersy.statistics.drop)
            prev_total_delayed = print_on_change("statistics-delayed-messages", prev_total_delayed, self._dispersy.statistics.delay)
            prev_total_outgoing = print_on_change("statistics-outgoing-messages", prev_total_outgoing, self._dispersy.statistics.outgoing)
            prev_total_fail = print_on_change("statistics-walk-fail", prev_total_fail, self._dispersy.statistics.walk_fail)
            prev_endpoint_recv = print_on_change("statistics-endpoint-recv", prev_endpoint_recv, self._dispersy.statistics.endpoint_recv)
            prev_endpoint_send = print_on_change("statistics-endpoint-send", prev_endpoint_send, self._dispersy.statistics.endpoint_send)
            prev_created_messages = print_on_change("statistics-created-messages", prev_created_messages, self._dispersy.statistics.created)
            prev_bootstrap_candidates = print_on_change("statistics-bootstrap-candidates", prev_bootstrap_candidates, self._dispersy.statistics.bootstrap_candidates)

#            def callback_cmp(a, b):
#                return cmp(self._dispersy.callback._statistics[a][0], self._dispersy.callback._statistics[b][0])
#            keys = self._dispersy.callback._statistics.keys()
#            keys.sort(reverse = True)
#
#            total_run = {}
#            for key in keys[:10]:
#                total_run[make_valid_key(key)] = self._dispersy.callback._statistics[key]
#            if len(total_run) > 0:
#                log("dispersy.log", "statistics-callback-run", **total_run)

#            stats = Conversion.debug_stats
#            total = stats["encode-message"]
#            nice_total = {'encoded':stats["-encode-count"], 'total':"%.2fs"%total}
#            for key, value in sorted(stats.iteritems()):
#                if key.startswith("encode") and not key == "encode-message" and total:
#                    nice_total[make_valid_key(key)] = "%7.2fs ~%5.1f%%" % (value, 100.0 * value / total)
#            log("dispersy.log", "statistics-encode", **nice_total)
#
#            total = stats["decode-message"]
#            nice_total = {'decoded':stats["-decode-count"], 'total':"%.2fs"%total}
#            for key, value in sorted(stats.iteritems()):
#                if key.startswith("decode") and not key == "decode-message" and total:
#                    nice_total[make_valid_key(key)] = "%7.2fs ~%5.1f%%" % (value, 100.0 * value / total)
#            log("dispersy.log", "statistics-decode", **nice_total)

            yield 1.0
