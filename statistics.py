from abc import ABCMeta, abstractmethod
from collections import defaultdict
from threading import RLock
from time import time

from .util import _runtime_statistics


class Statistics(object):

    __metaclass__ = ABCMeta

    def __init__(self):
        self._lock = RLock()

    def dict_inc(self, dictionary, key, value=1):
        if dictionary != None:
            with self._lock:
                dictionary[key] += value

    def get_dict(self):
        """
        Returns a deep clone of SELF as a dictionary.

        Warning: there is no recursion protection, if SELF contains self-references it will hang.
        """
        def clone(o):
            if isinstance(o, Statistics):
                return dict((key, clone(value))
                            for key, value
                            in o.__dict__.items()
                            if not key.startswith("_"))

            if isinstance(o, dict):
                return dict((clone(key), clone(value))
                            for key, value
                            in o.items())

            if isinstance(o, tuple):
                return tuple(clone(value) for value in o)

            if isinstance(o, list):
                return [clone(value) for value in o]

            return o
        return clone(self)

    @abstractmethod
    def update(self):
        pass

class DispersyStatistics(Statistics):

    def __init__(self, dispersy):
        super(DispersyStatistics, self).__init__()
        self._dispersy = dispersy

        self.communities = None
        self.connection_type = None
        self.database_version = dispersy.database.database_version
        self.lan_address = None
        self.start = self.timestamp = time()

        # nr packets received
        self.received_count = 0

        # nr messages successfully handled
        self.success_count = 0

        # nr messages which were received, but dropped
        self.drop_count = 0

        # nr messages which were received, but delayed
        self.delay_count = 0
        # nr delay messages being send
        self.delay_send = 0
        # nr delay messages which timed-out
        self.delay_timeout = 0
        # nr delay success
        self.delay_success = 0

        # nr sync messages created by this peer send using _send method
        self.created_count = 0

        # nr of bytes up/down and packets send as reported by endpoint
        self.total_down = 0
        self.total_up = 0
        self.total_send = 0

        # size of the sendqueue
        self.cur_sendqueue = 0

        # nr of candidates introduced/stumbled upon
        self.total_candidates_discovered = 0

        self.walk_attempt = 0
        self.walk_success = 0
        self.walk_bootstrap_attempt = 0
        self.walk_bootstrap_success = 0
        self.walk_invalid_response_identifier = 0

        self.wan_address = None

        # list with {count=int, duration=float, average=float, entry=str} dictionaries.  each entry
        # represents a key from the attach_runtime_statistics decorator
        self.runtime = None

        self.update()

        self.enable_debug_statistics(__debug__)

    def enable_debug_statistics(self, enable):
        if self.are_debug_statistics_enabled() != enable or not hasattr(self, 'drop'):
            if enable:
                self.drop = defaultdict(int)
                self.delay = defaultdict(int)
                self.success = defaultdict(int)
                self.outgoing = defaultdict(int)
                self.created = defaultdict(int)
                self.walk_fail = defaultdict(int)
                self.attachment = defaultdict(int)
                self.database = defaultdict(int)
                self.endpoint_recv = defaultdict(int)
                self.endpoint_send = defaultdict(int)
                self.bootstrap_candidates = defaultdict(int)

                # SOURCE:INTRODUCED:COUNT nested dictionary
                self.received_introductions = defaultdict(lambda: defaultdict(int))

                # DESTINATION:COUNT dictionary
                self.outgoing_introduction_request = defaultdict(int)

                # SOURCE:COUNT dictionary
                self.incoming_introduction_response = defaultdict(int)

            else:
                self.drop = None
                self.delay = None
                self.success = None
                self.created = None
                self.outgoing = None
                self.walk_fail = None
                self.attachment = None
                self.database = None
                self.endpoint_recv = None
                self.endpoint_send = None
                self.bootstrap_candidates = None
                self.received_introductions = None
                self.outgoing_introduction_request = None
                self.incoming_introduction_response = None

    def are_debug_statistics_enabled(self):
        return getattr(self, 'drop', None) != None

    def update(self, database=False):
        self.timestamp = time()
        self.connection_type = self._dispersy.connection_type
        self.lan_address = self._dispersy.lan_address
        self.wan_address = self._dispersy.wan_address

        self.total_down = self._dispersy.endpoint.total_down
        self.total_up = self._dispersy.endpoint.total_up
        self.total_send = self._dispersy.endpoint.total_send
        self.cur_sendqueue = self._dispersy.endpoint.cur_sendqueue

        self.communities = [community.statistics for community in self._dispersy.get_communities()]
        for community in self.communities:
            community.update(database=database)

        # list with {count=int, duration=float, average=float, entry=str} dictionaries.  each entry
        # represents a key from the attach_runtime_statistics decorator
        self.runtime = [statistic.get_dict(entry=entry) for entry, statistic in _runtime_statistics.iteritems()]

    def reset(self):
        self.success_count = 0
        self.drop_count = 0
        self.delay_count = 0
        self.delay_send = 0
        self.delay_success = 0
        self.delay_timeout = 0
        self.received_count = 0
        self.created_count = 0

        self._dispersy.endpoint.reset_statistics()
        self.total_down = self._dispersy.endpoint.total_down
        self.total_up = self._dispersy.endpoint.total_up
        self.total_send = self._dispersy.endpoint.total_send
        self.cur_sendqueue = self._dispersy.endpoint.cur_sendqueue
        self.start = self.timestamp = time()

        self.walk_attempt = 0
        self.walk_success = 0
        self.walk_bootstrap_attempt = 0
        self.walk_bootstrap_success = 0

        if self.are_debug_statistics_enabled():
            self.drop = defaultdict(int)
            self.delay = defaultdict(int)
            self.success = defaultdict(int)
            self.outgoing = defaultdict(int)
            self.created = defaultdict(int)
            self.walk_fail = defaultdict(int)
            self.attachment = defaultdict(int)
            self.database = defaultdict(int)
            self.endpoint_recv = defaultdict(int)
            self.endpoint_send = defaultdict(int)
            self.bootstrap_candidates = defaultdict(int)
            self.received_introductions = defaultdict(lambda: defaultdict(int))
            self.outgoing_introduction_request = defaultdict(int)
            self.incoming_introduction_response = defaultdict(int)


class CommunityStatistics(Statistics):

    def __init__(self, community):
        super(CommunityStatistics, self).__init__()

        self._community = community
        self.acceptable_global_time = None
        self.candidates = None
        self.cid = community.cid
        self.classification = community.get_classification()
        self.database = dict()
        self.database_id = community.database_id
        self.dispersy_acceptable_global_time_range = None
        self.dispersy_enable_candidate_walker = None
        self.dispersy_enable_candidate_walker_responses = None
        self.global_time = None
        self.hex_cid = community.cid.encode("HEX")
        self.hex_mid = community.my_member.mid.encode("HEX")
        self.mid = community.my_member.mid
        self.sync_bloom_new = 0
        self.sync_bloom_reuse = 0
        self.sync_bloom_send = 0
        self.sync_bloom_skip = 0
        self.update()

    def update(self, database=False):
        self.acceptable_global_time = self._community.acceptable_global_time
        self.dispersy_acceptable_global_time_range = self._community.dispersy_acceptable_global_time_range
        self.dispersy_enable_candidate_walker = self._community.dispersy_enable_candidate_walker
        self.dispersy_enable_candidate_walker_responses = self._community.dispersy_enable_candidate_walker_responses
        self.global_time = self._community.global_time
        now = time()
        self.candidates = [(candidate.lan_address, candidate.wan_address, candidate.global_time)
                           for candidate
                           in self._community.candidates.itervalues() if candidate.get_category(now) in [u'walk', u'stumble', u'intro']]
        if database:
            self.database = dict(self._community.dispersy.database.execute(u"SELECT meta_message.name, COUNT(sync.id) FROM sync JOIN meta_message ON meta_message.id = sync.meta_message WHERE sync.community = ? GROUP BY sync.meta_message", (self._community.database_id,)))
        else:
            self.database = dict()
