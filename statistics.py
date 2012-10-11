from time import time

from .revision import update_revision_information, get_revision_information

# update version information directly from SVN
update_revision_information("$HeadURL: https://svn.tribler.org/dispersy/branches/20120612-27046-mainbranch/dispersy.py $", "$Revision: 28434 $")

class Statistics():
    @staticmethod
    def dict_inc(dictionary, key, value=1L):
        try:
            dictionary[key] += value
        except KeyError:
            dictionary[key] = value

    def update(self):
        raise NotImplementedError()

class DispersyStatistics(Statistics):
    def __init__(self, dispersy):
        self._dispersy = dispersy

        self.communities = None
        self.connection_type = None
        self.database_version = dispersy.database.database_version
        self.lan_address = None
        self.revision = get_revision_information()
        self.start = self.timestamp = time()
        self.drop_count = 0
        self.delay_count = 0
        self.delay_send = 0
        self.delay_succes = 0
        self.delay_timeout = 0
        self.success_count = 0
        self.received_count = 0
        self.timestamp = None
        self.total_down = None
        self.total_up = None
        self.walk_attempt = 0
        self.walk_reset = 0
        self.walk_success = 0
        self.wan_address = None
        self.update()

        if __debug__:
            self.drop = {}
            self.delay = {}
            self.success = {}
            self.outgoing = {}
            self.walk_fail = {}
            self.attachment = {}

    def update(self, database=False):
        self.communities = [community.statistics for community in self._dispersy.get_communities()]
        self.connection_type = self._dispersy.connection_type
        self.lan_address = self._dispersy.lan_address
        self.timestamp = time()
        self.total_down = self._dispersy.endpoint.total_down
        self.total_up = self._dispersy.endpoint.total_up
        self.wan_address = self._dispersy.wan_address
        for community in self.communities:
            community.update(database=database)

    def reset(self):
        self.success_count = 0
        self.drop_count = 0
        self.delay_count = 0
        self.delay_send = 0
        self.delay_succes = 0
        self.delay_timeout = 0
        self.received_count = 0

        self._dispersy.endpoint.reset_statistics()
        self.total_down = self._dispersy.endpoint.total_down
        self.total_up = self._dispersy.endpoint.total_up

        self.walk_attempt = 0
        self.walk_reset = 0
        self.walk_success = 0

        if __debug__:
            self.drop = {}
            self.delay = {}
            self.success = {}
            self.outgoing = {}
            self.walk_fail = {}
            self.attachment = {}

class CommunityStatistics(Statistics):
    def __init__(self, community):
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
        self.update()

    def update(self, database=False):
        self.acceptable_global_time = self._community.acceptable_global_time
        self.dispersy_acceptable_global_time_range = self._community.dispersy_acceptable_global_time_range
        self.dispersy_enable_candidate_walker = self._community.dispersy_enable_candidate_walker
        self.dispersy_enable_candidate_walker_responses = self._community.dispersy_enable_candidate_walker_responses
        self.global_time = self._community.global_time
        self.candidates = [(candidate.lan_address, candidate.wan_address, candidate.get_global_time(self._community))
                           for candidate
                           in self._community.dispersy_yield_candidates()]
        if database:
            self.database = dict(self._community.dispersy.database.execute(u"SELECT meta_message.name, COUNT(sync.id) FROM sync JOIN meta_message ON meta_message.id = sync.meta_message WHERE sync.community = ? GROUP BY sync.meta_message", (self._community.database_id,)))
