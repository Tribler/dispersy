"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from abc import ABCMeta, abstractmethod
from collections import defaultdict, OrderedDict
from itertools import islice, groupby
import logging
from math import ceil
from random import random, Random, randint, shuffle, uniform
from time import time

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import LoopingCall, deferLater
from twisted.python.threadable import isInIOThread

from .authentication import NoAuthentication, MemberAuthentication, DoubleMemberAuthentication
from .bloomfilter import BloomFilter
from .candidate import Candidate, WalkCandidate
from .conversion import BinaryConversion, DefaultConversion, Conversion
from .destination import CommunityDestination, CandidateDestination, NHopCommunityDestination
from .distribution import (SyncDistribution, GlobalTimePruning, LastSyncDistribution, DirectDistribution,
                           FullSyncDistribution)
from .exception import ConversionNotFoundException, MetaNotFoundException
from .member import DummyMember, Member
from .message import (BatchConfiguration, Message, Packet, DropMessage, DelayMessageByProof,
                      DelayMessageByMissingMessage, DropPacket, DelayPacket, DelayMessage)
from .payload import (AuthorizePayload, RevokePayload, UndoPayload, DestroyCommunityPayload, DynamicSettingsPayload,
                      IdentityPayload, MissingIdentityPayload, IntroductionRequestPayload, IntroductionResponsePayload,
                      PunctureRequestPayload, PuncturePayload, MissingMessagePayload, MissingSequencePayload,
                      MissingProofPayload, SignatureRequestPayload, SignatureResponsePayload)
from .requestcache import RequestCache, SignatureRequestCache, IntroductionRequestCache
from .resolution import PublicResolution, LinearResolution, DynamicResolution
from .statistics import CommunityStatistics
from .taskmanager import TaskManager
from .timeline import Timeline
from .util import runtime_duration_warning, attach_runtime_statistics, deprecated, is_valid_address


DOWNLOAD_MM_PK_INTERVAL = 15.0
FAST_WALKER_CANDIDATE_TARGET = 15
FAST_WALKER_MAX_NEW_ELIGIBLE_CANDIDATES = 10
FAST_WALKER_STEPS = 15
FAST_WALKER_STEP_INTERVAL = 2.0
PERIODIC_CLEANUP_INTERVAL = 5.0
TAKE_STEP_INTERVAL = 5

logger = logging.getLogger(__name__)


class SyncCache(object):

    def __init__(self, time_low, time_high, modulo, offset, bloom_filter):
        self.time_low = time_low
        self.time_high = time_high
        self.modulo = modulo
        self.offset = offset
        self.bloom_filter = bloom_filter
        self.times_used = 0
        self.responses_received = 0
        self.candidate = None


class DispersyInternalMessage(object):
    pass


class DispersyDuplicatedUndo(DispersyInternalMessage):
    name = candidate = u"_DUPLICATED_UNDO_"

    def __init__(self, low_message, high_message):
        self.low_message = low_message
        self.high_message = high_message


class Community(TaskManager):
    __metaclass__ = ABCMeta

    # Probability steps to get a sync skipped if the previous one was empty
    _SKIP_CURVE_STEPS = [0, 0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    _SKIP_STEPS = len(_SKIP_CURVE_STEPS)

    @classmethod
    def get_classification(cls):
        """
        Describes the community type.  Should be the same across compatible versions.
        @rtype: unicode
        """
        return cls.__name__.decode("UTF-8")

    @classmethod
    def create_community(cls, dispersy, my_member, *args, **kargs):
        """
        Create a new community owned by my_member.

        Each unique community, that exists out in the world, is identified by a public/private key
        pair.  When the create_community method is called such a key pair is generated.

        Furthermore, my_member will be granted permission to use all the messages that the community
        provides.

        @param dispersy: The Dispersy instance where this community will attach itself to.
        @type dispersy: Dispersy

        @param my_member: The Member that will be granted Permit, Authorize, and Revoke for all
         messages.
        @type my_member: Member

        @param args: optional arguments that are passed to the community constructor.
        @type args: tuple

        @param kargs: optional keyword arguments that are passed to the community constructor.
        @type args: dictionary

        @return: The created community instance.
        @rtype: Community
        """
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(my_member, Member), type(my_member)
        assert my_member.public_key, my_member.database_id
        assert my_member.private_key, my_member.database_id
        assert isInIOThread()
        master = dispersy.get_new_member(u"high")

        # new community instance
        community = cls.init_community(dispersy, master, my_member, *args, **kargs)

        # create the dispersy-identity for the master member
        message = community.create_identity(sign_with_master=True)

        # authorize MY_MEMBER
        permission_triplets = []
        message_names = (u"dispersy-authorize", u"dispersy-revoke", u"dispersy-undo-own", u"dispersy-undo-other")
        for message in community.get_meta_messages():
            # grant all permissions for messages that use LinearResolution or DynamicResolution
            if isinstance(message.resolution, (LinearResolution, DynamicResolution)):
                for allowed in (u"authorize", u"revoke", u"permit"):
                    permission_triplets.append((my_member, message, allowed))

                # ensure that undo_callback is available
                if message.undo_callback:
                    # we do not support undo permissions for authorize, revoke, undo-own, and
                    # undo-other (yet)
                    if not message.name in message_names:
                        permission_triplets.append((my_member, message, u"undo"))

            # grant authorize, revoke, and undo permission for messages that use PublicResolution
            # and SyncDistribution.  Why?  The undo permission allows nodes to revoke a specific
            # message that was gossiped around.  The authorize permission is required to grant other
            # nodes the undo permission.  The revoke permission is required to remove the undo
            # permission.  The permit permission is not required as the message uses
            # PublicResolution and is hence permitted regardless.
            elif isinstance(message.distribution, SyncDistribution) and isinstance(message.resolution, PublicResolution):
                # ensure that undo_callback is available
                if message.undo_callback:
                    # we do not support undo permissions for authorize, revoke, undo-own, and
                    # undo-other (yet)
                    if not message.name in message_names:
                        for allowed in (u"authorize", u"revoke", u"undo"):
                            permission_triplets.append((my_member, message, allowed))

        if permission_triplets:
            community.create_authorize(permission_triplets, sign_with_master=True, forward=False)

        return community

    @classmethod
    def get_master_members(cls, dispersy):
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isInIOThread()
        logger.debug("retrieving all master members owning %s communities", cls.get_classification())
        execute = dispersy.database.execute
        return [dispersy.get_member(public_key=str(public_key)) if public_key else dispersy.get_member(mid=str(mid))
                for mid, public_key,
                in list(execute(u"SELECT m.mid, m.public_key FROM community AS c JOIN member AS m ON m.id = c.master"
                                u" WHERE c.classification = ?",
                                (cls.get_classification(),)))]

    @classmethod
    def init_community(cls, dispersy, master, my_member, *args, **kargs):
        """
        Initializes a new community, using master as the identifier and my_member as the
        public/private keypair to be used when sending messages.

        Each community is identified by the hash of the public key of the master member.
        This member is created in the create_community method.

        @param dispersy: The Dispersy instance where this community will attach itself to.
        @type dispersy: Dispersy

        @param master: The master member that identifies the community.
        @type master: DummyMember or Member

        @param my_member: The my member that identifies you in this community.
        @type my_member: Member

        @param args: optional arguments that are passed to the community constructor.
        @type args: tuple

        @param kargs: optional keyword arguments that are passed to the community constructor.
        @type kargs: dictionary

        @return: The initialized community instance.
        @rtype: Community
        """
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(my_member, Member), type(my_member)
        assert my_member.public_key, my_member.database_id
        assert my_member.private_key, my_member.database_id
        assert isInIOThread()

        # new community instance
        community = cls(dispersy, master, my_member)
        # add to dispersy
        dispersy.attach_community(community)

        community.initialize(*args, **kargs)

        return community

    def __init__(self, dispersy, master, my_member):
        """
        Please never call the constructor of a community directly, always use
        create_community or init_community.

        @param dispersy: The Dispersy object.
        @type dispersy: Dispersy

        @param master: The master member that identifies the community.
        @type master: DummyMember or Member

        @param my_member: The my member that identifies you in this community.
        @type my_member: Member
        """
        assert isInIOThread()
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(master, DummyMember), type(master)
        assert master.mid not in dispersy._communities
        assert isinstance(my_member, Member), type(my_member)
        assert my_member.public_key, my_member.database_id
        assert my_member.private_key, my_member.database_id

        super(Community, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        # Dispersy
        self._dispersy = dispersy

        # community data
        self._database_id = None
        self._database_version = None

        self._cid = master.mid
        self._master_member = master
        self._my_member = my_member

        self._global_time = 0
        self._candidates = OrderedDict()

        self._statistics = CommunityStatistics(self)

        self._last_sync_time = 0

        # batch caching incoming packets
        self._batch_cache = {}

        # delayed list for incoming packet/messages which are delayed
        self._delayed_key = defaultdict(list)

        self._delayed_value = defaultdict(list)

        self.meta_message_cache = {}
        self._meta_messages = {}

        self._conversions = []

        self._nrsyncpackets = 0

        self._do_pruning = False

        self._sync_cache_skip_count = 0

        self._acceptable_global_time_deadline = 0.0

        self._request_cache = None
        self._timeline = None
        self._random = None
        self._walked_candidates = None
        self._stumbled_candidates = None
        self._introduced_candidates = None
        self._walk_candidates = None
        self._fast_steps_taken = 0
        self._sync_cache = None

    def initialize(self):
        assert isInIOThread()
        self._logger.info("initializing:  %s", self.get_classification())
        self._logger.debug("master member: %s %s", self._master_member.mid.encode("HEX"),
            "" if self._master_member.public_key else " (no public key available)")

        # Do not immediately call the periodic cleanup LC to avoid an infinite recursion problem: init_community ->
        # initialize -> invoke_func -> _get_latest_channel_message -> convert_packet_to_message -> get_community ->
        # init_community
        self.register_task("periodic cleanup", LoopingCall(self._periodically_clean_delayed)).start(PERIODIC_CLEANUP_INTERVAL, now=False)

        try:
            self._database_id, my_member_did, self._database_version = self._dispersy.database.execute(
                u"SELECT id, member, database_version FROM community WHERE master = ?",
                (self._master_member.database_id,)).next()

            # if we're called with a different my_member, update the table to reflect this
            if my_member_did != self._my_member.database_id:
                self._dispersy.database.execute(u"UPDATE community SET member = ? WHERE master = ?",
                    (self._my_member.database_id, self._master_member.database_id))

        except StopIteration:
            self._dispersy.database.execute(
                u"INSERT INTO community(master, member, classification) VALUES(?, ?, ?)",
                (self._master_member.database_id, self._my_member.database_id, self.get_classification()))

            self._database_id, self._database_version = self._dispersy.database.execute(
                u"SELECT id, database_version FROM community WHERE master = ?",
                (self._master_member.database_id,)).next()

        self._logger.debug("database id:   %d", self._database_id)

        self._logger.debug("my member:     %s", self._my_member.mid.encode("HEX"))
        assert self._my_member.public_key, [self._database_id, self._my_member.database_id, self._my_member.public_key]
        assert self._my_member.private_key, [self._database_id, self._my_member.database_id, self._my_member.private_key]
        if not self._master_member.public_key and self.dispersy_enable_candidate_walker and self.dispersy_auto_download_master_member:
            self.register_task("download master member identity",
                               LoopingCall(self._download_master_member_identity),
                               delay=0, interval=DOWNLOAD_MM_PK_INTERVAL)

        # define all available messages
        self._initialize_meta_messages()

        # we're only interrested in the meta_message, filter the meta_message_cache
        for name in self.meta_message_cache.keys():
            if name not in self._meta_messages:
                del self.meta_message_cache[name]

        # batched insert
        update_list = []
        for database_id, name, priority, direction in self._dispersy.database.execute(u"SELECT id, name, priority, direction FROM meta_message WHERE community = ?", (self._database_id,)):
            meta_message_info = self.meta_message_cache.get(name)
            if meta_message_info:
                if priority != meta_message_info["priority"] or direction != meta_message_info["direction"]:
                    update_list.append((priority, direction, database_id))

                self._meta_messages[name]._database_id = database_id
                del self.meta_message_cache[name]

        if update_list:
            self._dispersy.database.executemany(u"UPDATE meta_message SET priority = ?, direction = ? WHERE id = ?",
                update_list)

        if self.meta_message_cache:
            insert_list = []
            for name, data in self.meta_message_cache.iteritems():
                insert_list.append((self.database_id, name, data["priority"], data["direction"]))
            self._dispersy.database.executemany(u"INSERT INTO meta_message (community, name, priority, direction) VALUES (?, ?, ?, ?)",
                insert_list)

            for database_id, name in self._dispersy.database.execute(u"SELECT id, name FROM meta_message WHERE community = ?", (self._database_id,)):
                self._meta_messages[name]._database_id = database_id  # cleanup pre-fetched values
        self.meta_message_cache = None

        # define all available conversions
        self._conversions = self.initiate_conversions()
        if __debug__:
            assert len(self._conversions) > 0, len(self._conversions)
            assert all(isinstance(conversion, Conversion) for conversion in self._conversions), [type(conversion) for conversion in self._conversions]

        # the global time.  zero indicates no messages are available, messages must have global
        # times that are higher than zero.
        self._global_time, = self._dispersy.database.execute(u"SELECT MAX(global_time) FROM sync WHERE community = ?", (self._database_id,)).next()
        if self._global_time is None:
            self._global_time = 0
        assert isinstance(self._global_time, (int, long))
        self._acceptable_global_time_cache = self._global_time
        self._logger.debug("global time:   %d", self._global_time)

        # the sequence numbers
        for current_sequence_number, name in self._dispersy.database.execute(u"SELECT MAX(sync.sequence), meta_message.name FROM sync, meta_message WHERE sync.meta_message = meta_message.id AND sync.member = ? AND meta_message.community = ? GROUP BY meta_message.name", (self._my_member.database_id, self.database_id)):
            if current_sequence_number:
                self._meta_messages[name].distribution._current_sequence_number = current_sequence_number

        # sync range bloom filters
        self._sync_cache = None
        self._sync_cache_skip_count = 0
        if __debug__:
            b = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate)
            self._logger.debug("sync bloom:    size: %d;  capacity: %d;  error-rate: %f",
                               int(ceil(b.size // 8)),
                               b.get_capacity(self.dispersy_sync_bloom_filter_error_rate),
                               self.dispersy_sync_bloom_filter_error_rate)

        # assigns temporary cache objects to unique identifiers
        self._request_cache = RequestCache()

        # initial timeline.  the timeline will keep track of member permissions
        self._timeline = Timeline(self)
        self._initialize_timeline()

        # random seed, used for sync range
        self._random = Random()

        # Initialize all the candidate iterators
        self._walked_candidates = self._iter_category(u'walk')
        self._stumbled_candidates = self._iter_category(u'stumble')
        self._introduced_candidates = self._iter_category(u'intro')
        self._walk_candidates = self._iter_categories([u'walk', u'stumble', u'intro'])

        # statistics...
        self._statistics.update()

        # turn on/off pruning
        self._do_pruning = any(isinstance(meta.distribution, SyncDistribution) and
                               isinstance(meta.distribution.pruning, GlobalTimePruning)
                               for meta in self._meta_messages.itervalues())

        try:
            # check if we have already created the identity message
            self.dispersy._database.execute(u"SELECT 1 FROM sync WHERE member = ? AND meta_message = ? LIMIT 1",
                                   (self._my_member.database_id, self.get_meta_message
                                    (u"dispersy-identity").database_id)).next()
            self._my_member.add_identity(self)
        except StopIteration:
            # we haven't do it now
            self.create_identity()

        # check/sanity check the database
        self.dispersy_check_database()
        from sys import argv
        if "--sanity-check" in argv:
            try:
                self.dispersy.sanity_check(self)
            except ValueError:
                self._logger.exception("sanity check fail for %s", self)

        # start walker, if needed
        if self.dispersy_enable_candidate_walker:
            self.register_task("start_walking",
                               reactor.callLater(self.database_id % 3, self.start_walking))

    @property
    def candidates(self):
        """
        Dictionary containing sock_addr:Candidate pairs.
        """
        return self._candidates

    @property
    def request_cache(self):
        """
        The request cache instance responsible for maintaining identifiers and timeouts for outstanding requests.
        @rtype: RequestCache
        """
        return self._request_cache

    @property
    def statistics(self):
        """
        The Statistics instance.
        """
        return self._statistics

    def _download_master_member_identity(self):
        assert not self._master_member.public_key
        self._logger.debug("using dummy master member")

        try:
            public_key, = self._dispersy.database.execute(u"SELECT public_key FROM member WHERE id = ?", (self._master_member.database_id,)).next()
        except StopIteration:
            pass
        else:
            if public_key:
                self._logger.debug("%s found master member", self._cid.encode("HEX"))
                self._master_member = self._dispersy.get_member(public_key=str(public_key))
                assert self._master_member.public_key
                self.cancel_pending_task("download master member identity")
            else:
                for candidate in islice(self.dispersy_yield_verified_candidates(), 1):
                    if candidate:
                        self._logger.debug("%s asking for master member from %s", self._cid.encode("HEX"), candidate)
                        self.create_missing_identity(candidate, self._master_member)

    def _initialize_meta_messages(self):
        assert isinstance(self._meta_messages, dict)
        assert len(self._meta_messages) == 0

        # obtain meta messages
        for meta_message in self.initiate_meta_messages():
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message

        if __debug__:
            sync_interval = 5.0
            for meta_message in self._meta_messages.itervalues():
                if isinstance(meta_message.distribution, SyncDistribution) and meta_message.batch.max_window >= sync_interval:
                    self._logger.warning(
                        "when sync is enabled the interval should be greater than the walking frequency. "
                        " otherwise you are likely to receive duplicate packets [%s]", meta_message.name)

    def _initialize_timeline(self):
        mapping = {}
        for name in [u"dispersy-authorize", u"dispersy-revoke", u"dispersy-dynamic-settings"]:
            try:
                meta = self.get_meta_message(name)
                mapping[meta.database_id] = meta.handle_callback
            except MetaNotFoundException:
                self._logger.warning("unable to load permissions from database [could not obtain %s]", name)

        if mapping:
            for packet, in list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message IN (" + ", ".join("?" for _ in mapping) + ") ORDER BY global_time, packet",
                                                                mapping.keys())):
                message = self._dispersy.convert_packet_to_message(str(packet), self, verify=False)
                if message:
                    self._logger.debug("processing %s", message.name)
                    mapping[message.database_id]([message], initializing=True)
                else:
                    # TODO: when a packet conversion fails we must drop something, and preferably check
                    # all messages in the database again...
                    self._logger.error("invalid message in database [%s; %s]\n%s",
                                       self.get_classification(), self.cid.encode("HEX"), str(packet).encode("HEX"))

    @property
    def dispersy_auto_load(self):
        """
        When True, this community will automatically be loaded when a packet is received.
        """
        # currently we grab it directly from the database, should become a property for efficiency
        return bool(self._dispersy.database.execute(u"SELECT auto_load FROM community WHERE master = ?",
                                                    (self._master_member.database_id,)).next()[0])

    @dispersy_auto_load.setter
    def dispersy_auto_load(self, auto_load):
        """
        Sets the auto_load flag for this community.
        """
        assert isinstance(auto_load, bool)
        self._dispersy.database.execute(u"UPDATE community SET auto_load = ? WHERE master = ?",
                                        (1 if auto_load else 0, self._master_member.database_id))

    @property
    def dispersy_auto_download_master_member(self):
        """
        Enable or disable automatic downloading of the dispersy-identity for the master member.
        """
        return True

    @property
    def dispersy_enable_candidate_walker(self):
        """
        Enable the candidate walker.

        When True is returned, the take_step method will be called periodically.  Otherwise
        it will be ignored.  The candidate walker is enabled by default.
        """
        return True

    @property
    def dispersy_enable_fast_candidate_walker(self):
        """
        Enable the fast candidate walker.

        When True is returned, the take_step method will initially take step more often to boost
        the number of candidates available at startup.
        The candidate fast walker is disabled by default.
        """
        return False

    @property
    def dispersy_enable_candidate_walker_responses(self):
        """
        Enable the candidate walker responses.

        When True is returned, the community will be able to respond to incoming
        dispersy-introduction-request and dispersy-puncture-request messages.  Otherwise these
        messages are left undefined and will be ignored.

        When dispersy_enable_candidate_walker returns True, this property must also return True.
        The default value is to mirror self.dispersy_enable_candidate_walker.
        """
        return self.dispersy_enable_candidate_walker

    @property
    def dispersy_enable_bloom_filter_sync(self):
        """
        Enable the bloom filter synchronisation during the neighbourhood walking.

        When True is returned, outgoing dispersy-introduction-request messages will get the chance to include a sync
        bloom filter by calling Community.dispersy_claim_sync_bloom_filter(...).

        When False is returned, outgoing dispersy-introduction-request messages will never include sync bloom filters
        and Community.acceptable_global_time will return 2 ** 63 - 1, ensuring that all messages that are delivered
        on-demand or incidentally, will be accepted.
        """
        return True

    @property
    def dispersy_sync_bloom_filter_error_rate(self):
        """
        The error rate that is allowed within the sync bloom filter.

        Having a higher error rate will allow for more items to be stored in the bloom filter,
        allowing more items to be syced with each sync interval.  Although this has the disadvantage
        that more false positives will occur.

        A false positive will mean that if A sends a dispersy-sync message to B, B will incorrectly
        believe that A already has certain messages.  Each message has -error rate- chance of being
        a false positive, and hence B will not be able to receive -error rate- percent of the
        messages in the system.

        This problem can be aleviated by having multiple bloom filters for each sync range with
        different prefixes.  Because bloom filters with different prefixes are extremely likely (the
        hash functions md5, sha1, shaxxx ensure this) to have false positives for different packets.
        Hence, having two of three different bloom filters will ensure you will get all messages,
        though it will take more rounds.

        @rtype: float
        """
        return 0.01

    @property
    def dispersy_sync_bloom_filter_bits(self):
        """
        The size in bits of this bloom filter.

        Note that the amount must be a multiple of eight.

        The sync bloom filter is part of the dispersy-introduction-request message and hence must
        fit within a single MTU.  There are several numbers that need to be taken into account.

        - A typical MTU is 1500 bytes

        - A typical IP header is 20 bytes.  However, the maximum IP header is 60 bytes (this
          includes information for VPN, tunnels, etc.)

        - The UDP header is 8 bytes

        - The dispersy header is 2 + 20 + 1 + 20 + 8 = 51 bytes (version, cid, type, member,
          global-time)

        - The signature is usually 60 bytes.  This depends on what public/private key was chosen.
          The current value is: self._my_member.signature_length

        - The other payload is 6 + 6 + 6 + 1 + 2 = 21 (destination-address, source-lan-address,
          source-wan-address, advice+connection-type+sync flags, identifier)

        - The sync payload uses 8 + 8 + 4 + 4 + 1 + 4 + 1 = 30 (time low, time high, modulo, offset,
          function, bits, prefix)
        """
        return (1500 - 60 - 8 - 51 - self._my_member.signature_length - 21 - 30) * 8

    @property
    def dispersy_sync_bloom_filter_strategy(self):
        return self._dispersy_claim_sync_bloom_filter_largest

    @property
    def dispersy_sync_skip_enable(self):
        return True  # _sync_skip_

    @property
    def dispersy_sync_cache_enable(self):
        return True  # _cache_enable_

    def dispersy_store(self, messages):
        """
        Called after new MESSAGES have been stored in the database.
        """
        if __debug__:
            cached = 0

        if self._sync_cache:
            cache = self._sync_cache
            for message in messages:
                if (message.distribution.priority > 32 and
                    cache.time_low <= message.distribution.global_time <= cache.time_high and
                        (message.distribution.global_time + cache.offset) % cache.modulo == 0):

                    if __debug__:
                        cached += 1

                    # update cached bloomfilter to avoid duplicates
                    cache.bloom_filter.add(message.packet)

                    # if this message was received from the candidate we send the bloomfilter too, increment responses
                    if (cache.candidate and message.candidate and cache.candidate.sock_addr == message.candidate.sock_addr):
                        cache.responses_received += 1

        if __debug__:
            if cached:
                self._logger.debug("%s] %d out of %d were part of the cached bloomfilter",
                                   self._cid.encode("HEX"), cached, len(messages))

    def dispersy_claim_sync_bloom_filter(self, request_cache):
        """
        Returns a (time_low, time_high, modulo, offset, bloom_filter) or None.
        """
        if self._sync_cache:
            if self._sync_cache.responses_received > 0:
                if self.dispersy_sync_skip_enable:
                    # We have received data, reset skip counter
                    self._sync_cache_skip_count = 0

                if self.dispersy_sync_cache_enable and self._sync_cache.times_used < 100:
                    self._statistics.sync_bloom_reuse += 1
                    self._statistics.sync_bloom_send += 1
                    cache = self._sync_cache
                    cache.times_used += 1
                    cache.responses_received = 0
                    cache.candidate = request_cache.helper_candidate

                    self._logger.debug("%s reuse #%d (packets received: %d; %s)",
                                       self._cid.encode("HEX"), cache.times_used, cache.responses_received,
                                       hex(cache.bloom_filter._filter))
                    return cache.time_low, cache.time_high, cache.modulo, cache.offset, cache.bloom_filter

            elif self._sync_cache.times_used == 0:
                # Still no updates, gradually increment the skipping probability one notch
                self._logger.debug("skip:%d -> %d  received:%d", self._sync_cache_skip_count,
                                   min(self._sync_cache_skip_count + 1, self._SKIP_STEPS),
                                   self._sync_cache.responses_received)
                self._sync_cache_skip_count = min(self._sync_cache_skip_count + 1, self._SKIP_STEPS)

        if (self.dispersy_sync_skip_enable and
            self._sync_cache_skip_count and
                random() < self._SKIP_CURVE_STEPS[self._sync_cache_skip_count - 1]):
                # Lets skip this one
                self._logger.debug("skip: random() was <%f", self._SKIP_CURVE_STEPS[self._sync_cache_skip_count - 1])
                self._statistics.sync_bloom_skip += 1
                self._sync_cache = None
                return None

        sync = self.dispersy_sync_bloom_filter_strategy(request_cache)
        if sync:
            self._sync_cache = SyncCache(*sync)
            self._sync_cache.candidate = request_cache.helper_candidate
            self._statistics.sync_bloom_new += 1
            self._statistics.sync_bloom_send += 1
            self._logger.debug("%s new sync bloom (%d/%d~%.2f)", self._cid.encode("HEX"),
                               self._statistics.sync_bloom_reuse, self._statistics.sync_bloom_new,
                               round(1.0 * self._statistics.sync_bloom_reuse / self._statistics.sync_bloom_new, 2))

        return sync

    # instead of pivot + capacity, compare pivot - capacity and pivot + capacity to see which globaltime range is largest
    @runtime_duration_warning(0.5)
    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def _dispersy_claim_sync_bloom_filter_largest(self, request_cache):
        if __debug__:
            t1 = time()

        syncable_messages = u", ".join(unicode(meta.database_id) for meta in self._meta_messages.itervalues() if isinstance(meta.distribution, SyncDistribution) and meta.distribution.priority > 32)
        if syncable_messages:
            if __debug__:
                t2 = time()

            acceptable_global_time = self.acceptable_global_time
            bloom = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate, prefix=chr(int(random() * 256)))
            capacity = bloom.get_capacity(self.dispersy_sync_bloom_filter_error_rate)

            desired_mean = self.global_time / 2.0
            lambd = 1.0 / desired_mean
            from_gbtime = self.global_time - int(self._random.expovariate(lambd))
            if from_gbtime < 1:
                from_gbtime = int(self._random.random() * self.global_time)

            if from_gbtime > 1 and self._nrsyncpackets >= capacity:
                # use from_gbtime -1/+1 to include from_gbtime
                right, rightdata = self._select_bloomfilter_range(request_cache, syncable_messages, from_gbtime - 1, capacity, True)

                # if right did not get to capacity, then we have less than capacity items in the database
                # skip left
                if right[2] == capacity:
                    left, leftdata = self._select_bloomfilter_range(request_cache, syncable_messages, from_gbtime + 1, capacity, False)
                    left_range = (left[1] or self.global_time) - left[0]
                    right_range = (right[1] or self.global_time) - right[0]

                    if left_range > right_range:
                        bloomfilter_range = left
                        data = leftdata
                    else:
                        bloomfilter_range = right
                        data = rightdata

                else:
                    bloomfilter_range = right
                    data = rightdata

                if __debug__:
                    t3 = time()
            else:
                if __debug__:
                    t3 = time()

                bloomfilter_range = [1, acceptable_global_time]

                data, fixed = self._select_and_fix(request_cache, syncable_messages, 0, capacity, True)
                if len(data) > 0 and fixed:
                    bloomfilter_range[1] = data[-1][0]
                    self._nrsyncpackets = capacity + 1

            if __debug__:
                t4 = time()

            if len(data) > 0:
                bloom.add_keys(str(packet) for _, packet in data)

                if __debug__:
                    self._logger.debug("%s syncing %d-%d, nr_packets = %d, capacity = %d, packets %d-%d, pivot = %d",
                                 self.cid.encode("HEX"), bloomfilter_range[0], bloomfilter_range[1],
                                 len(data), capacity, data[0][0], data[-1][0], from_gbtime)
                    self._logger.debug("%s took %f (fakejoin %f, rangeselect %f, dataselect %f, bloomfill, %f",
                                 self.cid.encode("HEX"), time() - t1, t2 - t1, t3 - t2, t4 - t3, time() - t4)

                return (min(bloomfilter_range[0], acceptable_global_time), min(bloomfilter_range[1], acceptable_global_time), 1, 0, bloom)

            if __debug__:
                self._logger.debug("%s no messages to sync", self.cid.encode("HEX"))

        elif __debug__:
            self._logger.debug("%s NOT syncing no syncable messages", self.cid.encode("HEX"))
        return (1, acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    def _select_bloomfilter_range(self, request_cache, syncable_messages, global_time, to_select, higher=True):
        data, fixed = self._select_and_fix(request_cache, syncable_messages, global_time, to_select, higher)

        lowerfixed = True
        higherfixed = True

        # if we selected less than to_select
        if len(data) < to_select:
            # calculate how many still remain
            to_select = to_select - len(data)
            if to_select > 25:
                if higher:
                    lowerdata, lowerfixed = self._select_and_fix(request_cache, syncable_messages, global_time + 1, to_select, False)
                    data = lowerdata + data
                else:
                    higherdata, higherfixed = self._select_and_fix(request_cache, syncable_messages, global_time - 1, to_select, True)
                    data = data + higherdata

        bloomfilter_range = [data[0][0], data[-1][0], len(data)]
        # we can use the global_time as a min or max value for lower and upper bound
        if higher:
            # we selected items higher than global_time, make sure bloomfilter_range[0] is at least as low a global_time + 1
            # we select all items higher than global_time, thus all items global_time + 1 are included
            bloomfilter_range[0] = min(bloomfilter_range[0], global_time + 1)

            # if not fixed and higher, then we have selected up to all know packets
            if not fixed:
                bloomfilter_range[1] = self.acceptable_global_time
            if not lowerfixed:
                bloomfilter_range[0] = 1
        else:
            # we selected items lower than global_time, make sure bloomfilter_range[1] is at least as high as global_time -1
            # we select all items lower than global_time, thus all items global_time - 1 are included
            bloomfilter_range[1] = max(bloomfilter_range[1], global_time - 1)

            if not fixed:
                bloomfilter_range[0] = 1
            if not higherfixed:
                bloomfilter_range[1] = self.acceptable_global_time

        return bloomfilter_range, data

    def _select_and_fix(self, request_cache, syncable_messages, global_time, to_select, higher=True):
        assert isinstance(syncable_messages, unicode)
        if higher:
            data = list(self._dispersy.database.execute(u"SELECT global_time, packet FROM sync WHERE meta_message IN (%s) AND undone = 0 AND global_time > ? ORDER BY global_time ASC LIMIT ?" % (syncable_messages),
                       (global_time, to_select + 1)))
        else:
            data = list(self._dispersy.database.execute(u"SELECT global_time, packet FROM sync WHERE meta_message IN (%s) AND undone = 0 AND global_time < ? ORDER BY global_time DESC LIMIT ?" % (syncable_messages),
                       (global_time, to_select + 1)))

        fixed = False
        if len(data) > to_select:
            fixed = True

            # if last 2 packets are equal, then we need to drop those
            global_time = data[-1][0]
            del data[-1]
            while data and data[-1][0] == global_time:
                del data[-1]

        if not higher:
            data.reverse()

        return data, fixed

    # instead of pivot + capacity, compare pivot - capacity and pivot + capacity to see which globaltime range is largest
    @runtime_duration_warning(0.5)
    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def _dispersy_claim_sync_bloom_filter_modulo(self, request_cache):
        syncable_messages = u", ".join(unicode(meta.database_id) for meta in self._meta_messages.itervalues() if isinstance(meta.distribution, SyncDistribution) and meta.distribution.priority > 32)
        if syncable_messages:
            bloom = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate, prefix=chr(int(random() * 256)))
            capacity = bloom.get_capacity(self.dispersy_sync_bloom_filter_error_rate)

            self._nrsyncpackets = list(self._dispersy.database.execute(u"SELECT count(*) FROM sync WHERE meta_message IN (%s) AND undone = 0 LIMIT 1" % (syncable_messages)))[0][0]
            modulo = int(ceil(self._nrsyncpackets / float(capacity)))
            if modulo > 1:
                offset = randint(0, modulo - 1)
                packets = list(str(packet) for packet, in self._dispersy.database.execute(u"SELECT sync.packet FROM sync WHERE meta_message IN (%s) AND sync.undone = 0 AND (sync.global_time + ?) %% ? = 0" % syncable_messages, (offset, modulo)))
            else:
                offset = 0
                modulo = 1
                packets = list(str(packet) for packet, in self._dispersy.database.execute(u"SELECT sync.packet FROM sync WHERE meta_message IN (%s) AND sync.undone = 0" % syncable_messages))

            bloom.add_keys(packets)

            self._logger.debug("%s syncing %d-%d, nr_packets = %d, capacity = %d, totalnr = %d",
                         self.cid.encode("HEX"), modulo, offset, self._nrsyncpackets, capacity, self._nrsyncpackets)

            return (1, self.acceptable_global_time, modulo, offset, bloom)

        else:
            self._logger.debug("%s NOT syncing no syncable messages", self.cid.encode("HEX"))
        return (1, self.acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    @property
    def dispersy_sync_response_limit(self):
        """
        The maximum number of bytes to send back per received dispersy-sync message.
        @rtype: int
        """
        return 5 * 1024

    @property
    def dispersy_missing_sequence_response_limit(self):
        """
        The maximum number of bytes to send back per received dispersy-missing-sequence message.
        @rtype: (int, int)
        """
        return 10 * 1024

    @property
    def dispersy_acceptable_global_time_range(self):
        return 10000

    @property
    def cid(self):
        """
        The 20 byte sha1 digest of the public master key, in other words: the community identifier.
        @rtype: string
        """
        return self._cid

    @property
    def database_id(self):
        """
        The number used to identify this community in the local Dispersy database.
        @rtype: int or long
        """
        return self._database_id

    @property
    def database_version(self):
        return self._database_version

    @property
    def master_member(self):
        """
        The community Member instance.
        @rtype: Member
        """
        return self._master_member

    @property
    def my_member(self):
        """
        Our own Member instance that is used to sign the messages that we create.
        @rtype: Member
        """
        return self._my_member

    @property
    def dispersy(self):
        """
        The Dispersy instance.
        @rtype: Dispersy
        """
        return self._dispersy

    @property
    def timeline(self):
        """
        The Timeline instance.
        @rtype: Timeline
        """
        return self._timeline

    @property
    def global_time(self):
        """
        The most highest global time that we have stored in the database.
        @rtype: int or long
        """
        return max(1, self._global_time)

    @property
    def acceptable_global_time(self):
        """
        The highest global time that we will accept for incoming messages that need to be stored in
        the database.

        The acceptable global time is determined as follows:

        1. when self.dispersy_enable_bloom_filter_sync == False, returns 2 ** 63 - 1, or

        2. when we have more than 5 candidates (i.e. we have more than 5 opinions about what the global_time should be)
           we will use its median + self.dispersy_acceptable_global_time_range, or

        3. otherwise we will not trust the candidate's opinions and use our own global time (obtained from the highest
           global time in the database) + self.dispersy_acceptable_global_time_range.

        @rtype: int or long
        """
        now = time()

        def acceptable_global_time_helper():
            options = sorted(global_time for global_time in (candidate.global_time for candidate in self.dispersy_yield_verified_candidates()) if global_time > 0)

            if len(options) > 5:
                # note: officially when the number of options is even, the median is the average between the
                # two 'middle' options.  in our case we simply round down the 'middle' option
                median_global_time = options[len(options) / 2]

            else:
                median_global_time = 0

            # 07/05/12 Boudewijn: for an unknown reason values larger than 2^63-1 cause overflow
            # exceptions in the sqlite3 wrapper
            return min(max(self._global_time, median_global_time) + self.dispersy_acceptable_global_time_range, 2 ** 63 - 1)

        if self.dispersy_enable_bloom_filter_sync:
            # get opinions from all active candidates
            if self._acceptable_global_time_deadline < now:
                self._acceptable_global_time_cache = acceptable_global_time_helper()
                self._acceptable_global_time_deadline = now + 5.0
            return self._acceptable_global_time_cache

        else:
            return 2 ** 63 - 1

    def unload_community(self):
        """
        Unload a single community.
        """

        self.purge_batch_cache()

        self.cancel_all_pending_tasks()

        self._request_cache.clear()

        self.dispersy.detach_community(self)

    def is_loaded(self):
        """
        Returns whether this community is attached to Dispersy
        """
        return self in self.dispersy.get_communities()

    def claim_global_time(self):
        """
        Increments the current global time by one and returns this value.
        @rtype: int or long
        """
        self.update_global_time(self._global_time + 1)
        self._logger.debug("claiming a new global time value @%d", self._global_time)
        return self._global_time

    def update_global_time(self, global_time):
        """
        Increase the local global time if the given GLOBAL_TIME is larger.
        """
        if global_time > self._global_time:
            self._logger.debug("updating global time %d -> %d", self._global_time, global_time)
            self._global_time = global_time

            if self._do_pruning:
                # Check for messages that need to be pruned because the global time changed.
                for meta in self._meta_messages.itervalues():
                    if isinstance(meta.distribution, SyncDistribution) and isinstance(meta.distribution.pruning, GlobalTimePruning):
                         self._dispersy.database.execute(
                            u"DELETE FROM sync WHERE meta_message = ? AND global_time <= ?",
                            (meta.database_id, self._global_time - meta.distribution.pruning.prune_threshold))

    def dispersy_check_database(self):
        """
        Called each time after the community is loaded and attached to Dispersy.
        """
        self._database_version = self._dispersy.database.check_community_database(self, self._database_version)

    def get_conversion_for_packet(self, packet):
        """
        Returns the conversion associated with PACKET.

        This method returns the first available conversion that can *decode* PACKET, this is tested
        in reversed order using conversion.can_decode_message(PACKET).  Typically a conversion can
        decode a string when it matches: the community version, the Dispersy version, and the
        community identifier, and the conversion knows how to decode messages types described in
        PACKET.

        Note that only the bytes needed to determine conversion.can_decode_message(PACKET) must be
        given, therefore PACKET is not necessarily an entire packet but can also be a the first N
        bytes of a packet.

        Raises ConversionNotFoundException(packet) when no conversion is available.
        """
        assert isinstance(packet, str), type(packet)
        for conversion in reversed(self._conversions):
            if conversion.can_decode_message(packet):
                return conversion

        self._logger.warning("unable to find conversion to decode %s in %s", packet.encode("HEX"), self._conversions)
        raise ConversionNotFoundException(packet=packet)

    def get_conversion_for_message(self, message):
        """
        Returns the conversion associated with MESSAGE.

        This method returns the first available conversion that can *encode* MESSAGE, this is tested
        in reversed order using conversion.can_encode_message(MESSAGE).  Typically a conversion can
        encode a message when: the conversion knows how to encode messages with MESSAGE.name.

        Raises ConversionNotFoundException(message) when no conversion is available.
        """
        assert isinstance(message, (Message, Message.Implementation)), type(message)

        for conversion in reversed(self._conversions):
            if conversion.can_encode_message(message):
                return conversion

        self._logger.warning("unable to find conversion to encode %s in %s", message, self._conversions)
        raise ConversionNotFoundException(message=message)

    def add_conversion(self, conversion):
        """
        Add a Conversion to the Community.

        A conversion instance converts between the internal Message structure and the on-the-wire
        message.

        @param conversion: The new conversion instance.
        @type conversion: Conversion
        """
        assert isinstance(conversion, Conversion)
        self._conversions.append(conversion)

    def start_walking(self):
        def get_eligible_candidates(now):
            # pretending that we're already in the future to make candidates eligible for walking sooner, add some randomness to load balance
            return [candidate for candidate in self._candidates.itervalues() if candidate.is_eligible_for_walk(now + uniform(20, 27.5))]

        def switch_to_normal_walking():
            """
            Start walking towards eligible candidates regularly, stopping the fast walker if it's still running.
            """
            self.cancel_pending_task("take fast steps")
            self.register_task("take step", LoopingCall(self.take_step)).start(TAKE_STEP_INTERVAL, now=True)

        def take_fast_steps():
            """
            Walk to all the initial and new eligible candidates.
            Stop if we got enough active candidates.

            """
            # count -everyone- that is active (i.e. walk or stumble)
            active_canidates = list(self.dispersy_yield_verified_candidates())
            if len(active_canidates) > FAST_WALKER_CANDIDATE_TARGET:
                self._logger.debug("there are %d active candidates available, "
                                   "quitting fast walker", len(active_canidates))
                switch_to_normal_walking()
            else:
                self._logger.debug("%d candidates active, target is %d walking a bit more... (step %d of %d)",
                                   len(active_canidates),
                                   FAST_WALKER_CANDIDATE_TARGET, self._fast_steps_taken,
                                   FAST_WALKER_STEPS)
                # request peers that are eligible
                eligible_candidates = get_eligible_candidates(time())
                self._logger.debug("Found %d eligible_candidates", len(eligible_candidates))

                for count, candidate in enumerate(eligible_candidates, 1):
                    self._logger.debug("%d of %d extra walk to %s", count, len(eligible_candidates), candidate)
                    self.create_introduction_request(candidate, allow_sync=False, is_fast_walker=True)

                self._fast_steps_taken += 1
                if self._fast_steps_taken >= FAST_WALKER_STEPS:
                    switch_to_normal_walking()

        if self.dispersy_enable_fast_candidate_walker:
            self._fast_steps_taken = 0
            self.register_task("take fast steps",
                               LoopingCall(take_fast_steps)
            ).start(FAST_WALKER_STEP_INTERVAL, now=True)
        else:
            switch_to_normal_walking()

    def take_step(self):
        now = time()
        self._logger.debug("previous sync was %.1f seconds ago",
                           now - self._last_sync_time if self._last_sync_time else -1)

        candidate = self.dispersy_get_walk_candidate()
        if candidate:
            self._logger.debug("%s %s taking step towards %s",
                               self.cid.encode("HEX"), self.get_classification(), candidate)
            self.create_introduction_request(candidate, self.dispersy_enable_bloom_filter_sync)
        else:
            self._logger.debug("%s %s no candidate to take step", self.cid.encode("HEX"), self.get_classification())
        self._last_sync_time = time()

    def _iter_category(self, category, strict=True):
        # strict=True will ensure both candidate.lan_address and candidate.wan_address are not
        # 0.0.0.0:0
        while True:
            index = 0
            has_result = False
            keys = self._candidates.keys()

            while index < len(keys):
                now = time()
                key = keys[index]
                candidate = self._candidates.get(key)

                if (candidate and
                    candidate.get_category(now) == category and
                        not (strict and (candidate.lan_address == ("0.0.0.0", 0) or candidate.wan_address == ("0.0.0.0", 0)))):

                    yield candidate
                    has_result = True

                    keys = self._candidates.keys()
                    try:
                        if keys[index] != key:
                            # a key has been removed from self._candidates
                            index = keys.index(key)
                    except (IndexError, ValueError):
                        index -= 1

                index += 1

            if not has_result:
                yield None

    def _iter_categories(self, categories, once=False):
        while True:
            index = 0
            has_result = False
            keys = self._candidates.keys()

            while index < len(keys):
                now = time()
                key = keys[index]
                candidate = self._candidates.get(key)

                if (candidate and
                        candidate.get_category(now) in categories):

                    yield candidate
                    has_result = True

                    keys = self._candidates.keys()
                    try:
                        if keys[index] != key:
                            # a key has been removed from self._candidates
                            index = keys.index(key)
                    except (IndexError, ValueError):
                        index -= 1

                index += 1

            if once:
                break
            elif not has_result:
                yield None

    def dispersy_yield_candidates(self):
        """
        Yields all candidates that are part of this community.

        The returned 'walk', 'stumble', and 'intro' candidates are randomised on every call and
        returned only once each.
        """
        now = time()
        candidates = [candidate for candidate in self._candidates.itervalues() if candidate.get_category(now) in (u"walk", u"stumble", u"intro")]
        shuffle(candidates)
        return iter(candidates)

    def dispersy_yield_verified_candidates(self):
        """
        Yields unique active candidates.

        The returned 'walk' and 'stumble' candidates are randomised on every call and returned only
        once each.
        """
        now = time()
        candidates = [candidate for candidate in self._candidates.itervalues() if candidate.get_category(now) in (u"walk", u"stumble")]
        shuffle(candidates)
        return iter(candidates)

    def dispersy_get_introduce_candidate(self, exclude_candidate=None):
        """
        Return one candidate or None in round robin fashion from the walked or stumbled categories.
        This method is used by the walker to choose the candidates to introduce when an introduction
        request is received.
        """
        first_candidates = [None, None]
        while True:
            def get_walked():
                result = self._walked_candidates.next()
                if result == first_candidates[0]:
                    result = None

                if not first_candidates[0]:
                    first_candidates[0] = result

                return result

            def get_stumbled():
                result = self._stumbled_candidates.next()
                if result == first_candidates[1]:
                    result = None

                if not first_candidates[1]:
                    first_candidates[1] = result

                return result

            r = self._random.random()
            result = get_walked() if r <= .5 else get_stumbled()
            if not result:
                result = get_stumbled() if r <= .5 else get_walked()

            if result and exclude_candidate:
                # same candidate as requesting the introduction
                if result == exclude_candidate:
                    continue

                # cannot introduce a non-tunnelled candidate to a tunneled candidate (it's swift instance will not
                # get it)
                if not exclude_candidate.tunnel and result.tunnel:
                    continue

                # cannot introduce two nodes that are behind a different symmetric NAT
                if (exclude_candidate.connection_type == u"symmetric-NAT" and
                    result.connection_type == u"symmetric-NAT" and
                        not exclude_candidate.wan_address[0] == result.wan_address[0]):
                    continue

            return result

    def dispersy_get_walk_candidate(self):
        """
        Returns a candidate from either the walk, stumble or intro category which is eligible for walking.
        Selects a category based on predifined probabilities.
        """
        # 13/02/12 Boudewijn: normal peers can not be visited multiple times within 30 seconds,
        # bootstrap peers can not be visited multiple times within 55 seconds.  this is handled by
        # the Candidate.is_eligible_for_walk(...) method

        from sys import maxsize

        now = time()

        # cleanup obsolete candidates
        self.cleanup_candidates()

        categories = [(maxsize, None), (maxsize, None), (maxsize, None), (maxsize, None)]
        category_sizes = [0, 0, 0, 0]

        for candidate in self._candidates.itervalues():
            if candidate.is_eligible_for_walk(now):
                category = candidate.get_category(now)
                if category == u"walk":
                    categories[0] = min(categories[0], (candidate.last_walk, candidate))
                    category_sizes[0] += 1
                elif category == u"stumble":
                    categories[1] = min(categories[1], (candidate.last_stumble, candidate))
                    category_sizes[1] += 1
                elif category == u"intro":
                    categories[2] = min(categories[2], (candidate.last_intro, candidate))
                    category_sizes[2] += 1
                elif category == u"discovered":
                    categories[3] = min(categories[3], (candidate.last_discovered, candidate))
                    category_sizes[3] += 1

        walk, stumble, intro, discovered = [candidate for _, candidate in categories]

        candidate = None
        while (walk or stumble or intro or discovered) and not candidate:
            r1 = self._random.random()
            r2 = self._random.random()

            if r1 <= .475:
                candidate = walk or ((stumble or intro) if r2 < .5 else (intro or stumble)) or discovered
                assert candidate, walk or stumble or intro or discovered

            elif r1 <= .95:
                candidate = ((stumble or intro) if r2 < .5 else (intro or stumble)) or walk or discovered
                assert candidate, walk or stumble or intro or discovered

            else:
                candidate = discovered

        self._logger.debug("returning [%2d:%2d:%2d:%2d] %s",
                           category_sizes[0], category_sizes[1],
                           category_sizes[2], category_sizes[3], candidate)
        return candidate

    def create_candidate(self, sock_addr, tunnel, lan_address, wan_address, connection_type):
        """
        Creates and returns a new WalkCandidate instance.
        """
        assert not sock_addr in self._candidates
        assert isinstance(tunnel, bool)
        candidate = WalkCandidate(sock_addr, tunnel, lan_address, wan_address, connection_type)
        self.add_candidate(candidate)
        return candidate

    def get_candidate(self, sock_addr, replace=True, lan_address=("0.0.0.0", 0)):
        """
        Returns an existing candidate object or None

        1. returns an existing candidate from self._candidates, or

        2. returns an existing candidate with the same host on a different port if this candidate is
           marked as a symmetric NAT.  When replace is True, the existing candidate is moved from
           its previous sock_addr to the new sock_addr.

        3. Or returns None
        """
        # use existing (bootstrap) candidate
        candidate = self._candidates.get(sock_addr)
        if candidate is None:
            # find matching candidate with the same host but a different port (symmetric NAT)
            for candidate in self._candidates.itervalues():
                if (candidate.connection_type == "symmetric-NAT" and
                    candidate.sock_addr[0] == sock_addr[0] and
                        candidate.lan_address in (("0.0.0.0", 0), lan_address)):
                    self._logger.debug("using existing candidate %s at different port %s %s",
                                       candidate, sock_addr[1], "(replace)" if replace else "(no replace)")

                    if replace:
                        self.remove_candidate(candidate.sock_addr)
                        self._candidates[sock_addr] = candidate = self.create_or_update_walkcandidate(sock_addr, candidate.lan_address, candidate.wan_address, candidate.tunnel, candidate.connection_type, candidate)
                    break

            else:
                # no symmetric NAT candidate found
                candidate = None

        return candidate

    def remove_candidate(self, sock_addr):
        # replace candidate
        candidate = self._candidates.pop(sock_addr, None)

        if candidate:
            # remove vote under previous key
            self._dispersy.wan_address_unvote(candidate)

    @deprecated("Use create_or_update_walkcandidate() instead")
    def get_walkcandidate(self, message):
        if isinstance(message.candidate, WalkCandidate):
            return message.candidate

        else:
            # modify either the senders LAN or WAN address based on how we perceive that node
            source_lan_address, source_wan_address = self._dispersy.estimate_lan_and_wan_addresses(message.candidate.sock_addr, message.payload.source_lan_address, message.payload.source_wan_address)

            # check if we have this candidate registered at its sock_addr
            candidate = self.get_candidate(message.candidate.sock_addr, lan_address=source_lan_address)
            if candidate:
                return candidate

            candidate = self.create_candidate(message.candidate.sock_addr, message.candidate.tunnel, source_lan_address, source_wan_address, message.payload.connection_type)
            return candidate

    def create_or_update_walkcandidate(self, sock_addr, lan_address, wan_address, tunnel, connection_type, candidate=None):
        lan_address, wan_address = self._dispersy.estimate_lan_and_wan_addresses(sock_addr, lan_address, wan_address)

        wcandidate = self.get_candidate(sock_addr, replace=True, lan_address=lan_address)
        if wcandidate:
            wcandidate.update(tunnel, lan_address, wan_address, connection_type)
        else:
            wcandidate = self.create_candidate(sock_addr, tunnel, lan_address, wan_address, connection_type)
        if candidate:
            wcandidate.merge(candidate)
        return wcandidate

    def add_candidate(self, candidate):
        assert isinstance(candidate, WalkCandidate), type(candidate)

        if candidate.sock_addr not in self._candidates:
            self._candidates[candidate.sock_addr] = candidate
            self._statistics.increase_discovered_candidates()

    def add_discovered_candidate(self, d_candidate):
        """
        Informs the community that a new Candidate was discovered in the DiscoveryCommunity.
        """
        candidate = self.get_candidate(d_candidate.sock_addr, replace=False)
        if not candidate:
            if isinstance(d_candidate, WalkCandidate):
                candidate = self.create_candidate(d_candidate.sock_addr, d_candidate.tunnel, d_candidate.lan_address, d_candidate.wan_address, d_candidate.connection_type)
            else:
                candidate = self.create_candidate(d_candidate.sock_addr, d_candidate.tunnel, d_candidate.sock_addr, d_candidate.sock_addr, u"unknown")
        candidate.discovered(time())

    def get_candidate_mid(self, mid):
        member = self._dispersy.get_member(mid=mid)
        if member:
            for candidate in self._candidates.itervalues():
                if candidate.is_associated(member):
                    return candidate

    def filter_duplicate_candidate(self, candidate):
        """
        A node told us its LAN and WAN address, it is possible that we can now determine that we
        already have CANDIDATE in our candidate list.

        When we learn that a candidate happens to be behind a symmetric NAT we must remove all other
        candidates that have the same host.
        """
        wan_address = candidate.wan_address
        lan_address = candidate.lan_address

        # find existing candidates that are likely to be the same candidate
        others = [other
                  for other
                  in self._candidates.itervalues()
                  if (other.wan_address[0] == wan_address[0] and
                      other.lan_address == lan_address)]

        if others:
            # merge and remove existing candidates in favor of the new CANDIDATE
            for other in others:
                # all except for the CANDIDATE
                if not other == candidate:
                    self._logger.warning("removing %s %s in favor of %s %s",
                                   other.sock_addr, other,
                                   candidate.sock_addr, candidate)
                    candidate.merge(other)
                    del self._candidates[other.sock_addr]
                    self._dispersy.wan_address_unvote(other)

            # add this candidate to make sure it didn't get removed in the del call
            self.add_candidate(candidate)

    def cleanup_candidates(self):
        """
        Removes all candidates that are obsolete.

        Returns the number of candidates that were removed.
        """
        now = time()
        obsolete_candidates = [(key, candidate) for key, candidate in self._candidates.iteritems() if candidate.get_category(now) is None]
        for key, candidate in obsolete_candidates:
            self._logger.debug("removing obsolete candidate %s", candidate)
            del self._candidates[key]
            self._dispersy.wan_address_unvote(candidate)

        return len(obsolete_candidates)

    def dispersy_cleanup_community(self, message):
        """
        A dispersy-destroy-community message is received.

        Once a community is destroyed, it must be reclassified to ensure that it is not loaded in
        its regular form.  This method returns the class that the community will be reclassified
        into.  It should return either a subclass of SoftKilledCommity or HardKilledCommunity
        depending on the received dispersy-destroy-community message.

        Depending on the degree of the destroy message, we will need to cleanup in different ways.

         - soft-kill: The community is frozen.  Dispersy will retain the data it has obtained.
           However, no messages beyond the global-time of the dispersy-destroy-community message
           will be accepted.  Responses to dispersy-sync messages will be send like normal.

         - hard-kill: The community is destroyed.  Dispersy will throw away everything except the
           dispersy-destroy-community message and the authorize chain that is required to verify
           this message.  The community should also remove all its data and cleanup as much as
           possible.

        Similar to other on_... methods, this method may raise a DropMessage exception.  In this
        case the message will be ignored and no data is removed.  However, each dispersy-sync that
        is sent is likely to result in the same dispersy-destroy-community message to be received.

        @param address: The address from where we received this message.
        @type address: (string, int)

        @param message: The received message.
        @type message: Message.Implementation

        @rtype: Community class
        """
        # override to implement community cleanup
        if message.payload.is_soft_kill:
            raise NotImplementedError()

        elif message.payload.is_hard_kill:
            return HardKilledCommunity

    def get_meta_message(self, name):
        """
        Returns the meta message by its name.

        @param name: The name of the message.
        @type name: unicode

        @return: The meta message.
        @rtype: Message

        @raise MetaNotFoundException: When there is no meta message by that name.
        """
        assert isinstance(name, unicode)
        if name in self._meta_messages:
            return self._meta_messages[name]

        raise MetaNotFoundException(name)

    def get_meta_messages(self):
        """
        Returns all meta messages.

        @return: The meta messages.
        @rtype: [Message]
        """
        return self._meta_messages.values()

    def initiate_meta_messages(self):
        """
        Create the meta messages for this community instance.

        This method is called once when the community is created.  The resulting meta messages can be obtained
        by either get_meta_message(name) or get_meta_messages().

        Since these meta messages will be used alongside the meta messages that each community
        provides, all message names are prefixed with 'dispersy-' to ensure that the names are
        unique.

        To differentiate the meta messages that the community provides from those that Dispersy provides, none of the
        messages added by the user should have a name that starts with 'dispersy-'.

        @return: The new meta messages.
        @rtype: [Message]

        """

        messages = [
            Message(self, u"dispersy-identity",
                    MemberAuthentication(encoding="bin"),
                    PublicResolution(),
                    LastSyncDistribution(synchronization_direction=u"ASC", priority=16, history_size=1),
                    CommunityDestination(node_count=0),
                    IdentityPayload(),
                    self._generic_timeline_check,
                    self.on_identity),
            Message(self, u"dispersy-signature-request",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    SignatureRequestPayload(),
                    self.check_signature_request,
                    self.on_signature_request),
            Message(self, u"dispersy-signature-response",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    SignatureResponsePayload(),
                    self.check_signature_response,
                    self.on_signature_response),
            Message(self, u"dispersy-authorize",
                    MemberAuthentication(),
                    PublicResolution(),
                    FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                    CommunityDestination(node_count=10),
                    AuthorizePayload(),
                    self._generic_timeline_check,
                    self.on_authorize),
            Message(self, u"dispersy-revoke",
                    MemberAuthentication(),
                    PublicResolution(),
                    FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                    CommunityDestination(node_count=10),
                    RevokePayload(),
                    self._generic_timeline_check,
                    self.on_revoke),
            Message(self, u"dispersy-undo-own",
                    MemberAuthentication(),
                    PublicResolution(),
                    FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                    CommunityDestination(node_count=10),
                    UndoPayload(),
                    self.check_undo,
                    self.on_undo),
            Message(self, u"dispersy-undo-other",
                    MemberAuthentication(),
                    LinearResolution(),
                    FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                    CommunityDestination(node_count=10),
                    UndoPayload(),
                    self.check_undo,
                    self.on_undo),
            Message(self, u"dispersy-destroy-community",
                    MemberAuthentication(),
                    LinearResolution(),
                    FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=192),
                    CommunityDestination(node_count=50),
                    DestroyCommunityPayload(),
                    self._generic_timeline_check,
                    self.on_destroy_community),
            Message(self, u"dispersy-dynamic-settings",
                    MemberAuthentication(),
                    LinearResolution(),
                    FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"DESC", priority=191),
                    CommunityDestination(node_count=10),
                    DynamicSettingsPayload(),
                    self._generic_timeline_check,
                    self.on_dynamic_settings),

            #
            # when something is missing, a dispersy-missing-... message can be used to request
            # it from another peer
            #

            # when we have a member id (20 byte sha1 of the public key) but not the public key
            Message(self, u"dispersy-missing-identity",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    MissingIdentityPayload(),
                    self._generic_timeline_check,
                    self.on_missing_identity),

            # when we are missing one or more SyncDistribution messages in a certain sequence
            Message(self, u"dispersy-missing-sequence",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    MissingSequencePayload(),
                    self._generic_timeline_check,
                    self.on_missing_sequence,
                    batch=BatchConfiguration(max_window=0.1)),

            # when we have a reference to a message that we do not have.  a reference consists
            # of the self identifier, the member identifier, and the global time
            Message(self, u"dispersy-missing-message",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    MissingMessagePayload(),
                    self._generic_timeline_check,
                    self.on_missing_message),

            # when we might be missing a dispersy-authorize message
            Message(self, u"dispersy-missing-proof",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    MissingProofPayload(),
                    self._generic_timeline_check,
                    self.on_missing_proof)
        ]

        if self.dispersy_enable_candidate_walker_responses:
            messages.extend([Message(self, u"dispersy-introduction-request",
                                     MemberAuthentication(),
                                     PublicResolution(),
                                     DirectDistribution(),
                                     CandidateDestination(),
                                     IntroductionRequestPayload(),
                                     self.check_introduction_request,
                                     self.on_introduction_request),
                             Message(self, u"dispersy-introduction-response",
                                     MemberAuthentication(),
                                     PublicResolution(),
                                     DirectDistribution(),
                                     CandidateDestination(),
                                     IntroductionResponsePayload(),
                                     self.check_introduction_response,
                                     self.on_introduction_response),
                             Message(self, u"dispersy-puncture-request",
                                     NoAuthentication(),
                                     PublicResolution(),
                                     DirectDistribution(),
                                     CandidateDestination(),
                                     PunctureRequestPayload(),
                                     self.check_puncture_request,
                                     self.on_puncture_request),
                             Message(self, u"dispersy-puncture",
                                     MemberAuthentication(),
                                     PublicResolution(),
                                     DirectDistribution(),
                                     CandidateDestination(),
                                     PuncturePayload(),
                                     self.check_puncture,
                                     self.on_puncture)])

        return messages

    @abstractmethod
    def initiate_conversions(self):
        """
        Create the Conversion instances for this community instance.

        This method is called once for each community when it is created.  The resulting Conversion instances can be
        obtained using get_conversion_for_packet() and get_conversion_for_message().

        Returns a list with all Conversion instances that this community will support.  Note that the ordering of
        Conversion classes determines what the get_..._conversion_...() methods return.

        @rtype: [Conversion]
        """
        pass

    def get_member(self, *argv, **kwargs):
        assert not argv, "Only named arguments are allowed"
        mid = kwargs.pop("mid", "")
        public_key = kwargs.pop("public_key", "")
        private_key = kwargs.pop("private_key", "")
        assert sum(map(bool, (mid, public_key, private_key))) == 1, \
            "Only one of the three optional arguments may be passed: %s" % str((mid, public_key, private_key))
        assert not kwargs, "Unexpected keyword arg received: %s" % kwargs
        assert isinstance(mid, str)
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        assert not mid or len(mid) == 20
        assert not public_key or self._dispersy.crypto.is_valid_public_bin(public_key)
        assert not private_key or self._dispersy.crypto.is_valid_private_bin(private_key)

        member = self._dispersy.get_member(mid=mid, public_key=public_key, private_key=private_key)
        # We only need to check if this member has an identity message in this community if we still don't have the full
        # public key
        if not mid:
            return member
        if isinstance(member, Member):
            has_identity = member.has_identity(self)
            if not has_identity:
                # check database and update identity set if found
                try:
                    self._dispersy.database.execute(u"SELECT 1 FROM sync WHERE member = ? AND meta_message = ? LIMIT 1",
                        (member.database_id, self.get_meta_message(u"dispersy-identity").database_id)).next()
                except StopIteration:
                    pass
                else:
                    member.add_identity(self)
                    has_identity = True
            if has_identity:
                return member

    def _generic_timeline_check(self, messages):
        meta = messages[0].meta
        if isinstance(meta.authentication, NoAuthentication):
            # we can not timeline.check this message because it uses the NoAuthentication policy
            for message in messages:
                yield message

        else:
            for message in messages:
                allowed, proofs = self.timeline.check(message)
                if allowed:
                    yield message
                else:
                    # reply with all proofs when message is rejected and has dynamicresolution
                    # in order to "fix" differences in dynamic resolution policy between us and the candidate
                    if isinstance(meta.resolution, DynamicResolution):
                        self._dispersy._send_packets([message.candidate], [proof.packet for proof in proofs], self, "-caused by dynamic resolution-")

                    yield DelayMessageByProof(message)

    def _drop(self, drop, packet, candidate):
        self._logger.warning("drop a %d byte packet %s from %s", len(packet), drop, candidate)
        if isinstance(drop, DropPacket):
            self._statistics.increase_msg_count(u"drop", u"drop_packet:%s" % drop)

        elif isinstance(drop, DropMessage):
            self._statistics.increase_msg_count(u"drop", u"drop_message:%s" % drop)

    def _delay(self, match_info, delay, packet, candidate):
        assert len(match_info) == 4, match_info
        assert not match_info[0] or isinstance(match_info[0], unicode), type(match_info[0])
        assert not match_info[1] or isinstance(match_info[1], str), type(match_info[1])
        assert not match_info[1] or len(match_info[1]) == 20, len(match_info[1])
        assert not match_info[2] or isinstance(match_info[2], (int, long)), type(match_info[2])
        assert not match_info[3] or isinstance(match_info[3], list), type(match_info[3])

        send_request = False

        # unwrap sequence number list
        seq_number_list = match_info[3] or [None]
        for seq in seq_number_list:
            unwrapped_key = (match_info[0], match_info[1], match_info[2], seq)

            # if we find a new key, then we need to send a request
            # if we did send a delay for this message that is
            if (unwrapped_key not in self._delayed_key) and (delay not in self._delayed_value):
                send_request = True

            self._delayed_key[unwrapped_key].append(delay)
            self._delayed_value[delay].append(unwrapped_key)

        if send_request:
            delay.send_request(self, candidate)
            self._statistics.increase_delay_msg_count(u"send")

        self._logger.debug("delay a %d byte packet/message (%s) from %s", len(packet), delay, candidate)
        self._statistics.increase_delay_msg_count(u"received")

        if isinstance(delay, DelayMessage):
            self._statistics.increase_msg_count(u"delay", u"delay_message:%s" % delay)

        elif isinstance(delay, DelayPacket):
            self._statistics.increase_msg_count(u"delay", u"delay_packet:%s" % delay)
            delay.delayed = packet
            delay.candidate = candidate

    def _resume_delayed(self, meta, messages):
        has_mid = isinstance(meta.authentication, (MemberAuthentication, DoubleMemberAuthentication))
        has_seq = isinstance(meta.distribution, FullSyncDistribution) and meta.distribution.enable_sequence_number

        received_keys = [(meta.name, message.authentication.member.mid if has_mid else None,
                       message.distribution.global_time,
                       message.distribution.sequence_number if has_seq else None) for message in messages]

        new_messages = defaultdict(set)
        new_packets = set()
        for received_key in received_keys:
            for key in self._delayed_key.keys():
                if all(k is None or k == rk for k, rk in zip(key, received_key)):
                    for delayed in self._delayed_key.pop(key):
                        delayed_keys = self._delayed_value[delayed]
                        delayed_keys.remove(key)

                        if len(delayed_keys) == 0 or delayed.resume_immediately:
                            self._statistics.increase_delay_msg_count(u"success")
                            self._remove_delayed(delayed)

                            if isinstance(delayed, DelayMessage):
                                delayed_message = delayed.on_success()
                                new_messages[delayed_message.meta].add(delayed_message)
                            else:
                                new_packets.add(delayed.on_success())

        if new_messages:
            for new_messages_meta in new_messages.itervalues():
                self._logger.debug("resuming %d messages", len(new_messages_meta))
                self.on_messages(list(new_messages_meta))

        if new_packets:
            self._logger.debug("resuming %d packets", len(new_packets))
            self.on_incoming_packets(list(new_packets), timestamp=time(), source=u"resumed")

    def _remove_delayed(self, delayed):
        for key in self._delayed_value[delayed]:
            self._delayed_key[key].remove(delayed)
            if len(self._delayed_key[key]) == 0:
                del self._delayed_key[key]

        del self._delayed_value[delayed]

    def _periodically_clean_delayed(self):
        now = time()
        for delayed in self._delayed_value.keys():
            if now > delayed.timestamp + 10:
                self._remove_delayed(delayed)
                delayed.on_timeout()
                self._statistics.increase_delay_msg_count(u"timeout")
                self._statistics.increase_msg_count(u"drop", u"delay_timeout:%s" % delayed)

    def on_incoming_packets(self, packets, cache=True, timestamp=0.0, source=u"unknown"):
        """
        Process incoming packets for this community.
        """
        assert isinstance(packets, (tuple, list)), packets
        assert len(packets) > 0, packets
        assert all(isinstance(packet, tuple) for packet in packets), packets
        assert all(len(packet) == 2 for packet in packets), packets
        assert all(isinstance(packet[0], Candidate) for packet in packets), packets
        assert all(isinstance(packet[1], str) for packet in packets), packets
        assert isinstance(cache, bool), cache
        assert isinstance(timestamp, float), timestamp

        self._logger.debug("got %d incoming packets", len(packets))

        for _, iterator in groupby(packets, key=lambda tup: (tup[1][1], tup[1][22])):
            cur_packets = list(iterator)
            # find associated conversion
            try:
                # TODO(emilon): just have a function that gets a packet type byte
                conversion = self.get_conversion_for_packet(cur_packets[0][1])
                meta = conversion.decode_meta_message(cur_packets[0][1])
                batch = [(self.get_candidate(candidate.sock_addr) or candidate, packet, conversion, source)
                         for candidate, packet in cur_packets]
                if meta.batch.enabled and cache:
                    if meta in self._batch_cache:
                        _, current_batch = self._batch_cache[meta]
                        current_batch.extend(batch)
                        self._logger.debug("adding %d %s messages to existing cache", len(batch), meta.name)
                    else:
                        self.register_task(meta, reactor.callLater(meta.batch.max_window, self._process_message_batch, meta))
                        self._batch_cache[meta] = (timestamp, batch)
                        self._logger.debug("new cache with %d %s messages (batch window: %d)",
                                           len(batch), meta.name, meta.batch.max_window)
                else:
                    self._on_batch_cache(meta, batch)

                self._statistics.increase_total_received_count(len(cur_packets))

            except ConversionNotFoundException:
                for candidate, packet in cur_packets:
                    self._logger.warning(
                        "_on_incoming_packets: drop a %d byte packet (received packet for unknown conversion) from %s",
                        len(packet), candidate)
                self._statistics.increase_msg_count(
                    u"drop", u"convert_packets_into_batch:unknown conversion", len(cur_packets))

    def _process_message_batch(self, meta):
        """
        Start processing a batch of messages.

        This method is called meta.batch.max_window seconds after the first message in this batch arrived or when
        flushing all the batches.  All messages in this batch have been 'cached' together in self._batch_cache[meta].
        Hopefully the delay caused the batch to collect as many messages as possible.

        """
        assert isinstance(meta, Message)
        assert meta in self._batch_cache

        _, batch = self._batch_cache.pop(meta)
        self.cancel_pending_task(meta)
        self._logger.debug("processing %sx %s batched messages", len(batch), meta.name)

        return self._on_batch_cache(meta, batch)

    def _on_batch_cache(self, meta, batch):
        """
        Start processing a batch of messages.

        The batch is processed in the following steps:

         1. All duplicate binary packets are removed.

         2. All binary packets are converted into Message.Implementation instances.  Some packets
            are dropped or delayed at this stage.

         3. All remaining messages are passed to on_message_batch.
        """
        # convert binary packets into Message.Implementation instances
        messages = []

        assert isinstance(batch, (list, set))
        assert len(batch) > 0
        assert all(isinstance(x, tuple) for x in batch)
        assert all(len(x) == 4 for x in batch)

        for candidate, packet, conversion, source in batch:
            assert isinstance(candidate, Candidate)
            assert isinstance(packet, str)
            assert isinstance(conversion, Conversion)
            try:
                # convert binary data to internal Message
                messages.append(conversion.decode_message(candidate, packet, source=source))

            except DropPacket as drop:
                self._drop(drop, packet, candidate)

            except DelayPacket as delay:
                self._dispersy._delay(delay, packet, candidate)

        assert all(isinstance(message, Message.Implementation) for message in messages), "convert_batch_into_messages must return only Message.Implementation instances"
        assert all(message.meta == meta for message in messages), "All Message.Implementation instances must be in the same batch"

        # handle the incoming messages
        if messages:
            self.on_messages(messages)

    def purge_batch_cache(self):
        """
        Remove all batches currently scheduled.
        """
        # remove any items that are left in the cache
        for meta in self._batch_cache.iterkeys():
            self.cancel_pending_task(meta)
        self._batch_cache.clear()

    def flush_batch_cache(self):
        """
        Process all pending batches with a sync distribution.
        """
        flush_list = [(meta, tup) for meta, tup in
                      self._batch_cache.iteritems() if isinstance(meta.distribution, SyncDistribution)]

        for meta, (_, batch) in flush_list:
            self._logger.debug("flush cached %dx %s messages (dc: %s)",
                               len(batch), meta.name, self._pending_tasks[meta])
            self._process_message_batch(meta)

    def on_messages(self, messages):
        """
        Process one batch of messages.

        This method is called to process one or more Message.Implementation instances that all have
        the same meta message.  This occurs when new packets are received, to attempt to process
        previously delayed messages, or when a member explicitly creates a message to process.  The
        last option should only occur for debugging purposes.

        The messages are processed with the following steps:

         1. Messages that are superseded or duplicate, based on their distribution policy, are dropped.

         2. The meta.check_callback(...) is used to allow messages to be dropped or delayed.

         3. Messages are stored, based on their distribution policy.

         4. The meta.handle_callback(...) is used to process the messages.

        @param packets: The sequence of messages with the same meta message from the same community.
        @type packets: [Message.Implementation]
        """
        assert isinstance(messages, list)
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)

        def _filter_fail(message):
            if isinstance(message, DelayMessage):
                self._dispersy._delay(message, message.delayed.packet, message.delayed.candidate)
                return False
            elif isinstance(message, DropMessage):
                self._drop(message, message.dropped.packet, message.dropped.candidate)
                return False
            return True

        meta = messages[0].meta
        debug_count = len(messages)
        debug_begin = time()

        # drop all duplicate or old messages
        messages = list(meta.distribution.check_batch(self._dispersy, messages))
        # TODO(emilon): This seems iffy
        assert len(messages) > 0  # should return at least one item for each message
        assert all(isinstance(message, (Message.Implementation, DropMessage, DelayMessage)) for message in messages)

        # handle/remove DropMessage and DelayMessage instances
        messages = [message for message in messages if _filter_fail(message)]
        if not messages:
            return 0

        # check all remaining messages on the community side.  may yield Message.Implementation,
        # DropMessage, and DelayMessage instances
        try:
            possibly_messages = list(meta.check_callback(messages))
        except:
            self._logger.exception("exception during check_callback for %s", meta.name)
            return 0
        # TODO(emilon): fixh _disp_check_modification in channel/community.py (tribler) so we can make a proper assert out of this.
        assert len(possibly_messages) >= 0  # may return zero messages
        assert all(isinstance(message, (Message.Implementation, DropMessage, DelayMessage, DispersyInternalMessage)) for message in possibly_messages), possibly_messages
        assert all(message.dropped not in possibly_messages for message in possibly_messages if isinstance(message, DropMessage)), possibly_messages  # dropped messages cannot be accepted
        #assert all(message.delayed not in possibly_messages for message in possibly_messages if isinstance(message, DelayMessage)), possibly_messages  # delayed messages cannot be accepted
        # TODO(Martijn): we filter out all delayed messages instead of asserting. Should be fixed when we remove the
        # batching behaviour of Dispersy.
        possibly_messages = [message for message in possibly_messages if (not isinstance(message, DelayMessage) or (message.delayed not in possibly_messages))]

        if len(possibly_messages) == 0:
            self._logger.warning("%s yielded zero messages, drop, or delays. "
                                 " This is allowed but likely to be an error.",
                                 meta.check_callback)

        # handle/remove DropMessage and DelayMessage instances
        possibly_messages = [message for message in possibly_messages if _filter_fail(message)]
        if not possibly_messages:
            return 0

        other = []
        messages = []
        for thing in possibly_messages:
            if isinstance(thing, DispersyInternalMessage):
                other.append(thing)
            else:
                messages.append(thing)

        self._logger.debug("in... %d %s messages from %s",
                           len(messages), meta.name,
                           " ".join(str(candidate) for candidate in set(
                               message.candidate for message in messages
                               if isinstance(message, Message.Implementation))))

        # store to disk and update locally
        if self._dispersy.store_update_forward(possibly_messages, True, True, False):
            self._statistics.increase_msg_count(u"success", meta.name, len(messages))

            if meta.name == u"dispersy-introduction-response":
                self._statistics.msg_statistics.walk_success_count += len(messages)
                self._dispersy._statistics.walk_success_count += len(messages)

            elif meta.name == u"dispersy-introduction-request":
                self._dispersy._statistics.incoming_intro_count += len(messages)
                for message in messages:
                    self._statistics.increase_msg_count(u"incoming_intro", message.candidate.sock_addr)
                    self._dispersy._statistics.dict_inc(u"incoming_intro_dict", message.candidate.sock_addr)

            # tell what happened
            debug_end = time()
            if debug_end - debug_begin > 1.0:
                self._logger.warning("handled %d/%d %.2fs %s messages (with %fs cache window)",
                                     len(messages), debug_count, (debug_end - debug_begin),
                                     meta.name, meta.batch.max_window)

            self._resume_delayed(meta, messages)

            # return the number of messages that were correctly handled (non delay, duplicates, etc)
            return len(messages)

        return 0

    def on_identity(self, messages):
        """
        We received a dispersy-identity message.
        """
        for message in messages:
            if message.authentication.member.mid == self._master_member.mid:
                self._logger.debug("%s received master member", self._cid.encode("HEX"))
                self._master_member = message.authentication.member
                assert self._master_member.public_key
                if self.is_pending_task_active("download master member identity"):
                    self.cancel_pending_task("download master member identity")

    def create_signature_request(self, candidate, message, response_func, response_args=(), timeout=10.0, forward=True):
        """
        Create a dispersy-signature-request message.

        The dispersy-signature-request message contains a sub-message that is to be signed by
        another member.  The sub-message must use the DoubleMemberAuthentication policy in order to
        store the two members and their signatures.

        If the other member decides to add their signature she will sent back a
        dispersy-signature-response message.  This message contains a (possibly) modified version of
        the sub-message.

        Receiving the dispersy-signed-response message results in a call to RESPONSE_FUNC.  The
        first parameter for this call is the SignatureRequestCache instance returned by
        create_signature_request, the second parameter is the proposed message that was sent back,
        the third parameter is a boolean indicating whether MESSAGE was modified.

        RESPONSE_FUNC must return a boolean value indicating whether the proposed message (the
        second parameter) is accepted.  Once we accept all signature responses we will add our own
        signature and the last proposed message is stored, updated, and forwarded.

        If not all members sent a reply withing timeout seconds, one final call to response_func is
        made with the second parameter set to None.

        @param candidate: Destination candidate.
        @type candidate: Candidate

        @param message: The message that needs the signature.
        @type message: Message.Implementation

        @param response_func: The method that is called when a signature or a timeout is received.
        @type response_func: callable method

        @param response_args: Optional arguments added when calling response_func.
        @type response_args: tuple

        @param timeout: How long before a timeout is generated.
        @type timeout: int/float

        @param forward: When True the messages are forwarded (as defined by their message
         destination policy) to other nodes in the community.  This parameter should (almost always)
         be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store: bool
        """
        assert isinstance(candidate, Candidate)
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.authentication, DoubleMemberAuthentication.Implementation)
        assert hasattr(response_func, "__call__")
        assert isinstance(response_args, tuple)
        assert isinstance(timeout, float)
        assert isinstance(forward, bool)

        # the members that need to sign
        members = [member for signature, member in message.authentication.signed_members if not (signature or member.private_key)]
        assert len(members) == 1, len(members)

        # temporary cache object
        cache = self.request_cache.add(SignatureRequestCache(self.request_cache, members, response_func, response_args, timeout))
        self._logger.debug("new cache: %s", cache)

        # the dispersy-signature-request message that will hold the
        # message that should obtain more signatures
        meta = self.get_meta_message(u"dispersy-signature-request")
        cache.request = meta.impl(distribution=(self.global_time,),
                                  destination=(candidate,),
                                  payload=(cache.number, message))

        self._logger.debug("asking %s", [member.mid.encode("HEX") for member in members])
        self._dispersy._forward([cache.request])
        return cache

    def check_signature_request(self, messages):
        assert isinstance(messages[0].meta.authentication, NoAuthentication)
        for message in messages:
            # we can not timeline.check this message because it uses the NoAuthentication policy

            # submsg contains the double signed message (that currently contains -no- signatures)
            submsg = message.payload.message

            for is_signed, member in submsg.authentication.signed_members:
                if member == self._my_member:
                    yield message
                    break
            else:
                yield DropMessage(message, "Nothing to sign")

    def on_signature_request(self, messages):
        """
        We received a dispersy-signature-request message.

        This message contains a sub-message (message.payload.message) that the message creator would
        like to have us sign.  We can choose for ourselves if we want to add our signature to the
        sub-message or not.

        Once we have determined that we could provide a signature and that the sub-message is valid,
        from a timeline perspective, we will ask the community to say yes or no to adding our
        signature.  This question is done by calling the
        sub-message.authentication.allow_signature_func method.

        We will only add our signature if the allow_signature_func method returns the same, or a
        modified sub-message.  If so, a dispersy-signature-response message is send to the creator
        of the message, the first one in the authentication list.

        Only _my_member is used.

        @see: create_signature_request

        @param messages: The dispersy-signature-request messages.
        @type messages: [Message.Implementation]
        """
        meta = self.get_meta_message(u"dispersy-signature-response")
        responses = []
        for message in messages:
            assert isinstance(message, Message.Implementation), type(message)
            assert isinstance(message.payload.message, Message.Implementation), type(message.payload.message)
            assert isinstance(message.payload.message.authentication, DoubleMemberAuthentication.Implementation), type(message.payload.message.authentication)

            # the community must allow this signature
            new_submsg = message.payload.message.authentication.allow_signature_func(message.payload.message)
            assert new_submsg is None or isinstance(new_submsg, Message.Implementation), type(new_submsg)
            if new_submsg:
                responses.append(meta.impl(distribution=(self.global_time,),
                                           destination=(message.candidate,),
                                           payload=(message.payload.identifier, new_submsg)))

        if responses:
            self.dispersy._forward(responses)

    def check_signature_response(self, messages):
        identifiers_seen = {}
        for message in messages:
            cache = self.request_cache.get(u"signature-request", message.payload.identifier)
            if not cache:
                yield DropMessage(message, "invalid response identifier")
                continue

            if message.payload.identifier in identifiers_seen:
                self._logger.error("already seen this indentifier in this batch, previous candidate %s this one %s", identifiers_seen[message.payload.identifier], message.candidate)
                yield DropMessage(message, "invalid puncture identifier")
                continue

            old_submsg = cache.request.payload.message
            new_submsg = message.payload.message

            if any(signature == "" and member != self._my_member for signature, member in
                   new_submsg.authentication.signed_members):
                yield DropMessage(message, "message isn't signed by the other party")
                continue

            if not old_submsg.meta == new_submsg.meta:
                yield DropMessage(message, "meta message may not change")
                continue

            if not old_submsg.authentication.member == new_submsg.authentication.member:
                yield DropMessage(message, "first member may not change")
                continue

            if not old_submsg.distribution.global_time == new_submsg.distribution.global_time:
                yield DropMessage(message, "global time may not change")
                continue

            identifiers_seen[message.payload.identifier] = message.candidate
            yield message

    def on_signature_response(self, messages):
        """
        Handle one or more dispersy-signature-response messages.

        We sent out a dispersy-signature-request, through the create_signature_request method, and
        have now received a dispersy-signature-response in reply.  If the signature is valid, we
        will call response_func with sub-message, where sub-message is the message parameter given
        to the create_signature_request method.

        Note that response_func is also called when the sub-message does not yet contain all the
        signatures.  This can be checked using sub-message.authentication.is_signed.
        """
        for message in messages:
            # get cache object linked to this request and stop timeout from occurring
            cache = self.request_cache.pop(u"signature-request", message.payload.identifier)

            old_submsg = cache.request.payload.message
            new_submsg = message.payload.message

            old_body = old_submsg.packet[:len(old_submsg.packet) - sum([member.signature_length for member in old_submsg.authentication.members])]
            new_body = new_submsg.packet[:len(new_submsg.packet) - sum([member.signature_length for member in new_submsg.authentication.members])]

            changed = old_body != new_body

            # A NHopCommunityDestination is allowed to have one unsigned changed field: the hop count.
            # This hop count has the restriction that it must be 1 less in the new message than
            # in the old message.
            if changed and isinstance(message.payload.message.meta.destination, NHopCommunityDestination):
                new_body_len = len(new_body)
                # Create a list of differing indices
                diffs = [i for i in xrange(len(old_body)) if (i < new_body_len) and (old_body[i] != new_body[i])]
                # These indices may not exist if new_body and old_body are not of the same size
                if diffs:
                    start_diff = min(diffs)
                    end_diff = max(diffs)
                    # We can have exactly a 1 byte difference (start == end)
                    if start_diff == end_diff:
                        import struct
                        i_old = struct.unpack_from("!b", old_body, start_diff)[0]
                        i_new = struct.unpack_from("!b", new_body, start_diff)[0]
                        # If this one byte is note 1 less than the new packet, it has changed.
                        changed = (i_new != (i_old - 1))

            result = cache.response_func(old_submsg, new_submsg, changed, *cache.response_args)
            assert isinstance(result, bool), "RESPONSE_FUNC must return a boolean value!  True to accept the proposed message, False to reject %s %s" % (type(cache), str(cache.response_func))
            if result:
                # add our own signatures and we can handle the message
                for signature, member in new_submsg.authentication.signed_members:
                    if not signature and member == self._my_member:
                        new_submsg.authentication.sign(new_body)
                        new_submsg.regenerate_packet()
                        break

                assert new_submsg.authentication.is_signed
                self.dispersy.store_update_forward([new_submsg], True, True, True)

    def check_introduction_request(self, messages):
        """
        We received a dispersy-introduction-request message.
        """
        for message in messages:
            if message.authentication.member.mid == self.my_member.mid:
                self._logger.debug("dropping dispersy-introduction-request, same mid.")
                yield DropMessage(message, "Received introduction_request from my_member [%s]" % str(message.candidate))
                continue

            yield message

    def on_introduction_request(self, messages, extra_payload=None):
        assert not extra_payload or isinstance(extra_payload, list), 'extra_payload is not a list %s' % type(extra_payload)

        meta_introduction_response = self.get_meta_message(u"dispersy-introduction-response")
        meta_puncture_request = self.get_meta_message(u"dispersy-puncture-request")
        responses = []
        requests = []
        now = time()

        #
        # make all candidates available for introduction
        #
        for message in messages:
            candidate = self.create_or_update_walkcandidate(message.candidate.sock_addr, message.payload.source_lan_address, message.payload.source_wan_address, message.candidate.tunnel, message.payload.connection_type, message.candidate)
            candidate.stumble(now)
            message._candidate = candidate

            # apply vote to determine our WAN address
            self._dispersy.wan_address_vote(message.payload.destination_address, candidate)

            self.filter_duplicate_candidate(candidate)
            self._logger.debug("received introduction request from %s", candidate)

        #
        # process the walker part of the request
        #
        for message in messages:
            payload = message.payload
            candidate = message.candidate
            if not candidate:
                continue

            if payload.advice:
                introduced = self.dispersy_get_introduce_candidate(candidate)
                if introduced is None:
                    self._logger.debug("no candidates available to introduce")
            else:
                introduced = None

            if introduced:
                self._logger.debug("telling %s that %s exists %s", candidate, introduced, type(self))

                introduction_args_list = [candidate.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, introduced.lan_address, introduced.wan_address, self._dispersy._connection_type, introduced.tunnel, payload.identifier]
                if extra_payload is not None:
                    introduction_args_list += extra_payload
                introduction_args_list = tuple(introduction_args_list)

                # create introduction response
                responses.append(meta_introduction_response.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=introduction_args_list))

                # create puncture request
                requests.append(meta_puncture_request.impl(distribution=(self.global_time,), destination=(introduced,), payload=(payload.source_lan_address, payload.source_wan_address, payload.identifier)))

            else:
                self._logger.debug("responding to %s without an introduction %s", candidate, type(self))

                none = ("0.0.0.0", 0)

                introduction_args_list = [candidate.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, none, none, self._dispersy._connection_type, False, payload.identifier]
                if extra_payload is not None:
                    introduction_args_list += extra_payload
                introduction_args_list = tuple(introduction_args_list)

                responses.append(meta_introduction_response.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=introduction_args_list))

        if responses:
            self._dispersy._forward(responses)
        if requests:
            self._dispersy._forward(requests)

        #
        # process the bloom filter part of the request
        #
        messages_with_sync = []
        for message in messages:
            payload = message.payload
            candidate = message.candidate
            if not candidate:
                continue

            if payload.sync:
                # 07/05/12 Boudewijn: for an unknown reason values larger than 2^63-1 cause
                # overflow exceptions in the sqlite3 wrapper

                # 11/11/13 Niels: according to http://www.sqlite.org/datatype3.html integers are signed and max
                # 8 bytes, hence the max value is 2 ** 63 - 1 as one bit is used for the sign
                time_low = min(payload.time_low, 2 ** 63 - 1)
                time_high = min(payload.time_high if payload.has_time_high else self.global_time, 2 ** 63 - 1)

                offset = long(payload.offset)
                modulo = long(payload.modulo)

                messages_with_sync.append((message, time_low, time_high, offset, modulo))

        if messages_with_sync:
            for message, generator in self._get_packets_for_bloomfilters(messages_with_sync, include_inactive=False):
                payload = message.payload
                # we limit the response by byte_limit bytes
                byte_limit = self.dispersy_sync_response_limit

                packets = []
                for packet, in payload.bloom_filter.not_filter(generator):
                    packets.append(packet)
                    byte_limit -= len(packet)
                    if byte_limit <= 0:
                        self._logger.debug("bandwidth throttle")
                        break

                if packets:
                    self._logger.debug("syncing %d packets (%d bytes) to %s",
                                       len(packets), sum(len(packet) for packet in packets), message.candidate)
                    self._dispersy._send_packets([message.candidate], packets, self, "-caused by sync-")

    def check_introduction_response(self, messages):
        identifiers_seen = {}
        for message in messages:
            if not self.request_cache.has(u"introduction-request", message.payload.identifier):
                self._dispersy._statistics.invalid_response_identifier_count += 1
                yield DropMessage(message, "invalid response identifier")
                continue

            if message.payload.identifier in identifiers_seen:
                self._logger.error("already seen this indentifier in this batch, previous candidate %s this one %s", identifiers_seen[message.payload.identifier], message.candidate)
                self._dispersy._statistics.invalid_response_identifier_count += 1
                yield DropMessage(message, "invalid response identifier")
                continue

            # check introduced LAN address, if given
            if not message.payload.lan_introduction_address == ("0.0.0.0", 0):
                if not is_valid_address(message.payload.lan_introduction_address):
                    yield DropMessage(message, "invalid LAN introduction address [is_valid_address]")
                    continue

            # check introduced WAN address, if given
            if not message.payload.wan_introduction_address == ("0.0.0.0", 0):
                if not is_valid_address(message.payload.wan_introduction_address):
                    yield DropMessage(message, "invalid WAN introduction address [is_valid_address]")
                    continue

                if message.payload.wan_introduction_address == self._dispersy._wan_address:
                    yield DropMessage(message, "invalid WAN introduction address [introduced to myself]")
                    continue

                # if WAN ip-addresses match, check if the LAN address is not the same
                if message.payload.wan_introduction_address[0] == self._dispersy._wan_address[0] and message.payload.lan_introduction_address == self._dispersy._lan_address:
                    yield DropMessage(message, "invalid LAN introduction address [introduced to myself]")
                    continue

            # if we do not know the WAN address, make sure that the LAN address is not the same
            elif not message.payload.lan_introduction_address == ("0.0.0.0", 0):
                if message.payload.lan_introduction_address == self._dispersy._lan_address:
                    yield DropMessage(message, "invalid LAN introduction address [introduced to myself]")
                    continue

            identifiers_seen[message.payload.identifier] = message.candidate
            yield message

    def on_introduction_response(self, messages):
        now = time()

        for message in messages:
            payload = message.payload
            candidate = self.create_or_update_walkcandidate(message.candidate.sock_addr, payload.source_lan_address, payload.source_wan_address, message.candidate.tunnel, payload.connection_type, message.candidate)
            candidate.walk_response(now)

            self.filter_duplicate_candidate(candidate)
            self._logger.debug("introduction response from %s", candidate)

            # apply vote to determine our WAN address
            self._dispersy.wan_address_vote(payload.destination_address, candidate)

            # get cache object linked to this request and stop timeout from occurring
            cache = self.request_cache.get(u"introduction-request", message.payload.identifier)
            cache.on_introduction_response()

            # handle the introduction
            lan_introduction_address = payload.lan_introduction_address
            wan_introduction_address = payload.wan_introduction_address
            if not (lan_introduction_address == ("0.0.0.0", 0) or wan_introduction_address == ("0.0.0.0", 0)):
                # we need to choose either the lan or wan address to be used as the sock_addr
                # currently we base this decision on the wan ip, if its the same as ours we're probably behind the same NAT and hence must use the lan address
                sock_introduction_addr = lan_introduction_address if wan_introduction_address[0] == self._dispersy._wan_address[0] else wan_introduction_address
                introduced = self.create_or_update_walkcandidate(sock_introduction_addr, lan_introduction_address, wan_introduction_address, payload.tunnel, u"unknown")
                introduced.intro(now)

                self.filter_duplicate_candidate(introduced)
                self._logger.debug("received introduction to %s from %s", introduced, candidate)

                cache.response_candidate = introduced

                # update statistics
                if self._dispersy._statistics.received_introductions is not None:
                    self._dispersy._statistics.received_introductions[candidate.sock_addr][introduced.sock_addr] += 1

            else:
                # update statistics
                if self._dispersy._statistics.received_introductions is not None:
                    self._dispersy._statistics.received_introductions[candidate.sock_addr]['-ignored-'] += 1

    def create_introduction_request(self, destination, allow_sync, forward=True, is_fast_walker=False, extra_payload=None):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]
        assert not extra_payload or isinstance(extra_payload, list), 'extra_payload is not a list %s' % type(extra_payload)

        cache = self.request_cache.add(IntroductionRequestCache(self, destination))
        destination.walk(time())

        # decide if the requested node should introduce us to someone else
        # advice = random() < 0.5 or len(community.candidates) <= 5
        advice = True

        # obtain sync range
        if not allow_sync:
            # do not request a sync when we connecting to a bootstrap candidate
            sync = None

        else:
            # flush any sync-able items left in the cache before we create a sync
            self.flush_batch_cache()
            sync = self.dispersy_claim_sync_bloom_filter(cache)
            if __debug__:
                assert sync is None or isinstance(sync, tuple), sync
                if not sync is None:
                    assert len(sync) == 5, sync
                    time_low, time_high, modulo, offset, bloom_filter = sync
                    assert isinstance(time_low, (int, long)), time_low
                    assert isinstance(time_high, (int, long)), time_high
                    assert isinstance(modulo, int), modulo
                    assert isinstance(offset, int), offset
                    assert isinstance(bloom_filter, BloomFilter), bloom_filter

                    # verify that the bloom filter is correct
                    try:
                        _, packets = self._get_packets_for_bloomfilters([[None, time_low, self.global_time if time_high == 0 else time_high, offset, modulo]], include_inactive=True).next()
                        packets = [packet for packet, in packets]

                    except OverflowError:
                        self._logger.error("time_low:  %d", time_low)
                        self._logger.error("time_high: %d", time_high)
                        self._logger.error("2**63 - 1: %d", 2 ** 63 - 1)
                        self._logger.exception("the sqlite3 python module can not handle values 2**63 or larger. "
                                               " limit time_low and time_high to 2**63-1")
                        assert False

                    # BLOOM_FILTER must be the same after transmission
                    test_bloom_filter = BloomFilter(bloom_filter.bytes, bloom_filter.functions, prefix=bloom_filter.prefix)
                    assert bloom_filter.bytes == test_bloom_filter.bytes, "problem with the long <-> binary conversion"
                    assert list(bloom_filter.not_filter((packet,) for packet in packets)) == [], "does not have all correct bits set before transmission"
                    assert list(test_bloom_filter.not_filter((packet,) for packet in packets)) == [], "does not have all correct bits set after transmission"

                    # BLOOM_FILTER must have been correctly filled
                    test_bloom_filter.clear()
                    test_bloom_filter.add_keys(packets)
                    if not bloom_filter.bytes == bloom_filter.bytes:
                        if bloom_filter.bits_checked < test_bloom_filter.bits_checked:
                            self._logger.error("%d bits in: %s",
                                               bloom_filter.bits_checked, bloom_filter.bytes.encode("HEX"))
                            self._logger.error("%d bits in: %s",
                                               test_bloom_filter.bits_checked, test_bloom_filter.bytes.encode("HEX"))
                            assert False, "does not match the given range [%d:%d] %%%d+%d packets:%d" % (time_low, time_high, modulo, offset, len(packets))

        args_list = [destination.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, advice, self._dispersy._connection_type, sync, cache.number]
        if extra_payload is not None:
            args_list += extra_payload
        args_list = tuple(args_list)

        meta_request = self.get_meta_message(u"dispersy-introduction-request")
        request = meta_request.impl(authentication=(self.my_member,),
                                    distribution=(self.global_time,),
                                    destination=(destination,),
                                    payload=args_list)

        if forward:
            if sync:
                time_low, time_high, modulo, offset, _ = sync
                self._logger.debug("%s %s sending introduction request to %s [%d:%d] %%%d+%d",
                                   self.cid.encode("HEX"), type(self), destination,
                                   time_low, time_high, modulo, offset)
            else:
                self._logger.debug("%s %s sending introduction request to %s",
                                   self.cid.encode("HEX"), type(self), destination)

            self._dispersy._forward([request])

        return request

    def send_keep_alive(self, candidate):
        """
        Request a response from a candidate. If does not answer, let it time out.

        The implementation of this mechanism uses an IntroductionRequest without any
        piggybacked data. So, we don't receive any introductions or bloomfilters etc.
        """
        assert isinstance(candidate, WalkCandidate), [type(candidate), candidate]

        cache = self.request_cache.add(IntroductionRequestCache(self, candidate))
        args_list = [candidate.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, False,
                     self._dispersy._connection_type, None, cache.number]

        meta_request = self.get_meta_message(u"dispersy-introduction-request")
        request = meta_request.impl(authentication=(self.my_member,),
                                    distribution=(self.global_time,),
                                    destination=(candidate,),
                                    payload=tuple(args_list))
        self._dispersy._forward([request])

    def _get_packets_for_bloomfilters(self, requests, include_inactive=True):
        """
        Return all packets matching a Bloomfilter request

        @param requests: A list of requests, each of them being a tuple consisting of the request,
         time_low, time_high, offset, and modulo
        @type requests: list

        @param include_inactive: When False only active packets (due to pruning) are returned
        @type include_inactive: bool

        @return: An generator yielding the original request and a generator consisting of the packets matching the request
        """

        assert isinstance(requests, list)
        assert all(isinstance(request, (list, tuple)) for request in requests)
        assert all(len(request) == 5 for request in requests)

        def get_sub_select(meta):
            direction = meta.distribution.synchronization_direction
            if direction == u"ASC":
                return u"""
 SELECT * FROM
  (SELECT sync.packet FROM sync    -- """ + meta.name + """
   WHERE sync.meta_message = ? AND sync.undone = 0 AND sync.global_time BETWEEN ? AND ? AND (sync.global_time + ?) % ? = 0
   ORDER BY sync.global_time ASC)"""

            if direction == u"DESC":
                return u"""
 SELECT * FROM
  (SELECT sync.packet FROM sync    -- """ + meta.name + """
   WHERE sync.meta_message = ? AND sync.undone = 0 AND sync.global_time BETWEEN ? AND ? AND (sync.global_time + ?) % ? = 0
   ORDER BY sync.global_time DESC)"""

            if direction == u"RANDOM":
                return u"""
 SELECT * FROM
  (SELECT sync.packet FROM sync    -- """ + meta.name + """
   WHERE sync.meta_message = ? AND sync.undone = 0 AND sync.global_time BETWEEN ? AND ? AND (sync.global_time + ?) % ? = 0
   ORDER BY RANDOM())"""

            raise RuntimeError("Unknown synchronization_direction [%d]" % direction)

        # obtain all available messages for this community
        meta_messages = sorted([meta
                                for meta
                                in self.get_meta_messages()
                                if isinstance(meta.distribution, SyncDistribution) and meta.distribution.priority > 32],
                               key=lambda meta: meta.distribution.priority,
                               reverse=True)
        # build multi-part SQL statement from meta_messages
        sql = "".join((u"SELECT * FROM (", " UNION ALL ".join(get_sub_select(meta) for meta in meta_messages), ")"))
        self._logger.debug(sql)

        for message, time_low, time_high, offset, modulo in requests:
            sql_arguments = []
            for meta in meta_messages:
                if include_inactive:
                    _time_low = time_low
                else:
                    _time_low = min(max(time_low, self.global_time - meta.distribution.pruning.inactive_threshold + 1), 2 ** 63 - 1) if isinstance(meta.distribution.pruning, GlobalTimePruning) else time_low

                sql_arguments.extend((meta.database_id, _time_low, time_high, offset, modulo))
            self._logger.debug("%s", sql_arguments)

            yield message, ((str(packet),) for packet, in self._dispersy._database.execute(sql, sql_arguments))

    def check_puncture_request(self, messages):
        for message in messages:
            if message.payload.lan_walker_address == message.candidate.sock_addr:
                yield DropMessage(message, "invalid LAN walker address [puncture herself]")
                continue

            if message.payload.wan_walker_address == message.candidate.sock_addr:
                yield DropMessage(message, "invalid WAN walker address [puncture herself]")
                continue

            if not is_valid_address(message.payload.lan_walker_address):
                yield DropMessage(message, "invalid LAN walker address [is_valid_address]")
                continue

            if not is_valid_address(message.payload.wan_walker_address):
                yield DropMessage(message, "invalid WAN walker address [is_valid_address]")
                continue

            if message.payload.wan_walker_address == self._dispersy._wan_address:
                yield DropMessage(message, "invalid WAN walker address [puncture myself]")
                continue

            if message.payload.wan_walker_address[0] == self._dispersy._wan_address[0] and message.payload.lan_walker_address == self._dispersy._lan_address:
                yield DropMessage(message, "invalid LAN walker address [puncture myself]")
                continue

            yield message

    def on_puncture_request(self, messages):
        meta_puncture = self.get_meta_message(u"dispersy-puncture")
        punctures = []
        for message in messages:
            lan_walker_address = message.payload.lan_walker_address
            wan_walker_address = message.payload.wan_walker_address
            assert is_valid_address(lan_walker_address), lan_walker_address
            assert is_valid_address(wan_walker_address), wan_walker_address

            # we are asked to send a message to a -possibly- unknown peer get the actual candidate
            # or create a dummy candidate
            sock_addr = lan_walker_address if wan_walker_address[0] == self._dispersy._wan_address[0] else wan_walker_address
            candidate = self.get_candidate(sock_addr, replace=False, lan_address=lan_walker_address)
            if candidate is None:
                # assume that tunnel is disabled
                tunnel = False
                candidate = Candidate(sock_addr, tunnel)

            punctures.append(meta_puncture.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=(self._dispersy._lan_address, self._dispersy._wan_address, message.payload.identifier)))
            self._logger.debug("%s asked us to send a puncture to %s", message.candidate, candidate)

        self._dispersy._forward(punctures)

    def check_puncture(self, messages):
        identifiers_seen = {}
        for message in messages:
            if not self.request_cache.has(u"introduction-request", message.payload.identifier):
                yield DropMessage(message, "invalid puncture identifier")
                continue

            if message.payload.identifier in identifiers_seen:
                self._logger.error("already seen this indentifier in this batch, previous candidate %s this one %s", identifiers_seen[message.payload.identifier], message.candidate)
                yield DropMessage(message, "invalid puncture identifier")
                continue

            identifiers_seen[message.payload.identifier] = message.candidate
            yield message

    def on_puncture(self, messages):
        now = time()

        for message in messages:
            cache = self.request_cache.get(u"introduction-request", message.payload.identifier)
            cache.on_puncture()

            if not (message.payload.source_lan_address == ("0.0.0.0", 0) or message.payload.source_wan_address == ("0.0.0.0", 0)):
                candidate = self.create_or_update_walkcandidate(message.candidate.sock_addr, message.payload.source_lan_address, message.payload.source_wan_address, message.candidate.tunnel, u"unknown", message.candidate)
                candidate.intro(now)

                self._logger.debug("received punture from %s", candidate)
                cache.puncture_candidate = candidate

    def create_missing_message(self, candidate, member, global_time):
        meta = self.get_meta_message(u"dispersy-missing-message")
        request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(member, [global_time]))
        self._dispersy._forward([request])

    def on_missing_message(self, messages):
        for message in messages:

            responses = []
            candidate = message.candidate
            member_database_id = message.payload.member.database_id
            for global_time in message.payload.global_times:
                try:
                    packet, = self._dispersy._database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                              (self.database_id, member_database_id, global_time)).next()
                    responses.append(str(packet))
                except StopIteration:
                    pass

            if responses:
                self._dispersy._send_packets([candidate], responses, self, "-caused by missing-message-")
            else:
                self._logger.warning('could not find missing messages for candidate %s, global_times %s',
                                     candidate, message.payload.global_times)

    def create_identity(self, sign_with_master=False, store=True, update=True):
        """
        Create a dispersy-identity message for self.my_member.

        The dispersy-identity message contains the public key of a community member.  In the future
        other data can be included in this message, however, it must consist of data that does not
        change over time as this message is only transferred on demand, and not during the sync
        phase.

        @param store: When True the messages are stored (as defined by their message distribution
         policy) in the local dispersy database.  This parameter should (almost always) be True, its
         inclusion is mostly to allow certain debugging scenarios.
        @type store: bool
        """
        assert isinstance(store, bool)
        meta = self.get_meta_message(u"dispersy-identity")

        # 13/03/12 Boudewijn: currently create_identity is either called when joining or creating a
        # self.  when creating a self self._global_time should be 1, since the master
        # member dispersy-identity message has just been created.  when joining a self
        # self._global time should be 0, since no messages have been either received or created.
        #
        # as a security feature we force that the global time on dispersy-identity messages are
        # always 2 or higher (except for master members who should get global time 1)
        global_time = self.claim_global_time()
        while global_time < 2:
            global_time = self.claim_global_time()

        message = meta.impl(authentication=(self.master_member if sign_with_master else self.my_member,),
                            distribution=(global_time,))
        self._dispersy.store_update_forward([message], store, update, False)
        # indicate that we have the identity message
        if sign_with_master:
            self.master_member.add_identity(self)
        else:
            self.my_member.add_identity(self)
        return message

    def create_missing_identity(self, candidate, dummy_member):
        """
        Create a dispersy-missing-identity message.

        To verify a message signature we need the corresponding public key from the member who made
        the signature.  When we are missing a public key, we can request a dispersy-identity message
        which contains this public key.

        """
        assert isinstance(candidate, Candidate)
        assert isinstance(dummy_member, DummyMember)

        meta = self.get_meta_message(u"dispersy-missing-identity")
        request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(dummy_member.mid,))
        self._dispersy._forward([request])

    def on_missing_identity(self, messages):
        """
        We received dispersy-missing-identity messages.

        The message contains the mid of a member.  The sender would like to obtain one or more
        associated dispersy-identity messages.

        @see: create_identity_request

        @param messages: The dispersy-identity message.
        @type messages: [Message.Implementation]
        """
        meta_id = self.get_meta_message(u"dispersy-identity").database_id
        sql_member = u"SELECT id FROM member WHERE mid = ? LIMIT 10"
        sql_packet = u"SELECT packet FROM sync WHERE community = ? AND member = ? AND meta_message = ? LIMIT 1"

        for message in messages:
            mid = message.payload.mid

            # we are assuming that no more than 10 members have the same sha1 digest.
            for member_id in [member_id for member_id, in self._dispersy._database.execute(sql_member, (buffer(mid),))]:
                packets = [str(packet) for packet, in self._dispersy._database.execute(sql_packet,
                                                                                       (self.database_id, member_id, meta_id))]

                if packets:
                    self._logger.debug("responding with %d identity messages", len(packets))
                    self._dispersy._send_packets([message.candidate], packets, self, "-caused by missing-identity-")

                else:
                    assert not message.payload.mid == self.my_member.mid, "we should always have our own dispersy-identity"
                    self._logger.warning("could not find any missing members. "
                                         " no response is sent [%s, mid:%s, cid:%s]",
                                         mid.encode("HEX"), self.my_member.mid.encode("HEX"), self.cid.encode("HEX"))

    def create_missing_sequence(self, candidate, member, message, missing_low, missing_high):
        meta = self.get_meta_message(u"dispersy-missing-sequence")
        request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(member, message, missing_low, missing_high))
        self._dispersy._forward([request])

    def on_missing_sequence(self, messages):
        """
        We received a dispersy-missing-sequence message.

        The message contains a member and a range of sequence numbers.  We will send the messages,
        up to a certain limit, in this range back to the sender.

        To limit the amount of bandwidth used we will not sent back more data after a certain amount
        has been sent.  This magic number is subject to change.

        Sometimes peers will request overlapping sequence numbers.  Only unique messages will be
        given back (per batch).  Also, if multiple sequence number ranges are requested, these
        ranges are translated into one large range, and all containing sequence numbers are given
        back.

        @param messages: dispersy-missing-sequence messages.
        @type messages: [Message.Implementation]
        """

        self._logger.debug("received %d missing-sequence message for community %d", len(messages), self.database_id)

        # we know that there are buggy clients out there that give numerous overlapping requests.
        # we will filter these to perform as few queries on the database as possible
        def merge_ranges(ranges):
            """
            Merges all ranges passed into overlapping equivalents.
            """
            # This will fail if ranges is empty, but that can't happen
            ranges = sorted([sorted(range_) for range_ in ranges])
            cur_low, cur_high = ranges[0]
            for low, high in ranges:
                if low <= cur_high:
                    cur_high = max(cur_high, high)
                else:
                    yield (cur_low, cur_high)
                    cur_low, cur_high = low, high
            yield (cur_low, cur_high)

        def fetch_packets(member_id, message_id, candidate, requests):
            # We limit the response by byte_limit bytes per incoming candidate
            byte_limit = self.dispersy_missing_sequence_response_limit

            packets = []
            for (member_id, message_id), sequences in requests.iteritems():
                if not sequences:
                    # empty set will fail min(...) and max(...)
                    continue

                self._logger.debug("fetching member:%d message:%d packets from database for %s",
                                   member_id, message_id, candidate)
                for range_min, range_max in merge_ranges(sequences):
                    for packet, in self._dispersy._database.execute(
                            u"SELECT packet FROM sync "
                            u"WHERE member = ? AND meta_message = ? AND sequence BETWEEN ? AND ? "
                            u"ORDER BY sequence",
                            (member_id, message_id, range_min, range_max)):
                        packet = str(packet)
                        packets.append(packet)

                        byte_limit -= len(packet)
                        if byte_limit <= 0:
                            self._logger.debug("Bandwidth throttle.  byte_limit:%d", byte_limit)
                            return packets
            return packets

        sources = defaultdict(lambda: defaultdict(list))
        for message in messages:
            member_id = message.payload.member.database_id
            message_id = message.payload.message.database_id
            self._logger.debug("%s requests member:%d message_id:%d range:[%d:%d]",
                               message.candidate, member_id, message_id,
                               message.payload.missing_low, message.payload.missing_high)

            sources[message.candidate][(member_id, message_id)].append((message.payload.missing_low, message.payload.missing_high))

        for candidate, member_message_requests in sources.iteritems():
            assert isinstance(candidate, Candidate), type(candidate)
            packets = fetch_packets(member_id, message_id, candidate, member_message_requests)
            if __debug__:
                # ensure we are sending the correct sequence numbers back
                for packet in packets:
                    msg = self._dispersy.convert_packet_to_message(packet, self)
                    assert msg
                    self._logger.debug("syncing %d bytes, member:%d message:%d sequence:%d to %s",
                                 len(packet),
                                 msg.authentication.member.database_id,
                                 msg.database_id,
                                 msg.distribution.sequence_number,
                                 candidate)

            self._dispersy._send_packets([candidate], packets, self, u"-sequence-")

    def create_missing_proof(self, candidate, message):
        meta = self.get_meta_message(u"dispersy-missing-proof")
        request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(message.authentication.member, message.distribution.global_time))
        self._dispersy._forward([request])

    def on_missing_proof(self, messages):
        for message in messages:
            try:
                packet, = self._dispersy._database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ? LIMIT 1",
                                                          (self.database_id, message.payload.member.database_id, message.payload.global_time)).next()

            except StopIteration:
                self._logger.warning("someone asked for proof for a message that we do not have")

            else:
                packet = str(packet)
                msg = self._dispersy.convert_packet_to_message(packet, self, verify=False)
                allowed, proofs = self.timeline.check(msg)
                if allowed and proofs:
                    self._logger.debug("we found %d packets containing proof for %s", len(proofs), message.candidate)
                    self._dispersy._send_packets([message.candidate], [proof.packet for proof in proofs], self, "-caused by missing-proof-")

                else:
                    self._logger.debug("unable to give %s missing proof.  allowed:%s.  proofs:%d packets",
                                       message.candidate, allowed, len(proofs))

    def create_authorize(self, permission_triplets, sign_with_master=False, store=True, update=True, forward=True):
        """
        Grant permissions to members in a self.

        This method will generate a message that grants the permissions in permission_triplets.
        Each item in permission_triplets contains (Member, Message, permission) where permission is
        either u'permit', u'authorize', or u'revoke'.

        By default, self.my_member is doing the authorization.  This means, that
        self.my_member must have the authorize permission for each of the permissions that she
        is authorizing.

        >>> # Authorize Bob to use Permit payload for 'some-message'
        >>> from Payload import Permit
        >>> bob = dispersy.get_member(public_key=bob_public_key)
        >>> msg = self.get_meta_message(u"some-message")
        >>> self.create_authorize(self, [(bob, msg, u'permit')])

        @param permission_triplets: The permissions that are granted.  Must be a list or tuple
         containing (Member, Message, permission) tuples.
        @type permissions_pairs: [(Member, Message, string)]

        @param sign_with_master: When True self.master_member is used to sign the authorize
         message.  Otherwise self.my_member is used.
        @type sign_with_master: bool

        @param store: When True the messages are stored (as defined by their message distribution
         policy) in the local dispersy database.  This parameter should (almost always) be True, its
         inclusion is mostly to allow certain debugging scenarios.
        @type store: bool

        @param update: When True the messages are passed to their handle_callback methods.  This
         parameter should (almost always) be True, its inclusion is mostly to allow certain
         debugging scenarios.
        @type update: bool

        @param forward: When True the messages are forwarded (as defined by their message
         destination policy) to other nodes in the community.  This parameter should (almost always)
         be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store: bool
        """
        if __debug__:
            assert isinstance(permission_triplets, (tuple, list))
            for triplet in permission_triplets:
                assert isinstance(triplet, tuple)
                assert len(triplet) == 3
                assert isinstance(triplet[0], Member)
                assert isinstance(triplet[1], Message)
                assert isinstance(triplet[2], unicode)
                assert triplet[2] in (u"permit", u"authorize", u"revoke", u"undo")

        meta = self.get_meta_message(u"dispersy-authorize")
        message = meta.impl(authentication=((self.master_member if sign_with_master else self.my_member),),
                            distribution=(self.claim_global_time(), self._claim_master_member_sequence_number(meta) if sign_with_master else meta.distribution.claim_sequence_number()),
                            payload=(permission_triplets,))

        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    def on_authorize(self, messages, initializing=False):
        """
        Process a dispersy-authorize message.

        This method is called to process a dispersy-authorize message.  This message is either
        received from a remote source or locally generated.

        @param messages: The received messages.
        @type messages: [Message.Implementation]

        @raise DropMessage: When unable to verify that this message is valid.
        @todo: We should raise a DelayMessageByProof to ensure that we request the proof for this
         message immediately.
        """
        for message in messages:
            self.timeline.authorize(message.authentication.member, message.distribution.global_time, message.payload.permission_triplets, message)

    def create_revoke(self, permission_triplets, sign_with_master=False, store=True, update=True, forward=True):
        """
        Revoke permissions from a members in a community.

        This method will generate a message that revokes the permissions in permission_triplets.
        Each item in permission_triplets contains (Member, Message, permission) where permission is
        either u'permit', u'authorize', or u'revoke'.

        By default, community.my_member is doing the revoking.  This means, that community.my_member
        must have the revoke permission for each of the permissions that she is revoking.

        >>> # Revoke the right of Bob to use Permit payload for 'some-message'
        >>> from Payload import Permit
        >>> bob = dispersy.get_member(public_key=bob_public_key)
        >>> msg = self.get_meta_message(u"some-message")
        >>> self.create_revoke(community, [(bob, msg, u'permit')])

        @param permission_triplets: The permissions that are revoked.  Must be a list or tuple
         containing (Member, Message, permission) tuples.
        @type permissions_pairs: [(Member, Message, string)]

        @param sign_with_master: When True community.master_member is used to sign the revoke
         message.  Otherwise community.my_member is used.
        @type sign_with_master: bool

        @param store: When True the messages are stored (as defined by their message distribution
         policy) in the local dispersy database.  This parameter should (almost always) be True, its
         inclusion is mostly to allow certain debugging scenarios.
        @type store: bool

        @param update: When True the messages are passed to their handle_callback methods.  This
         parameter should (almost always) be True, its inclusion is mostly to allow certain
         debugging scenarios.
        @type update: bool

        @param forward: When True the messages are forwarded (as defined by their message
         destination policy) to other nodes in the community.  This parameter should (almost always)
         be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store: bool
        """
        if __debug__:
            assert isinstance(permission_triplets, (tuple, list))
            for triplet in permission_triplets:
                assert isinstance(triplet, tuple)
                assert len(triplet) == 3
                assert isinstance(triplet[0], Member)
                assert isinstance(triplet[1], Message)
                assert isinstance(triplet[2], unicode)
                assert triplet[2] in (u"permit", u"authorize", u"revoke", u"undo")

        meta = self.get_meta_message(u"dispersy-revoke")
        message = meta.impl(authentication=((self.master_member if sign_with_master else self.my_member),),
                            distribution=(self.claim_global_time(), self._claim_master_member_sequence_number(meta) if sign_with_master else meta.distribution.claim_sequence_number()),
                            payload=(permission_triplets,))

        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    def on_revoke(self, messages, initializing=False):
        """
        Process a dispersy-revoke message.

        This method is called to process a dispersy-revoke message.  This message is either received
        from an external source or locally generated.

        @param messages: The received messages.
        @type messages: [Message.Implementation]

        @raise DropMessage: When unable to verify that this message is valid.
        @todo: We should raise a DelayMessageByProof to ensure that we request the proof for this
         message immediately.
        """
        changes = defaultdict(lambda : [self.global_time, self.global_time])

        for message in messages:
            for _, pmeta, _ in message.payload.permission_triplets:
                changes[pmeta][0] = min(changes[pmeta][0], message.distribution.global_time)

            # apply new policy setting
            self.timeline.revoke(message.authentication.member, message.distribution.global_time, message.payload.permission_triplets, message)

        if not initializing:
            for meta, globaltime_range in changes.iteritems():
                self._update_timerange(meta, globaltime_range[0], globaltime_range[1])

    def create_undo(self, message, sign_with_master=False, store=True, update=True, forward=True):
        """
        Create a dispersy-undo-own or dispersy-undo-other message to undo MESSAGE.

        A dispersy-undo-own message is created when MESSAGE.authentication.member is
        COMMUNITY.my_member and SIGN_WITH_MASTER is False.  Otherwise a dispersy-undo-other message
        is created.

        As a safeguard, when MESSAGE is already marked as undone in the database, the associated
        dispersy-undo-own or dispersy-undo-other message is returned instead of creating a new one.
        None is returned when MESSAGE is already marked as undone and neither of these messages can
        be found.
        """
        if __debug__:
            assert isinstance(message, Message.Implementation)
            assert isinstance(sign_with_master, bool)
            assert isinstance(store, bool)
            assert isinstance(update, bool)
            assert isinstance(forward, bool)
            assert message.undo_callback, "message does not allow undo"
            assert not message.name in (u"dispersy-undo-own", u"dispersy-undo-other", u"dispersy-authorize", u"dispersy-revoke"), "Currently we do NOT support undoing any of these, as it has consequences for other messages"

        # creating a second dispersy-undo for the same message is malicious behavior (it can cause
        # infinate data traffic).  nodes that notice this behavior must blacklist the offending
        # node.  hence we ensure that we did not send an undo before
        try:
            undone, = self._dispersy._database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                      (self.database_id, message.authentication.member.database_id, message.distribution.global_time)).next()

        except StopIteration:
            assert False, "The message that we want to undo does not exist.  Programming error"
            return None

        else:
            if undone:
                # already undone.  refuse to undo again but return the previous undo message
                self._logger.error("you are attempting to undo the same message twice. "
                                   "trying to return the previous undo message")
                undo_own_meta = self.get_meta_message(u"dispersy-undo-own")
                undo_other_meta = self.get_meta_message(u"dispersy-undo-other")
                for packet_id, message_id, packet in self._dispersy._database.execute(
                        u"SELECT id, meta_message, packet FROM sync WHERE community = ? AND member = ? AND meta_message IN (?, ?)",
                        (self.database_id, message.authentication.member.database_id, undo_own_meta.database_id, undo_other_meta.database_id)):
                    self._logger.debug("checking: %s", message_id)
                    msg = Packet(undo_own_meta if undo_own_meta.database_id == message_id else undo_other_meta, str(packet), packet_id).load_message()
                    if message.distribution.global_time == msg.payload.global_time:
                        return msg

                # TODO(emilon): Review this statement
                # Could not find the undo message that caused the sync.undone to be True.  The undone was probably
                # caused by changing permissions
                self._logger.error("No previous message found, returning None")
                return

            else:
                # create the undo message
                meta = self.get_meta_message(u"dispersy-undo-own" if self.my_member == message.authentication.member and not sign_with_master else u"dispersy-undo-other")
                msg = meta.impl(authentication=((self.master_member if sign_with_master else self.my_member),),
                                distribution=(self.claim_global_time(), self._claim_master_member_sequence_number(meta) if sign_with_master else meta.distribution.claim_sequence_number()),
                                payload=(message.authentication.member, message.distribution.global_time, message))

                if __debug__:
                    assert msg.distribution.global_time > message.distribution.global_time
                    allowed, _ = self.timeline.check(msg)
                    assert allowed, "create_undo was called without having the permission to undo"

                self._dispersy.store_update_forward([msg], store, update, forward)
                return msg

    def check_undo(self, messages):
        # Note: previously all MESSAGES have been checked to ensure that the sequence numbers are
        # correct.  this check takes into account the messages in the batch.  hence, if one of these
        # messages is dropped or delayed it can invalidate the sequence numbers of the other
        # messages in this batch!

        assert all(message.name in (u"dispersy-undo-own", u"dispersy-undo-other") for message in messages)

        dependencies = {}

        for message in messages:
            if message.payload.packet is None:
                # obtain the packet that we are attempting to undo
                try:
                    packet_id, message_name, packet_data = self._dispersy._database.execute(u"SELECT sync.id, meta_message.name, sync.packet FROM sync JOIN meta_message ON meta_message.id = sync.meta_message WHERE sync.community = ? AND sync.member = ? AND sync.global_time = ?",
                                                                                           (self.database_id, message.payload.member.database_id, message.payload.global_time)).next()
                except StopIteration:
                    delay = DelayMessageByMissingMessage(message, message.payload.member, message.payload.global_time)
                    dependencies[message.authentication.member.public_key] = (message.distribution.sequence_number, delay)
                    yield delay
                    continue

                message.payload.packet = Packet(self.get_meta_message(message_name), str(packet_data), packet_id)

            # ensure that the message in the payload allows undo
            if not message.payload.packet.meta.undo_callback:
                drop = DropMessage(message, "message does not allow undo")
                dependencies[message.authentication.member.public_key] = (message.distribution.sequence_number, drop)
                yield drop
                continue

            # check the timeline
            allowed, _ = message.community.timeline.check(message)
            if not allowed:
                delay = DelayMessageByProof(message)
                dependencies[message.authentication.member.public_key] = (message.distribution.sequence_number, delay)
                yield delay
                continue

            # check batch dependencies
            dependency = dependencies.get(message.authentication.member.public_key)
            if dependency:
                sequence_number, consequence = dependency
                assert sequence_number < message.distribution.sequence_number, [sequence_number, message.distribution.sequence_number]
                # MESSAGE gets the same consequence as the previous message
                self._logger.debug("apply same consequence on later message (%s on #%d applies to #%d)",
                                   consequence, sequence_number, message.distribution.sequence_number)
                yield consequence.duplicate(message)
                continue

            try:
                undone, = self._dispersy._database.execute(u"SELECT undone FROM sync WHERE id = ?", (message.payload.packet.packet_id,)).next()
            except StopIteration:
                assert False, "The conversion ensures that the packet exists in the DB.  Hence this should never occur"
                undone = 0

            if undone and message.name == u"dispersy-undo-own":
                # look for other packets we received that undid this packet
                member = message.authentication.member
                undo_own_meta = self.get_meta_message(u"dispersy-undo-own")
                for packet_id, packet in self._dispersy._database.execute(
                        u"SELECT id, packet FROM sync WHERE community = ? AND member = ? AND meta_message = ?",
                        (self.database_id, member.database_id, undo_own_meta.database_id)):

                    db_msg = Packet(undo_own_meta, str(packet), packet_id).load_message()
                    if message.payload.global_time == db_msg.payload.global_time:
                        # we've found another packet which undid this packet
                        if member == self.my_member:
                            self._logger.exception("We created a duplicate undo-own message")
                        else:
                            self._logger.warning("Someone else created a duplicate undo-own message")

                        # Reply to this peer with a higher (or equally) ranked message in case we have one
                        if db_msg.packet <= message.packet:
                            message.payload.process_undo = False
                            yield message
                            # the sender apparently does not have the lower dispersy-undo message, lets give it back
                            self._dispersy._send_packets([message.candidate], [db_msg.packet], self, db_msg.name)

                            yield DispersyDuplicatedUndo(db_msg, message)
                            break
                        else:
                            # The new message is binary lower. As we cannot delete the old one, what we do
                            # instead, is we store both and mark the message we already have as undone by the new one.
                            # To accomplish this, we yield a DispersyDuplicatedUndo so on_undo() can mark the other
                            # message as undone by the newly reveived message.
                            yield message
                            yield DispersyDuplicatedUndo(message, db_msg)
                            break
                else:
                    # did not break, hence, the message hasn't been undone more than once.
                    yield message

                # continue.  either the message was malicious or it has already been yielded
                continue

            yield message

    def on_undo(self, messages):
        """
        Undo a single message.
        """
        assert all(message.name in (u"dispersy-undo-own", u"dispersy-undo-other", u"_DUPLICATED_UNDO_") for message in messages)

        # We first need to extract the DispersyDuplicatedUndo objects from the messages list and deal with them
        real_messages = []
        parameters = []
        for message in messages:
            if isinstance(message, DispersyDuplicatedUndo):
                # Flag the higher undo message as undone by the lower one
                parameters.append((message.low_message.packet_id,
                                   self.database_id,
                                   message.high_message.authentication.member.database_id,
                                   message.high_message.distribution.global_time))

            elif isinstance(message, Message.Implementation) and message.payload.process_undo:
                # That's a normal undo message
                parameters.append((message.packet_id, self.database_id, message.payload.member.database_id, message.payload.global_time))
                real_messages.append(message)

        self._dispersy._database.executemany(u"UPDATE sync SET undone = ? "
                                             u"WHERE community = ? AND member = ? AND global_time = ?", parameters)

        for meta, sub_messages in groupby(real_messages, key=lambda x: x.payload.packet.meta):
            meta.undo_callback([(message.payload.member, message.payload.global_time, message.payload.packet) for message in sub_messages])

    def create_destroy_community(self, degree, sign_with_master=False, store=True, update=True, forward=True):
        assert isinstance(degree, unicode)
        assert degree in (u"soft-kill", u"hard-kill")

        meta = self.get_meta_message(u"dispersy-destroy-community")
        message = meta.impl(authentication=((self.master_member if sign_with_master else self.my_member),),
                            distribution=(self.claim_global_time(),),
                            payload=(degree,))

        # in this special case we need to forward the message before processing it locally.
        # otherwise the candidate table will have been cleaned and we won't have any destination
        # addresses.
        self._dispersy._forward([message])

        # now store and update without forwarding.  forwarding now will result in new entries in our
        # candidate table that we just clean.
        self._dispersy.store_update_forward([message], store, update, False)
        return message

    def on_destroy_community(self, messages):
        # epidemic spread of the destroy message
        self._dispersy._forward(messages)

        for message in messages:
            assert message.name == u"dispersy-destroy-community"
            self._logger.debug("%s", message)

            try:
                # let the community code cleanup first.
                new_classification = self.dispersy_cleanup_community(message)
            except Exception:
                continue
            assert issubclass(new_classification, Community)

            # community cleanup is done.  Now we will cleanup the dispersy database.

            if message.payload.is_soft_kill:
                # soft-kill: The community is frozen.  Dispersy will retain the data it has obtained.
                # However, no messages beyond the global-time of the dispersy-destroy-community message
                # will be accepted.  Responses to dispersy-sync messages will be send like normal.
                raise NotImplementedError()

            elif message.payload.is_hard_kill:
                # hard-kill: The community is destroyed.  Dispersy will throw away everything except the
                # dispersy-destroy-community message and the authorize chain that is required to verify
                # this message.  The community should also remove all its data and cleanup as much as
                # possible.

                # todo: this should be made more efficient.  not all dispersy-destroy-community messages
                # need to be kept.  Just the ones in the chain to authorize the message that has just
                # been received.

                identity_message_id = self.get_meta_message(u"dispersy-identity").database_id
                packet_ids = set()
                identities = set()

                # we should not remove our own dispersy-identity message
                try:
                    packet_id, = self._dispersy._database.execute(u"SELECT id FROM sync WHERE meta_message = ? AND member = ?", (identity_message_id, self.my_member.database_id)).next()
                except StopIteration:
                    pass
                else:
                    identities.add(self.my_member.public_key)
                    packet_ids.add(packet_id)

                # obtain the permission chain
                todo = [message]
                while todo:
                    item = todo.pop()

                    if not item.packet_id in packet_ids:
                        packet_ids.add(item.packet_id)

                        # ensure that we keep the identity message
                        if not item.authentication.member.public_key in identities:
                            identities.add(item.authentication.member.public_key)
                            try:
                                packet_id, = self._dispersy._database.execute(u"SELECT id FROM sync WHERE meta_message = ? AND member = ?",
                                                                             (identity_message_id, item.authentication.member.database_id)).next()
                            except StopIteration:
                                pass
                            else:
                                packet_ids.add(packet_id)

                        # get proofs required for ITEM
                        _, proofs = self._timeline.check(item)
                        todo.extend(proofs)

                # 1. cleanup the double_signed_sync table.
                self._dispersy._database.execute(u"DELETE FROM double_signed_sync WHERE sync IN (SELECT id FROM sync JOIN double_signed_sync ON sync.id = double_signed_sync.sync WHERE sync.community = ?)", (self.database_id,))

                # 2. cleanup sync table.  everything except what we need to tell others this
                # community is no longer available
                self._dispersy._database.execute(u"DELETE FROM sync WHERE community = ? AND id NOT IN (" + u", ".join(u"?" for _ in packet_ids) + ")", [self.database_id] + list(packet_ids))

            self._dispersy.reclassify_community(self, new_classification)

    def create_dynamic_settings(self, policies, sign_with_master=False, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"dispersy-dynamic-settings")
        message = meta.impl(authentication=((self.master_member if sign_with_master else self.my_member),),
                            distribution=(self.claim_global_time(), self._claim_master_member_sequence_number(meta) if sign_with_master else meta.distribution.claim_sequence_number()),
                            payload=(policies,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    def on_dynamic_settings(self, messages, initializing=False):
        assert isinstance(initializing, bool)

        changes = defaultdict(lambda : [self.global_time, self.global_time])
        for message in messages:
            self._logger.debug("received %s policy changes", len(message.payload.policies))
            for meta, policy in message.payload.policies:
                changes[meta][0] = min(changes[meta][0], message.distribution.global_time)

                # apply new policy setting
                self.timeline.change_resolution_policy(meta, message.distribution.global_time, policy, message)

        if not initializing:
            for meta, globaltime_range in changes.iteritems():
                self._update_timerange(meta, globaltime_range[0], globaltime_range[1])

    def _update_timerange(self, meta, time_low, time_high):
        execute = self._dispersy._database.execute
        executemany = self._dispersy._database.executemany

        self._logger.debug("updating %s [%d:%d]", meta.name, time_low, time_high)
        undo = []
        redo = []

        for packet_id, packet, undone in list(execute(u"SELECT id, packet, undone FROM sync WHERE meta_message = ? AND global_time BETWEEN ? AND ?",
                                                      (meta.database_id, time_low, time_high))):
            message = self._dispersy.convert_packet_to_message(str(packet), self)
            if message:
                message.packet_id = packet_id
                allowed, _ = self.timeline.check(message)
                if allowed and undone:
                    self._logger.debug("redo message %s at time %d",
                                       message.name, message.distribution.global_time)
                    redo.append(message)

                elif not (allowed or undone):
                    self._logger.debug("undo message %s at time %d",
                                       message.name, message.distribution.global_time)
                    undo.append(message)

                elif __debug__:
                    self._logger.debug("no change for message %s at time %d",
                                       message.name, message.distribution.global_time)

        if undo:
            executemany(u"UPDATE sync SET undone = 1 WHERE id = ?", ((message.packet_id,) for message in undo))
            meta.undo_callback([(message.authentication.member, message.distribution.global_time, message) for message in undo])

            # notify that global times have changed
            # meta.self.update_sync_range(meta, [message.distribution.global_time for message in undo])

        if redo:
            executemany(u"UPDATE sync SET undone = 0 WHERE id = ?", ((message.packet_id,) for message in redo))
            meta.handle_callback(redo)

    def _claim_master_member_sequence_number(self, meta):
        """
        Tries to guess the most recent sequence number used by the master member for META in
        SELF.

        This is a risky method because sequence numbers must be unique, however, we can not
        guarantee that two peers do not claim a sequence number for the master member at around the
        same time.  Unfortunately we can not overcome this problem in a distributed fashion.

        Also note that calling this method twice will give identital values.  Ensure that the
        message is updated locally before claiming another value to ensure different sequence
        numbers are used.
        """
        assert isinstance(meta.distribution, FullSyncDistribution), "currently only FullSyncDistribution allows sequence numbers"
        sequence_number, = self._dispersy._database.execute(u"SELECT COUNT(*) FROM sync WHERE member = ? AND sync.meta_message = ?",
                                                           (self.master_member.database_id, meta.database_id)).next()
        return sequence_number + 1


class HardKilledCommunity(Community):

    def initialize(self, *args, **kargs):
        super(HardKilledCommunity, self).initialize(*args, **kargs)
        destroy_message_id = self._meta_messages[u"dispersy-destroy-community"].database_id
        try:
            packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message = ? LIMIT 1", (destroy_message_id,)).next()
        except StopIteration:
            self._logger.error("unable to locate the dispersy-destroy-community message")
            self._destroy_community_packet = ""
        else:
            self._destroy_community_packet = str(packet)

    @property
    def dispersy_enable_candidate_walker(self):
        # disable candidate walker
        return False

    @property
    def dispersy_enable_candidate_walker_responses(self):
        # enable walker responses
        return True

    def initiate_conversions(self):
        # TODO we will not be able to use this conversion because the community version will not
        # match
        return [DefaultConversion(self)]

    def get_conversion_for_packet(self, packet):
        try:
            return super(HardKilledCommunity, self).get_conversion_for_packet(packet)

        except ConversionNotFoundException:
            # the dispersy version MUST BE available.  Currently we only support \x00: BinaryConversion
            if packet[0] == "\x00":
                self.add_conversion(BinaryConversion(self, packet[1]))

            # try again
            return super(HardKilledCommunity, self).get_conversion_for_packet(packet)

    def on_introduction_request(self, messages):
        if self._destroy_community_packet:
            self._dispersy._send_packets([message.candidate for message in messages], [self._destroy_community_packet],
                self, "-caused by destroy-community-")
