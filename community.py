"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from abc import ABCMeta, abstractmethod
from itertools import islice
from math import ceil
from random import random, Random, randint, shuffle
from time import time

try:
    # python 2.7 only...
    from collections import OrderedDict
except ImportError:
    from .python27_ordereddict import OrderedDict

from .bloomfilter import BloomFilter
from .candidate import WalkCandidate, BootstrapCandidate
from .conversion import BinaryConversion, DefaultConversion
from .decorator import documentation, runtime_duration_warning
from .dispersy import Dispersy
from .distribution import SyncDistribution, GlobalTimePruning
from .logger import get_logger
from .member import DummyMember, Member
from .requestcache import RequestCache
from .resolution import PublicResolution, LinearResolution, DynamicResolution
from .statistics import CommunityStatistics
from .timeline import Timeline
logger = get_logger(__name__)


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


class Community(object):
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
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(my_member, Member), type(my_member)
        assert my_member.public_key, my_member.database_id
        assert my_member.private_key, my_member.database_id
        assert dispersy.callback.is_current_thread
        master = dispersy.get_new_member(u"high")

        dispersy.database.execute(u"INSERT INTO community (master, member, classification) VALUES(?, ?, ?)", (master.database_id, my_member.database_id, cls.get_classification()))
        community_database_id = dispersy.database.last_insert_rowid

        try:
            # new community instance
            community = cls.load_community(dispersy, master, *args, **kargs)
            assert community.database_id == community_database_id

            # create the dispersy-identity for the master member
            message = community.create_dispersy_identity(sign_with_master=True)

            # create my dispersy-identity
            message = community.create_dispersy_identity()

            # authorize MY_MEMBER
            permission_triplets = []
            for message in community.get_meta_messages():
                # grant all permissions for messages that use LinearResolution or DynamicResolution
                if isinstance(message.resolution, (LinearResolution, DynamicResolution)):
                    for allowed in (u"authorize", u"revoke", u"permit"):
                        permission_triplets.append((my_member, message, allowed))

                    # ensure that undo_callback is available
                    if message.undo_callback:
                        # we do not support undo permissions for authorize, revoke, undo-own, and
                        # undo-other (yet)
                        if not message.name in (u"dispersy-authorize", u"dispersy-revoke", u"dispersy-undo-own", u"dispersy-undo-other"):
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
                        if not message.name in (u"dispersy-authorize", u"dispersy-revoke", u"dispersy-undo-own", u"dispersy-undo-other"):
                            for allowed in (u"authorize", u"revoke", u"undo"):
                                permission_triplets.append((my_member, message, allowed))

            if permission_triplets:
                community.create_dispersy_authorize(permission_triplets, sign_with_master=True, forward=False)

        except:
            # undo the insert info the database
            # TODO it might still leave unused database entries referring to the community id
            dispersy.database.execute(u"DELETE FROM community WHERE id = ?", (community_database_id,))

            # raise the exception because this shouldn't happen
            raise

        else:
            return community

    @classmethod
    def join_community(cls, dispersy, master, my_member, *args, **kargs):
        """
        Join an existing community.

        Once you have discovered an existing community, i.e. you have obtained the public master key
        from a community, you can join this community.

        Joining a community does not mean that you obtain permissions in that community, those will
        need to be granted by another member who is allowed to do so.  However, it will let you
        receive, send, and disseminate messages that do not require any permission to use.

        @param dispersy: The Dispersy instance where this community will attach itself to.
        @type dispersy: Dispersy

        @param master: The master member that identified the community that we want to join.
        @type master: DummyMember or Member

        @param my_member: The member that will be granted Permit, Authorize, and Revoke for all
         messages.
        @type my_member: Member

        @param args: optional argumets that are passed to the community constructor.
        @type args: tuple

        @param kargs: optional keyword arguments that are passed to the community constructor.
        @type args: dictionary

        @return: The created community instance.
        @rtype: Community
        """
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(master, DummyMember), type(master)
        assert isinstance(my_member, Member), type(my_member)
        assert my_member.public_key, my_member.database_id
        assert my_member.private_key, my_member.database_id
        assert dispersy.callback.is_current_thread
        logger.debug("joining %s %s", cls.get_classification(), master.mid.encode("HEX"))

        dispersy.database.execute(u"INSERT INTO community(master, member, classification) VALUES(?, ?, ?)",
                                  (master.database_id, my_member.database_id, cls.get_classification()))
        community_database_id = dispersy.database.last_insert_rowid

        try:
            # new community instance
            community = cls.load_community(dispersy, master, *args, **kargs)
            assert community.database_id == community_database_id

            # create my dispersy-identity
            community.create_dispersy_identity()

        except:
            # undo the insert info the database
            # TODO it might still leave unused database entries referring to the community id
            dispersy.database.execute(u"DELETE FROM community WHERE id = ?", (community_database_id,))

            # raise the exception because this shouldn't happen
            raise

        else:
            return community

    @classmethod
    def get_master_members(cls, dispersy):
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert dispersy.callback.is_current_thread
        logger.debug("retrieving all master members owning %s communities", cls.get_classification())
        execute = dispersy.database.execute
        return [dispersy.get_member(str(public_key)) if public_key else dispersy.get_temporary_member_from_id(str(mid))
                for mid, public_key,
                in list(execute(u"SELECT m.mid, m.public_key FROM community AS c JOIN member AS m ON m.id = c.master WHERE c.classification = ?",
                                (cls.get_classification(),)))]

    @classmethod
    def load_community(cls, dispersy, master, *args, **kargs):
        """
        Load a single community.

        Will raise a ValueError exception when cid is unavailable.

        @param master: The master member that identifies the community.
        @type master: DummyMember or Member

        @return: The community identified by master.
        @rtype: Community
        """
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(master, DummyMember), type(master)
        assert dispersy.callback.is_current_thread
        logger.debug("loading %s %s", cls.get_classification(), master.mid.encode("HEX"))
        community = cls(dispersy, master, *args, **kargs)

        # tell dispersy that there is a new community
        dispersy.attach_community(community)

        return community

    def __init__(self, dispersy, master):
        """
        Initialize a community.

        Generally a new community is created using create_community.  Or an existing community is
        loaded using load_community.  These two methods prepare and call this __init__ method.

        @param dispersy: The Dispersy instance where this community will attach itself to.
        @type dispersy: Dispersy

        @param master: The master member that identifies the community.
        @type master: DummyMember or Member
        """
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(master, DummyMember), type(master)
        assert dispersy.callback.is_current_thread
        logger.debug("initializing:  %s", self.get_classification())
        logger.debug("master member: %s %s", master.mid.encode("HEX"), "" if master.public_key else " (no public key available)")

        # Dispersy
        self._dispersy = dispersy

        # _pending_callbacks contains all id's for registered calls that should be removed when the
        # community is unloaded.  most of the time this contains all the generators that are being
        # used by the community
        self._pending_callbacks = []

        try:
            self._database_id, member_public_key, self._database_version = self._dispersy.database.execute(u"SELECT community.id, member.public_key, database_version FROM community JOIN member ON member.id = community.member WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            raise ValueError(u"Community not found in database [" + master.mid.encode("HEX") + "]")
        logger.debug("database id:   %d", self._database_id)

        self._cid = master.mid
        self._master_member = master
        self._my_member = self._dispersy.get_member(str(member_public_key))
        logger.debug("my member:     %s", self._my_member.mid.encode("HEX"))
        assert self._my_member.public_key, [self._database_id, self._my_member.database_id, self._my_member.public_key]
        assert self._my_member.private_key, [self._database_id, self._my_member.database_id, self._my_member.private_key]
        if not self._master_member.public_key and self.dispersy_enable_candidate_walker and self.dispersy_auto_download_master_member:
            self._pending_callbacks.append(self._dispersy.callback.register(self._download_master_member_identity))

        # pre-fetch some values from the database, this allows us to only query the database once
        self.meta_message_cache = {}
        for database_id, name, cluster, priority, direction in self._dispersy.database.execute(u"SELECT id, name, cluster, priority, direction FROM meta_message WHERE community = ?", (self._database_id,)):
            self.meta_message_cache[name] = {"id": database_id, "cluster": cluster, "priority": priority, "direction": direction}
        # define all available messages
        self._meta_messages = {}
        self._initialize_meta_messages()
        # cleanup pre-fetched values
        self.meta_message_cache = None

        # define all available conversions
        self._conversions = self.initiate_conversions()
        if __debug__:
            from .conversion import Conversion
            assert len(self._conversions) > 0, len(self._conversions)
            assert all(isinstance(conversion, Conversion) for conversion in self._conversions), [type(conversion) for conversion in self._conversions]

        # the global time.  zero indicates no messages are available, messages must have global
        # times that are higher than zero.
        self._global_time, = self._dispersy.database.execute(u"SELECT MAX(global_time) FROM sync WHERE community = ?", (self._database_id,)).next()
        if self._global_time is None:
            self._global_time = 0
        assert isinstance(self._global_time, (int, long))
        self._acceptable_global_time_cache = self._global_time
        self._acceptable_global_time_deadline = 0.0
        logger.debug("global time:   %d", self._global_time)

        # sync range bloom filters
        self._sync_cache = None
        self._sync_cache_skip_count = 0
        if __debug__:
            b = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate)
            logger.debug("sync bloom:    size: %d;  capacity: %d;  error-rate: %f", int(ceil(b.size // 8)), b.get_capacity(self.dispersy_sync_bloom_filter_error_rate), self.dispersy_sync_bloom_filter_error_rate)

        # assigns temporary cache objects to unique identifiers
        self._request_cache = RequestCache(self._dispersy.callback)

        # initial timeline.  the timeline will keep track of member permissions
        self._timeline = Timeline(self)
        self._initialize_timeline()

        # random seed, used for sync range
        self._random = Random(self._cid)
        self._nrsyncpackets = 0

        # Initialize all the candidate iterators
        self._candidates = OrderedDict()
        self._walked_candidates = self._iter_category(u'walk')
        self._stumbled_candidates = self._iter_category(u'stumble')
        self._introduced_candidates = self._iter_category(u'intro')
        self._walk_candidates = self._iter_categories([u'walk', u'stumble', u'intro'])
        self._bootstrap_candidates = self._iter_bootstrap()
        self._pending_callbacks.append(self._dispersy.callback.register(self._periodically_cleanup_candidates))

        # statistics...
        self._statistics = CommunityStatistics(self)

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
        logger.debug("using dummy master member")

        def on_dispersy_identity(message):
            if message and not self._master_member:
                logger.debug("%s received master member", self._cid.encode("HEX"))
                assert message.authentication.member.mid == self._master_member.mid
                self._master_member = message.authentication.member
                assert self._master_member.public_key

        delay = 2.0
        while not self._master_member.public_key:
            try:
                public_key, = self._dispersy.database.execute(u"SELECT public_key FROM member WHERE id = ?", (self._master_member.database_id,)).next()
            except StopIteration:
                pass
            else:
                if public_key:
                    logger.debug("%s found master member", self._cid.encode("HEX"))
                    self._master_member = self._dispersy.get_member(str(public_key))
                    assert self._master_member.public_key
                    break

            for candidate in islice(self.dispersy_yield_verified_candidates(), 1):
                if candidate:
                    logger.debug("%s asking for master member from %s", self._cid.encode("HEX"), candidate)
                    self._dispersy.create_missing_identity(self, candidate, self._master_member, on_dispersy_identity)

            yield delay
            delay = min(300.0, delay * 1.1)

    def _initialize_meta_messages(self):
        assert isinstance(self._meta_messages, dict)
        assert len(self._meta_messages) == 0

        # obtain dispersy meta messages
        for meta_message in self._dispersy.initiate_meta_messages(self):
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message

        # obtain community meta messages
        for meta_message in self.initiate_meta_messages():
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message

        if __debug__:
            sync_interval = 5.0
            for meta_message in self._meta_messages.itervalues():
                if isinstance(meta_message.distribution, SyncDistribution) and meta_message.batch.max_window >= sync_interval:
                    logger.warning("when sync is enabled the interval should be greater than the walking frequency.  otherwise you are likely to receive duplicate packets [%s]", meta_message.name)

    def _initialize_timeline(self):
        mapping = {}
        for name in [u"dispersy-authorize", u"dispersy-revoke", u"dispersy-dynamic-settings"]:
            try:
                meta = self.get_meta_message(name)
            except KeyError:
                logger.warning("unable to load permissions from database [could not obtain %s]", name)
            else:
                mapping[meta.database_id] = meta.handle_callback

        if mapping:
            for packet, in list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message IN (" + ", ".join("?" for _ in mapping) + ") ORDER BY global_time, packet",
                                                                mapping.keys())):
                message = self._dispersy.convert_packet_to_message(str(packet), self, verify=False)
                if message:
                    logger.debug("processing %s", message.name)
                    mapping[message.database_id]([message], initializing=True)
                else:
                    # TODO: when a packet conversion fails we must drop something, and preferably check
                    # all messages in the database again...
                    logger.error("invalid message in database [%s; %s]\n%s", self.get_classification(), self.cid.encode("HEX"), str(packet).encode("HEX"))

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

        When True is returned, the dispersy_take_step method will be called periodically.  Otherwise
        it will be ignored.  The candidate walker is enabled by default.
        """
        return True

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

    # @property
    # def dispersy_sync_bloom_filter_redundancy(self):
    #     """
    #     The number of bloom filters, each with a unique prefix, that are used to represent one sync
    #     range.

    #     The effective error rate for a sync range then becomes redundancy * error_rate.

    #     @rtype: int
    #     """
    #     return 3

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
        return True #_sync_skip_

    @property
    def dispersy_sync_cache_enable(self):
        return True #_cache_enable_

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
                logger.debug("%s] %d out of %d were part of the cached bloomfilter", self._cid.encode("HEX"), cached, len(messages))

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

                    logger.debug("%s reuse #%d (packets received: %d; %s)", self._cid.encode("HEX"), cache.times_used, cache.responses_received, hex(cache.bloom_filter._filter))
                    return cache.time_low, cache.time_high, cache.modulo, cache.offset, cache.bloom_filter

            elif self._sync_cache.times_used == 0:
                # Still no updates, gradually increment the skipping probability one notch
                logger.debug("skip:%d -> %d  received:%d", self._sync_cache_skip_count, min(self._sync_cache_skip_count + 1, self._SKIP_STEPS), self._sync_cache.responses_received)
                self._sync_cache_skip_count = min(self._sync_cache_skip_count + 1, self._SKIP_STEPS)

        if (self.dispersy_sync_skip_enable and
            self._sync_cache_skip_count and
            random() < self._SKIP_CURVE_STEPS[self._sync_cache_skip_count - 1]):
                # Lets skip this one
                logger.debug("skip: random() was <%f", self._SKIP_CURVE_STEPS[self._sync_cache_skip_count - 1])
                self._statistics.sync_bloom_skip += 1
                self._sync_cache = None
                return None

        sync = self.dispersy_sync_bloom_filter_strategy()
        if sync:
            self._sync_cache = SyncCache(*sync)
            self._sync_cache.candidate = request_cache.helper_candidate
            self._statistics.sync_bloom_new += 1
            self._statistics.sync_bloom_send += 1
            logger.debug("%s new sync bloom (%d/%d~%.2f)", self._cid.encode("HEX"), self._statistics.sync_bloom_reuse, self._statistics.sync_bloom_new, round(1.0 * self._statistics.sync_bloom_reuse / self._statistics.sync_bloom_new, 2))

        return sync

    @runtime_duration_warning(0.5)
    def dispersy_claim_sync_bloom_filter_simple(self):
        bloom = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate, prefix=chr(int(random() * 256)))
        capacity = bloom.get_capacity(self.dispersy_sync_bloom_filter_error_rate)
        global_time = self.global_time

        desired_mean = global_time / 2.0
        lambd = 1.0 / desired_mean
        time_point = global_time - int(self._random.expovariate(lambd))
        if time_point < 1:
            time_point = int(self._random.random() * global_time)

        time_low = time_point - capacity / 2
        time_high = time_low + capacity

        if time_low < 1:
            time_low = 1
            time_high = capacity
            db_high = capacity

        elif time_high > global_time - capacity:
            time_low = max(1, global_time - capacity)
            time_high = self.acceptable_global_time
            db_high = global_time

        else:
            db_high = time_high

        bloom.add_keys(str(packet) for packet, in self._dispersy.database.execute(u"SELECT sync.packet FROM sync JOIN meta_message ON meta_message.id = sync.meta_message WHERE sync.community = ? AND meta_message.priority > 32 AND NOT sync.undone AND global_time BETWEEN ? AND ?", (self._database_id, time_low, db_high)))

        if __debug__:
            import sys
            print >> sys.stderr, "Syncing %d-%d, capacity = %d, pivot = %d" % (time_low, time_high, capacity, time_low)
        return (time_low, time_high, 1, 0, bloom)

    # choose a pivot, add all items capacity to the right. If too small, add items left of pivot
    @runtime_duration_warning(0.5)
    def dispersy_claim_sync_bloom_filter_right(self):
        bloom = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate, prefix=chr(int(random() * 256)))
        capacity = bloom.get_capacity(self.dispersy_sync_bloom_filter_error_rate)

        desired_mean = self.global_time / 2.0
        lambd = 1.0 / desired_mean
        from_gbtime = self.global_time - int(self._random.expovariate(lambd))
        if from_gbtime < 1:
            from_gbtime = int(self._random.random() * self.global_time)

        # import sys
        # print >> sys.stderr, "Pivot", from_gbtime

        mostRecent = False
        if from_gbtime > 1:
            # use from_gbtime - 1 to include from_gbtime
            right, _ = self._select_and_fix(from_gbtime - 1, capacity, True)

            # we did not select enough items from right side, increase nr of items for left
            if len(right) < capacity:
                to_select = capacity - len(right)
                mostRecent = True

                left, _ = self._select_and_fix(from_gbtime, to_select, False)
                data = left + right
            else:
                data = right
        else:
            data, _ = self._select_and_fix(0, capacity, True)

        if len(data) > 0:
            if len(data) >= capacity:
                time_low = min(from_gbtime, data[0][0])

                if mostRecent:
                    time_high = self.acceptable_global_time
                else:
                    time_high = max(from_gbtime, data[-1][0])

            # we did not fill complete bloomfilter, assume we selected all items
            else:
                time_low = 1
                time_high = self.acceptable_global_time

            bloom.add_keys(str(packet) for _, packet in data)

            # print >> sys.stderr, "Syncing %d-%d, nr_packets = %d, capacity = %d, packets %d-%d"%(time_low, time_high, len(data), capacity, data[0][0], data[-1][0])

            return (time_low, time_high, 1, 0, bloom)
        return (1, self.acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    # instead of pivot + capacity, divide capacity to have 50/50 division around pivot
    @runtime_duration_warning(0.5)
    def dispersy_claim_sync_bloom_filter_50_50(self):
        bloom = BloomFilter(self.dispersy_sync_bloom_filter_bits, self.dispersy_sync_bloom_filter_error_rate, prefix=chr(int(random() * 256)))
        capacity = bloom.get_capacity(self.dispersy_sync_bloom_filter_error_rate)

        desired_mean = self.global_time / 2.0
        lambd = 1.0 / desired_mean
        from_gbtime = self.global_time - int(self._random.expovariate(lambd))
        if from_gbtime < 1:
            from_gbtime = int(self._random.random() * self.global_time)

        # import sys
        # print >> sys.stderr, "Pivot", from_gbtime

        mostRecent = False
        leastRecent = False

        if from_gbtime > 1:
            to_select = capacity / 2

            # use from_gbtime - 1 to include from_gbtime
            right, _ = self._select_and_fix(from_gbtime - 1, to_select, True)

            # we did not select enough items from right side, increase nr of items for left
            if len(right) < to_select:
                to_select = capacity - len(right)
                mostRecent = True

            left, _ = self._select_and_fix(from_gbtime, to_select, False)

            # we did not select enough items from left side
            if len(left) < to_select:
                leastRecent = True

                # increase nr of items for right if we did select enough items on right side
                if len(right) >= to_select:
                    to_select = capacity - len(right) - len(left)
                    right = right + self._select_and_fix(right[-1][0], to_select, True)[0]
            data = left + right

        else:
            data, _ = self._select_and_fix(0, capacity, True)

        if len(data) > 0:
            if len(data) >= capacity:
                if leastRecent:
                    time_low = 1
                else:
                    time_low = min(from_gbtime, data[0][0])

                if mostRecent:
                    time_high = self.acceptable_global_time
                else:
                    time_high = max(from_gbtime, data[-1][0])

            # we did not fill complete bloomfilter, assume we selected all items
            else:
                time_low = 1
                time_high = self.acceptable_global_time

            bloom.add_keys(str(packet) for _, packet in data)

            # print >> sys.stderr, "Syncing %d-%d, nr_packets = %d, capacity = %d, packets %d-%d"%(time_low, time_high, len(data), capacity, data[0][0], data[-1][0])

            return (time_low, time_high, 1, 0, bloom)
        return (1, self.acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    # instead of pivot + capacity, compare pivot - capacity and pivot + capacity to see which globaltime range is largest
    @runtime_duration_warning(0.5)
    def _dispersy_claim_sync_bloom_filter_largest(self):
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
                right, rightdata = self._select_bloomfilter_range(syncable_messages, from_gbtime - 1, capacity, True)

                # if right did not get to capacity, then we have less than capacity items in the database
                # skip left
                if right[2] == capacity:
                    left, leftdata = self._select_bloomfilter_range(syncable_messages, from_gbtime + 1, capacity, False)
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

                data, fixed = self._select_and_fix(syncable_messages, 0, capacity, True)
                if len(data) > 0 and fixed:
                    bloomfilter_range[1] = data[-1][0]
                    self._nrsyncpackets = capacity + 1

            if __debug__:
                t4 = time()

            if len(data) > 0:
                bloom.add_keys(str(packet) for _, packet in data)

                if __debug__:
                    logger.debug("%s syncing %d-%d, nr_packets = %d, capacity = %d, packets %d-%d, pivot = %d",
                                 self.cid.encode("HEX"), bloomfilter_range[0], bloomfilter_range[1], len(data), capacity, data[0][0], data[-1][0], from_gbtime)
                    logger.debug("%s took %f (fakejoin %f, rangeselect %f, dataselect %f, bloomfill, %f",
                                 self.cid.encode("HEX"), time() - t1, t2 - t1, t3 - t2, t4 - t3, time() - t4)

                return (min(bloomfilter_range[0], acceptable_global_time), min(bloomfilter_range[1], acceptable_global_time), 1, 0, bloom)

            if __debug__:
                logger.debug("%s no messages to sync", self.cid.encode("HEX"))

        elif __debug__:
            logger.debug("%s NOT syncing no syncable messages", self.cid.encode("HEX"))
        return (1, acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    # instead of pivot + capacity, compare pivot - capacity and pivot + capacity to see which globaltime range is largest
    @runtime_duration_warning(0.5)
    def _dispersy_claim_sync_bloom_filter_modulo(self):
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

            logger.debug("%s syncing %d-%d, nr_packets = %d, capacity = %d, totalnr = %d",
                         self.cid.encode("HEX"), modulo, offset, self._nrsyncpackets, capacity, self._nrsyncpackets)

            return (1, self.acceptable_global_time, modulo, offset, bloom)

        else:
            logger.debug("%s NOT syncing no syncable messages", self.cid.encode("HEX"))
        return (1, self.acceptable_global_time, 1, 0, BloomFilter(8, 0.1, prefix='\x00'))

    def _select_and_fix(self, syncable_messages, global_time, to_select, higher=True):
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

    def _select_bloomfilter_range(self, syncable_messages, global_time, to_select, higher=True):
        data, fixed = self._select_and_fix(syncable_messages, global_time, to_select, higher)

        lowerfixed = True
        higherfixed = True

        # if we selected less than to_select
        if len(data) < to_select:
            # calculate how many still remain
            to_select = to_select - len(data)
            if to_select > 25:
                if higher:
                    lowerdata, lowerfixed = self._select_and_fix(syncable_messages, global_time + 1, to_select, False)
                    data = lowerdata + data
                else:
                    higherdata, higherfixed = self._select_and_fix(syncable_messages, global_time - 1, to_select, True)
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
        # remove all pending callbacks
        for id_ in self._pending_callbacks:
            self._dispersy.callback.unregister(id_)
        self._pending_callbacks = []

        self._dispersy.detach_community(self)

    def claim_global_time(self):
        """
        Increments the current global time by one and returns this value.
        @rtype: int or long
        """
        self._global_time += 1
        logger.debug("claiming a new global time value @%d", self._global_time)
        self._check_for_pruning()
        return self._global_time

    def update_global_time(self, global_time):
        """
        Increase the local global time if the given GLOBAL_TIME is larger.
        """
        if global_time > self._global_time:
            logger.debug("updating global time %d -> %d", self._global_time, global_time)
            self._global_time = global_time
            self._check_for_pruning()

    def _check_for_pruning(self):
        """
        Check for messages that need to be pruned because the global time changed.  Should be called
        whenever self._global_time is increased.
        """
        for meta in self._meta_messages.itervalues():
            if isinstance(meta.distribution, SyncDistribution) and isinstance(meta.distribution.pruning, GlobalTimePruning):
                # TODO: some messages should support a notifier when a message is pruned
                # logger.debug("checking pruning for %s @%d", meta.name, self._global_time)
                # packets = [str(packet)
                #            for packet,
                #            in self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message = ? AND global_time <= ?",
                #                                               (meta.database_id, self._global_time - meta.distribution.pruning.prune_threshold))]
                # if packets:

                self._dispersy.database.execute(u"DELETE FROM sync WHERE meta_message = ? AND global_time <= ?",
                                                (meta.database_id, self._global_time - meta.distribution.pruning.prune_threshold))
                logger.debug("%d %s messages have been pruned", self._dispersy.database.changes, meta.name)

    def dispersy_check_database(self):
        """
        Called each time after the community is loaded and attached to Dispersy.
        """
        self._database_version = self._dispersy.database.check_community_database(self, self._database_version)

    def get_member(self, public_key):
        """
        Returns a Member instance associated with public_key.

        since we have the public_key, we can create this user when it didn't already exist.  Hence,
        this method always succeeds.

        @param public_key: The public key of the member we want to obtain.
        @type public_key: string

        @return: The Member instance associated with public_key.
        @rtype: Member

        @note: This returns -any- Member, it may not be a member that is part of this community.

        @todo: Since this method returns Members that are not specifically bound to any community,
         this method should be moved to Dispersy
        """
        logger.warning("deprecated.  please use Dispersy.get_member")
        return self._dispersy.get_member(public_key)

    def get_members_from_id(self, mid):
        """
        Returns zero or more Member instances associated with mid, where mid is the sha1 digest of a
        member public key.

        As we are using only 20 bytes to represent the actual member public key, this method may
        return multiple possible Member instances.  In this case, other ways must be used to figure
        out the correct Member instance.  For instance: if a signature or encryption is available,
        all Member instances could be used, but only one can succeed in verifying or decrypting.

        Since we may not have the public key associated to MID, this method may return an empty
        list.  In such a case it is sometimes possible to DelayPacketByMissingMember to obtain the
        public key.

        @param mid: The 20 byte sha1 digest indicating a member.
        @type mid: string

        @return: A list containing zero or more Member instances.
        @rtype: [Member]

        @note: This returns -any- Member, it may not be a member that is part of this community.

        @todo: Since this method returns Members that are not specifically bound to any community,
         this method should be moved to Dispersy
        """
        logger.warning("deprecated.  please use Dispersy.get_members_from_id")
        return self._dispersy.get_members_from_id(mid)

    def get_default_conversion(self):
        """
        Returns the default conversion (defined as the last conversion).

        Raises KeyError() when no conversions are available.
        """
        if self._conversions:
            return self._conversions[-1]

        # for backwards compatibility we will raise a KeyError when conversion isn't found
        # (previously self._conversions was a dictionary)
        logger.warning("unable to find default conversion (there are no conversions available)")
        raise KeyError()

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

        Raises KeyError(packet) when no conversion is available.
        """
        assert isinstance(packet, str), type(packet)
        for conversion in reversed(self._conversions):
            if conversion.can_decode_message(packet):
                return conversion

        # for backwards compatibility we will raise a KeyError when no conversion for PACKET is
        # found (previously self._conversions was a dictionary)
        logger.warning("unable to find conversion to decode %s in %s", packet.encode("HEX"), self._conversions)
        raise KeyError(packet)

    def get_conversion_for_message(self, message):
        """
        Returns the conversion associated with MESSAGE.

        This method returns the first available conversion that can *encode* MESSAGE, this is tested
        in reversed order using conversion.can_encode_message(MESSAGE).  Typically a conversion can
        encode a message when: the conversion knows how to encode messages with MESSAGE.name.

        Raises KeyError(message) when no conversion is available.
        """
        if __debug__:
            from .message import Message
            assert isinstance(message, (Message, Message.Implementation)), type(message)

        for conversion in reversed(self._conversions):
            if conversion.can_encode_message(message):
                return conversion

        # for backwards compatibility we will raise a KeyError when no conversion for MESSAGE is
        # found (previously self._conversions was a dictionary)
        logger.warning("unable to find conversion to encode %s in %s", message, self._conversions)
        raise KeyError(message)

    def add_conversion(self, conversion):
        """
        Add a Conversion to the Community.

        A conversion instance converts between the internal Message structure and the on-the-wire
        message.

        @param conversion: The new conversion instance.
        @type conversion: Conversion
        """
        if __debug__:
            from .conversion import Conversion
            assert isinstance(conversion, Conversion)
        self._conversions.append(conversion)

    @documentation(Dispersy.take_step)
    def dispersy_take_step(self, allow_sync):
        return self._dispersy.take_step(self, allow_sync)

    @documentation(Dispersy.get_message)
    def get_dispersy_message(self, member, global_time):
        return self._dispersy.get_message(self, member, global_time)

    @documentation(Dispersy.create_authorize)
    def create_dispersy_authorize(self, permission_triplets, sign_with_master=False, store=True, update=True, forward=True):
        return self._dispersy.create_authorize(self, permission_triplets, sign_with_master, store, update, forward)

    @documentation(Dispersy.create_revoke)
    def create_dispersy_revoke(self, permission_triplets, sign_with_master=False, store=True, update=True, forward=True):
        return self._dispersy.create_revoke(self, permission_triplets, sign_with_master, store, update, forward)

    @documentation(Dispersy.create_undo)
    def create_dispersy_undo(self, message, sign_with_master=False, store=True, update=True, forward=True):
        return self._dispersy.create_undo(self, message, sign_with_master, store, update, forward)

    @documentation(Dispersy.create_identity)
    def create_dispersy_identity(self, sign_with_master=False, store=True, update=True):
        return self._dispersy.create_identity(self, sign_with_master, store, update)

    @documentation(Dispersy.create_signature_request)
    def create_dispersy_signature_request(self, candidate, message, response_func, response_args=(), timeout=10.0, forward=True):
        return self._dispersy.create_signature_request(self, candidate, message, response_func, response_args, timeout, forward)

    @documentation(Dispersy.create_destroy_community)
    def create_dispersy_destroy_community(self, degree, sign_with_master=False, store=True, update=True, forward=True):
        return self._dispersy.create_destroy_community(self, degree, sign_with_master, store, update, forward)

    @documentation(Dispersy.create_dynamic_settings)
    def create_dispersy_dynamic_settings(self, policies, sign_with_master=False, store=True, update=True, forward=True):
        return self._dispersy.create_dynamic_settings(self, policies, sign_with_master, store, update, forward)

    @documentation(Dispersy.create_introduction_request)
    def create_introduction_request(self, candidate, allow_sync):
        return self._dispersy.create_introduction_request(self, candidate, allow_sync)

    def dispersy_on_dynamic_settings(self, messages, initializing=False):
        return self._dispersy.on_dynamic_settings(self, messages, initializing)

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

    def _iter_bootstrap(self, once=False):
        while True:
            no_result = True

            bootstrap_candidates = list(self._dispersy.bootstrap_candidates)
            for candidate in bootstrap_candidates:
                if candidate.is_eligible_for_walk(time()):
                    no_result = False
                    yield candidate

            if no_result:
                yield None

            if once:
                break

    def dispersy_yield_candidates(self):
        """
        Yields all candidates that are part of this community.

        The returned 'walk', 'stumble', and 'intro' candidates are randomised on every call and
        returned only once each.
        """
        assert all(not sock_address in self._candidates for sock_address in self._dispersy._bootstrap_candidates.iterkeys()), "none of the bootstrap candidates may be in self._candidates"

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
        assert all(not sock_address in self._candidates for sock_address in self._dispersy._bootstrap_candidates.iterkeys()), "none of the bootstrap candidates may be in self._candidates"

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
        assert all(not sock_address in self._candidates for sock_address in self._dispersy._bootstrap_candidates.iterkeys()), "none of the bootstrap candidates may be in self._candidates"

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

            r = random()
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

        assert all(not sock_address in self._candidates for sock_address in self._dispersy._bootstrap_candidates.iterkeys()), "none of the bootstrap candidates may be in self._candidates"

        from sys import maxint

        now = time()
        categories = [(maxint, None), (maxint, None), (maxint, None)]
        category_sizes = [0, 0, 0]

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

        walk, stumble, intro = [candidate for _, candidate in categories]
        while walk or stumble or intro:
            r = random()

            # 13/02/12 Boudewijn: we decrease the 1% chance to contact a bootstrap peer to .5%
            if r <= .4975:  # ~50%
                if walk:
                    logger.debug("returning [%2d:%2d:%2d walk   ] %s", category_sizes[0] , category_sizes[1], category_sizes[2], walk)
                    return walk

            elif r <= .995:  # ~50%
                if stumble or intro:
                    while True:
                        if random() <= .5:
                            if stumble:
                                logger.debug("returning [%2d:%2d:%2d stumble] %s", category_sizes[0] , category_sizes[1], category_sizes[2], stumble)
                                return stumble

                        else:
                            if intro:
                                logger.debug("returning [%2d:%2d:%2d intro  ] %s", category_sizes[0] , category_sizes[1], category_sizes[2], intro)
                                return intro

            else:  # ~.5%
                candidate = self._bootstrap_candidates.next()
                if candidate:
                    logger.debug("returning [%2d:%2d:%2d bootstr] %s", category_sizes[0] , category_sizes[1], category_sizes[2], candidate)
                    return candidate

        bootstrap_candidates = list(self._iter_bootstrap(once=True))
        shuffle(bootstrap_candidates)
        for candidate in bootstrap_candidates:
            if candidate:
                logger.debug("returning [%2d:%2d:%2d bootstr] %s", category_sizes[0] , category_sizes[1], category_sizes[2], candidate)
                return candidate

        logger.debug("no candidates or bootstrap candidates available")
        return None

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

        2. returns a bootstrap candidate from self._bootstrap_candidates, or

        3. returns an existing candidate with the same host on a different port if this candidate is
           marked as a symmetric NAT.  When replace is True, the existing candidate is moved from
           its previous sock_addr to the new sock_addr.

        4. Or returns None
        """
        # use existing (bootstrap) candidate
        candidate = self._candidates.get(sock_addr) or self._dispersy._bootstrap_candidates.get(sock_addr)
        logger.debug("existing candidate for %s:%d is %s", sock_addr[0], sock_addr[1], candidate)

        if candidate is None:
            # find matching candidate with the same host but a different port (symmetric NAT)
            for candidate in self._candidates.itervalues():
                if (candidate.connection_type == "symmetric-NAT" and
                    candidate.sock_addr[0] == sock_addr[0] and
                    candidate.lan_address in (("0.0.0.0", 0), lan_address)):
                    logger.debug("using existing candidate %s at different port %s %s", candidate, sock_addr[1], "(replace)" if replace else "(no replace)")

                    if replace:
                        # remove vote under previous key
                        self._dispersy.wan_address_unvote(candidate)

                        # replace candidate
                        del self._candidates[candidate.sock_addr]
                        lan_address, wan_address = self._dispersy.estimate_lan_and_wan_addresses(sock_addr, candidate.lan_address, candidate.wan_address)
                        candidate.sock_addr = sock_addr
                        candidate.update(candidate.tunnel, lan_address, wan_address, candidate.connection_type)
                        self._candidates[candidate.sock_addr] = candidate

                    break

            else:
                # no symmetric NAT candidate found
                candidate = None

        return candidate

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

    def add_candidate(self, candidate):
        if not isinstance(candidate, BootstrapCandidate):
            assert candidate.sock_addr not in self._dispersy._bootstrap_candidates.iterkeys(), "none of the bootstrap candidates may be in self._candidates"

            if candidate.sock_addr not in self._candidates:
                self._candidates[candidate.sock_addr] = candidate
                self._dispersy.statistics.total_candidates_discovered += 1

    def update_bootstrap_candidates(self, candidates):
        """
        Informs the community that BootstrapCandidate instances are available.

        This method will ensure that none of the self._candidates point to a known
        BootstrapCandidate.
        """
        for candidate in candidates:
            self._candidates.pop(candidate.sock_addr, None)

        assert len(set(self._candidates.iterkeys()) & set(bsc.sock_addr for bsc in self._dispersy.bootstrap_candidates)) == 0,\
                   "candidates and bootstrap candidates must be separate"

    def get_candidate_mid(self, mid):
        members = self._dispersy.get_members_from_id(mid)
        if members:
            member = members[0]

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

        # merge and remove existing candidates in favor of the new CANDIDATE
        for other in others:
            # all except for the CANDIDATE
            if not other == candidate:
                logger.warning("removing %s %s in favor of %s %s",
                               other.sock_addr, other,
                               candidate.sock_addr, candidate)
                candidate.merge(other)
                del self._candidates[other.sock_addr]
                self.add_candidate(candidate)
                self._dispersy.wan_address_unvote(other)

    def handle_missing_messages(self, messages, *classes):
        if __debug__:
            from .message import Message
            from .dispersy import MissingSomethingCache
            assert all(isinstance(message, Message.Implementation) for message in messages), [type(message) for message in messages]
            assert all(issubclass(cls, MissingSomethingCache) for cls in classes), [type(cls) for cls in classes]

        for message in messages:
            for cls in classes:
                cache = self._request_cache.pop(cls.create_identifier_from_message(message))
                if cache:
                    logger.debug("found request cache for %s", message)
                    for response_func, response_args in cache.callbacks:
                        response_func(message, *response_args)

    def _periodically_cleanup_candidates(self):
        """
        Periodically remove obsolete Candidate instances.
        """
        while True:
            yield 5 * 60.0
            self.cleanup_candidates()

    def cleanup_candidates(self):
        """
        Removes all candidates that are obsolete.

        Returns the number of candidates that were removed.
        """
        now = time()
        obsolete_candidates = [(key, candidate) for key, candidate in self._candidates.iteritems() if candidate.is_obsolete(now)]
        for key, candidate in obsolete_candidates:
            logger.debug("removing obsolete candidate %s", candidate)
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

    def dispersy_malicious_member_detected(self, member, packets):
        """
        Proof has been found that MEMBER is malicious

        @param member: The malicious member.
        @type member: Member

        @param packets: One or more packets proving that the member is malicious.  All packets must
         be associated to the same community.
        @type packets: [Packet]
        """
        pass

    def get_meta_message(self, name):
        """
        Returns the meta message by its name.

        @param name: The name of the message.
        @type name: unicode

        @return: The meta message.
        @rtype: Message

        @raise KeyError: When there is no meta message by that name.
        """
        assert isinstance(name, unicode)
        return self._meta_messages[name]

    def get_meta_messages(self):
        """
        Returns all meta messages.

        @return: The meta messages.
        @rtype: [Message]
        """
        return self._meta_messages.values()

    @abstractmethod
    def initiate_meta_messages(self):
        """
        Create the meta messages for one community instance.

        This method is called once for each community when it is created.  The resulting meta
        messages can be obtained by either get_meta_message(name) or get_meta_messages().

        To distinct the meta messages that the community provides from those that Dispersy provides,
        none of the messages may have a name that starts with 'dispersy-'.

        @return: The new meta messages.
        @rtype: [Message]
        """
        pass

    @abstractmethod
    def initiate_conversions(self):
        """
        Create the Conversion instances for this community instance.

        This method is called once for each community when it is created.  The resulting Conversion instances can be
        obtained using get_default_conversion(), get_conversion_for_packet(), and get_conversion_for_message().

        Returns a list with all Conversion instances that this community will support.  Note that the ordering of
        Conversion classes determines what the get_..._conversion_...() methods return.

        @rtype: [Conversion]
        """
        pass


class HardKilledCommunity(Community):

    def __init__(self, *args, **kargs):
        super(HardKilledCommunity, self).__init__(*args, **kargs)

        destroy_message_id = self._meta_messages[u"dispersy-destroy-community"].database_id
        try:
            packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message = ? LIMIT 1", (destroy_message_id,)).next()
        except StopIteration:
            logger.error("unable to locate the dispersy-destroy-community message")
            self._destroy_community_packet = ""
        else:
            self._destroy_community_packet = str(packet)

    def _initialize_meta_messages(self):
        super(HardKilledCommunity, self)._initialize_meta_messages()

        # replace introduction_request behaviour
        self._meta_messages[u"dispersy-introduction-request"]._handle_callback = self.dispersy_on_introduction_request

    @property
    def dispersy_enable_candidate_walker(self):
        # disable candidate walker
        return False

    @property
    def dispersy_enable_candidate_walker_responses(self):
        # enable walker responses
        return True

    def initiate_meta_messages(self):
        # there are no community messages
        return []

    def initiate_conversions(self):
        # TODO we will not be able to use this conversion because the community version will not
        # match
        return [DefaultConversion(self)]

    def get_conversion_for_packet(self, packet):
        try:
            return super(HardKilledCommunity, self).get_conversion_for_packet(packet)

        except KeyError:
            # the dispersy version MUST BE available.  Currently we only support \x00: BinaryConversion
            if packet[0] == "\x00":
                self.add_conversion(BinaryConversion(self, packet[1]))

            # try again
            return super(HardKilledCommunity, self).get_conversion_for_packet(packet)

    def dispersy_on_introduction_request(self, messages):
        if self._destroy_community_packet:
            self._dispersy.statistics.dict_inc(self._dispersy.statistics.outgoing, u"-destroy-community")
            self._dispersy.endpoint.send([message.candidate for message in messages], [self._destroy_community_packet])
