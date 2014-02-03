"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from abc import ABCMeta, abstractmethod
from collections import defaultdict
from itertools import islice, groupby
from math import ceil
from random import random, Random, randint, shuffle
from time import time

from .authentication import NoAuthentication, MemberAuthentication, DoubleMemberAuthentication
from .bloomfilter import BloomFilter
from .cache import (SignatureRequestCache, IntroductionRequestCache, MissingMemberCache, MissingMessageCache, MissingSomethingCache,
                    MissingLastMessageCache, MissingProofCache, MissingSequenceOverviewCache, MissingSequenceCache)
from .candidate import Candidate, WalkCandidate, BootstrapCandidate
from .conversion import BinaryConversion, DefaultConversion, Conversion
from .decorator import documentation, runtime_duration_warning, attach_runtime_statistics
from .destination import CommunityDestination, CandidateDestination
from .dispersy import Dispersy
from .distribution import SyncDistribution, GlobalTimePruning, LastSyncDistribution, DirectDistribution, FullSyncDistribution
from .logger import get_logger
from .member import DummyMember, Member
from .message import (BatchConfiguration, Message, Packet, DropMessage, DelayMessageByProof,
                      DelayMessageByMissingMessage, DropPacket, DelayPacket, DelayMessage)
from .payload import (AuthorizePayload, RevokePayload, UndoPayload, DestroyCommunityPayload, DynamicSettingsPayload,
                      IdentityPayload, MissingIdentityPayload, IntroductionRequestPayload, IntroductionResponsePayload,
                      PunctureRequestPayload, PuncturePayload, MissingMessagePayload, MissingLastMessagePayload,
                      MissingSequencePayload, MissingProofPayload, SignatureRequestPayload, SignatureResponsePayload)
from .requestcache import RequestCache
from .resolution import PublicResolution, LinearResolution, DynamicResolution
from .statistics import CommunityStatistics
from .timeline import Timeline


try:
    # python 2.7 only...
    from collections import OrderedDict
except ImportError:
    from .python27_ordereddict import OrderedDict


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
            message = community.create_identity(sign_with_master=True)

            # create my dispersy-identity
            message = community.create_identity()

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
                community.create_authorize(permission_triplets, sign_with_master=True, forward=False)

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
            community.create_identity()

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

        # batch caching incoming packets
        self._batch_cache = {}

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

        # obtain meta messages
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

        When True is returned, the take_step method will be called periodically.  Otherwise
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

        sync = self.dispersy_sync_bloom_filter_strategy(request_cache)
        if sync:
            self._sync_cache = SyncCache(*sync)
            self._sync_cache.candidate = request_cache.helper_candidate
            self._statistics.sync_bloom_new += 1
            self._statistics.sync_bloom_send += 1
            logger.debug("%s new sync bloom (%d/%d~%.2f)", self._cid.encode("HEX"), self._statistics.sync_bloom_reuse, self._statistics.sync_bloom_new, round(1.0 * self._statistics.sync_bloom_reuse / self._statistics.sync_bloom_new, 2))

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

            logger.debug("%s syncing %d-%d, nr_packets = %d, capacity = %d, totalnr = %d",
                         self.cid.encode("HEX"), modulo, offset, self._nrsyncpackets, capacity, self._nrsyncpackets)

            return (1, self.acceptable_global_time, modulo, offset, bloom)

        else:
            logger.debug("%s NOT syncing no syncable messages", self.cid.encode("HEX"))
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

    def take_step(self, allow_sync):
        if self.cid in self._dispersy._communities:
            candidate = self.dispersy_get_walk_candidate()
            if candidate:
                logger.debug("%s %s taking step towards %s", self.cid.encode("HEX"), self.get_classification(), candidate)
                self.create_introduction_request(candidate, allow_sync)
                return True
            else:
                logger.debug("%s %s no candidate to take step", self.cid.encode("HEX"), self.get_classification())
                return False

    @documentation(Dispersy.get_message)
    def get_dispersy_message(self, member, global_time):
        return self._dispersy.get_message(self, member, global_time)

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

        from sys import maxsize

        now = time()
        categories = [(maxsize, None), (maxsize, None), (maxsize, None)]
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
                    logger.debug("returning [%2d:%2d:%2d walk   ] %s", category_sizes[0], category_sizes[1], category_sizes[2], walk)
                    return walk

            elif r <= .995:  # ~50%
                if stumble or intro:
                    while True:
                        if random() <= .5:
                            if stumble:
                                logger.debug("returning [%2d:%2d:%2d stumble] %s", category_sizes[0], category_sizes[1], category_sizes[2], stumble)
                                return stumble

                        else:
                            if intro:
                                logger.debug("returning [%2d:%2d:%2d intro  ] %s", category_sizes[0], category_sizes[1], category_sizes[2], intro)
                                return intro

            else:  # ~.5%
                candidate = self._bootstrap_candidates.next()
                if candidate:
                    logger.debug("returning [%2d:%2d:%2d bootstr] %s", category_sizes[0], category_sizes[1], category_sizes[2], candidate)
                    return candidate

        bootstrap_candidates = list(self._iter_bootstrap(once=True))
        shuffle(bootstrap_candidates)
        for candidate in bootstrap_candidates:
            if candidate:
                logger.debug("returning [%2d:%2d:%2d bootstr] %s", category_sizes[0], category_sizes[1], category_sizes[2], candidate)
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
                        self._candidates[candidate.sock_addr] = candidate = self.create_candidate(sock_addr, candidate.tunnel, lan_address, wan_address, candidate.connection_type)
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
            assert isinstance(candidate, WalkCandidate), type(candidate)
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

        assert len(set(self._candidates.iterkeys()) & set(bsc.sock_addr for bsc in self._dispersy.bootstrap_candidates)) == 0, \
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
                self._dispersy.wan_address_unvote(other)
        self.add_candidate(candidate)

    def handle_missing_messages(self, messages, *classes):
        if __debug__:
            from .message import Message
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
                    self.on_missing_proof),

            # when we have a reference to a LastSyncDistribution that we do not have.  a
            # reference consists of the self identifier and the member identifier
            Message(self, u"dispersy-missing-last-message",
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    MissingLastMessagePayload(),
                    self._generic_timeline_check,
                    self.on_missing_last_message),
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
                    yield DelayMessageByProof(message)

    def on_incoming_packets(self, packets, cache=True, timestamp=0.0):
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

        messages = []
        for message_type, iterator in groupby(packets, key=lambda tup: tup[1][22]):
            cur_packets = list(iterator)
            # find associated conversion
            try:
                # TODO(emilon): just have a function that gets a packet type byte
                conversion = self.get_conversion_for_packet(cur_packets[0][1])
                meta = conversion.decode_meta_message(cur_packets[0][1])
                batch = [(self.get_candidate(candidate.sock_addr) or candidate, packet, conversion)
                         for candidate, packet in cur_packets]
                if meta.batch.enabled and cache:
                    if meta in self._batch_cache:
                        task_identifier, current_timestamp, current_batch = self._batch_cache[meta]
                        current_batch.extend(batch)
                        logger.debug("adding %d %s messages to existing cache", len(batch), meta.name)
                    else:
                        # TODO(emilon): add it to the pending callbacks
                        task_identifier = self._dispersy._callback.register(self._on_batch_cache_timeout, (meta,), delay=meta.batch.max_window)
                        self._batch_cache[meta] = (task_identifier, timestamp, batch)
                        logger.debug("new cache with %d %s messages (batch window: %d)", len(batch), meta.name, meta.batch.max_window)
                else:
                    self._on_batch_cache(meta, batch)
            except KeyError:
                for candidate, packet in cur_packets:
                    logger.warning("drop a %d byte packet (received packet for unknown conversion) from %s", len(packet), candidate)
                self._dispersy._statistics.dict_inc(self._statistics.drop, "_convert_packets_into_batch:unknown conversion", len(cur_packets))
                self._dispersy._statistics.drop_count += len(cur_packets)

    def _on_batch_cache_timeout(self, meta):
        """
        Start processing a batch of messages once the cache timeout occurs.

        This method is called meta.batch.max_window seconds after the first message in this batch
        arrived.  All messages in this batch have been 'cached' together in self._batch_cache[meta].
        Hopefully the delay caused the batch to collect as many messages as possible.
        """
        assert isinstance(meta, Message)
        assert meta in self._batch_cache

        _, _, batch = self._batch_cache.pop(meta)
        logger.debug("processing %sx %s batched messages", len(batch), meta.name)

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
        assert all(len(x) == 3 for x in batch)

        for candidate, packet, conversion in batch:
            assert isinstance(candidate, Candidate)
            assert isinstance(packet, str)
            assert isinstance(conversion, Conversion)

            try:
                # convert binary data to internal Message
                messages.append(conversion.decode_message(LoopbackCandidate() if candidate is None else candidate, packet))

            except DropPacket as exception:
                logger.warning("drop a %d byte packet (%s) from %s", len(packet), exception, candidate)
                self._dispersy._statistics.dict_inc(self._dispersy._statistics.drop, "_convert_batch_into_messages:%s" % exception)
                self._dispersy._statistics.drop_count += 1

            except DelayPacket as delay:
                logger.debug("delay a %d byte packet (%s) from %s", len(packet), delay, candidate)
                if delay.create_request(candidate, packet):
                    self._dispersy._statistics.delay_send += 1
                self._dispersy._statistics.dict_inc(self._dispersy._statistics.delay, "_convert_batch_into_messages:%s" % delay)
                self._dispersy._statistics.delay_count += 1

        assert all(isinstance(message, Message.Implementation) for message in messages), "_convert_batch_into_messages must return only Message.Implementation instances"
        assert all(message.meta == meta for message in messages), "All Message.Implementation instances must be in the same batch"
        logger.debug("%d %s messages after conversion", len(messages), meta.name)

        # handle the incoming messages
        if messages:
            self.on_messages(messages)

    def purge_batch_cache(self):
        """
        Remove all batches currently scheduled.
        """
        # remove any items that are left in the cache
        for task_identifier, _, _ in self._batch_cache.itervalues():
            self._callback.unregister(task_identifier)
        self._batch_cache.clear()

    def flush_batch_cache(self):
        """
        Process all pending batches with a sync distribution.
        """
        flush_list = [(meta, tup) for meta, tup in
                      self._batch_cache.iteritems() if isinstance(meta.distribution, SyncDistribution)]
        for meta, (task_identifier, timestamp, batch) in flush_list:
            logger.debug("flush cached %dx %s messages (id: %s)", len(batch), meta.name, task_identifier)
            self._dispersy._callback.unregister(task_identifier)
            self._on_batch_cache_timeout(meta)

    def on_messages(self, messages):
        """
        Process one batch of messages.

        This method is called to process one or more Message.Implementation instances that all have
        the same meta message.  This occurs when new packets are received, to attempt to process
        previously delayed messages, or when a member explicitly creates a message to process.  The
        last option should only occur for debugging purposes.

        The messages are processed with the following steps:

         1. Messages created by a member in our blacklist are droped.

         2. Messages that are old or duplicate, based on their distribution policy, are dropped.

         3. The meta.check_callback(...) is used to allow messages to be dropped or delayed.

         4. Messages are stored, based on their distribution policy.

         5. The meta.handle_callback(...) is used to process the messages.

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
                logger.debug("%s delay %s (%s)", message.delayed.candidate, message.delayed, message)

                if message.create_request():
                    self._dispersy._statistics.delay_send += 1
                self._dispersy._statistics.dict_inc(self._dispersy._statistics.delay, "om_message_batch:%s" % message.delayed)
                self._dispersy._statistics.delay_count += 1
                return False

            elif isinstance(message, DropMessage):
                logger.debug("%s drop: %s (%s)", message.dropped.candidate, message.dropped.name, message)
                self._dispersy._statistics.dict_inc(self._dispersy._statistics.drop, "on_message_batch:%s" % message)
                self._dispersy._statistics.drop_count += 1
                return False

            else:
                return True

        meta = messages[0].meta
        debug_count = len(messages)
        debug_begin = time()

        # drop all duplicate or old messages
        assert type(meta.distribution) in self._dispersy._check_distribution_batch_map
        messages = list(self._dispersy._check_distribution_batch_map[type(meta.distribution)](messages))
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
            messages = list(meta.check_callback(messages))
        except:
            logger.exception("exception during check_callback for %s", meta.name)
            return 0
        # TODO(emilon): fixh _disp_check_modification in channel/community.py (tribler) so we can make a proper assert out of this.
        assert len(messages) >= 0  # may return zero messages
        assert all(isinstance(message, (Message.Implementation, DropMessage, DelayMessage)) for message in messages)

        if len(messages) == 0:
            logger.warning("%s yielded zero messages, drop, or delays.  This is allowed but likely to be an error.", meta.check_callback)

        # handle/remove DropMessage and DelayMessage instances
        messages = [message for message in messages if _filter_fail(message)]
        if not messages:
            return 0

        logger.debug("in... %d %s messages from %s", len(messages), meta.name, " ".join(str(candidate) for candidate in set(message.candidate for message in messages)))

        # store to disk and update locally
        if self._dispersy.store_update_forward(messages, True, True, False):

            self._dispersy._statistics.dict_inc(self._dispersy._statistics.success, meta.name, len(messages))
            self._dispersy._statistics.success_count += len(messages)

            # tell what happened
            debug_end = time()
            if debug_end - debug_begin > 1.0:
                logger.warning("handled %d/%d %.2fs %s messages (with %fs cache window)", len(messages), debug_count, (debug_end - debug_begin), meta.name, meta.batch.max_window)
            else:
                logger.debug("handled %d/%d %.2fs %s messages (with %fs cache window)", len(messages), debug_count, (debug_end - debug_begin), meta.name, meta.batch.max_window)

            # return the number of messages that were correctly handled (non delay, duplicates, etc)
            return len(messages)

        return 0

    def on_identity(self, messages):
        """
        We received a dispersy-identity message.
        """
        for message in messages:
            # get cache object linked to this request and stop timeout from occurring
            cache = self.request_cache.pop(MissingMemberCache.create_identifier(message.authentication.member))
            if cache:
                for func, args in cache.callbacks:
                    func(message, *args)

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
            logger.debug("%s", message)
            self.timeline.authorize(message.authentication.member, message.distribution.global_time, message.payload.permission_triplets, message)

        # this might be a response to a dispersy-missing-proof or dispersy-missing-sequence
        self.handle_missing_messages(messages, MissingProofCache, MissingSequenceCache)

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
        for message in messages:
            self.timeline.revoke(message.authentication.member, message.distribution.global_time, message.payload.permission_triplets, message)

        # this might be a response to a dispersy-missing-sequence
        self.handle_missing_messages(messages, MissingSequenceCache)

    def check_signature_request(self, messages):
        assert isinstance(messages[0].meta.authentication, NoAuthentication)
        for message in messages:
            # we can not timeline.check this message because it uses the NoAuthentication policy

            # submsg contains the double signed message (that currently contains -no- signatures)
            submsg = message.payload.message

            has_private_member = False
            try:
                for is_signed, member in submsg.authentication.signed_members:
                    # security: do NOT allow to accidentally sign with master member.
                    if member == self.master_member:
                        raise DropMessage(message, "You may never ask for a master member signature")

                    # is this signature missing, and could we provide it
                    if not is_signed and member.private_key:
                        has_private_member = True
                        break
            except DropMessage as exception:
                yield exception
                continue

            # we must be one of the members that needs to sign
            if not has_private_member:
                yield DropMessage(message, "Nothing to sign")
                continue

            # we can not timeline.check the submessage because it uses the DoubleMemberAuthentication policy
            # the message that we are signing must be valid according to our timeline
            # if not message.community.timeline.check(submsg):
            # raise DropMessage("Does not fit timeline")

            # allow message
            yield message

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

        If we can add multiple signatures, i.e. we have the private keys for both the message
        creator and the second member, the allow_signature_func is called only once but multiple
        signatures will be appended.

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
            submsg = message.payload.message.authentication.allow_signature_func(message.payload.message)
            assert submsg is None or isinstance(submsg, Message.Implementation), type(submsg)
            if submsg:
                responses.append(meta.impl(distribution=(self.global_time,),
                                           destination=(message.candidate,),
                                           payload=(message.payload.identifier, submsg)))

        if responses:
            # TODO(emilon): Is this right? (quick hack while moving it away from dispersy.py)
            self.dispersy._forward(responses)

    def check_signature_response(self, messages):
        unique = set()

        for message in messages:
            cache = self.request_cache.get(SignatureRequestCache.create_identifier(message.payload.identifier))
            if not cache:
                yield DropMessage(message, "invalid response identifier")
                continue

            if cache.identifier in unique:
                yield DropMessage(message, "duplicate identifier in batch")
                continue

            old_submsg = cache.request.payload.message
            new_submsg = message.payload.message

            if not old_submsg.meta == new_submsg.meta:
                yield DropMessage(message, "meta message may not change")
                continue

            if not old_submsg.authentication.member == new_submsg.authentication.member:
                yield DropMessage(message, "first member may not change")
                continue

            if not old_submsg.distribution.global_time == new_submsg.distribution.global_time:
                yield DropMessage(message, "global time may not change")
                continue

            unique.add(cache.identifier)
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
            cache = self.request_cache.pop(SignatureRequestCache.create_identifier(message.payload.identifier))

            old_submsg = cache.request.payload.message
            new_submsg = message.payload.message

            old_body = old_submsg.packet[:len(old_submsg.packet) - sum([member.signature_length for member in old_submsg.authentication.members])]
            new_body = new_submsg.packet[:len(new_submsg.packet) - sum([member.signature_length for member in new_submsg.authentication.members])]

            result = cache.response_func(cache, new_submsg, old_body != new_body, *cache.response_args)
            assert isinstance(result, bool), "RESPONSE_FUNC must return a boolean value!  True to accept the proposed message, False to reject %s %s" % (type(cache), str(cache.response_func))
            if result:
                # add our own signatures and we can handle the message
                for signature, member in new_submsg.authentication.signed_members:
                    if not signature and member.private_key:
                        new_submsg.authentication.set_signature(member, member.sign(new_body))

                assert new_submsg.authentication.is_signed
                self.store_update_forward([new_submsg], True, True, True)

    def check_introduction_request(self, messages):
        """
        We received a dispersy-introduction-request message.
        """
        for message in messages:
            # 25/01/12 Boudewijn: during all DAS2 NAT node314 often sends requests to herself.  This
            # results in more candidates (all pointing to herself) being added to the candidate
            # list.  This converges to only sending requests to herself.  To prevent this we will
            # drop all requests that have an outstanding identifier.  This is not a perfect
            # solution, but the change that two nodes select the same identifier and send requests
            # to each other is relatively small.
            # 30/10/12 Niels: additionally check if both our lan_addresses are the same. They should
            # be if we're sending it to ourself. Not checking wan_address as that is subject to change.
            if self.request_cache.has(IntroductionRequestCache.create_identifier(message.payload.identifier)) and \
                    self._dispersy._lan_address == message.payload.source_lan_address:
                logger.debug("dropping dispersy-introduction-request, this identifier is already in use.")
                yield DropMessage(message, "Duplicate identifier from %s (most likely received from our self)" % str(message.candidate))
                continue

            logger.debug("accepting dispersy-introduction-request from %s", message.candidate)
            yield message

    def on_introduction_request(self, messages):
        meta_introduction_response = self.get_meta_message(u"dispersy-introduction-response")
        meta_puncture_request = self.get_meta_message(u"dispersy-puncture-request")
        responses = []
        requests = []
        now = time()
        self._dispersy._statistics.walk_advice_incoming_request += len(messages)

        #
        # make all candidates available for introduction
        #
        for message in messages:
            candidate = self.get_walkcandidate(message)
            message._candidate = candidate
            if not candidate:
                continue

            payload = message.payload

            # apply vote to determine our WAN address
            self._dispersy.wan_address_vote(payload.destination_address, candidate)

            # until we implement a proper 3-way handshake we are going to assume that the creator of
            # this message is associated to this candidate
            candidate.associate(message.authentication.member)

            # update sender candidate
            source_lan_address, source_wan_address = self._dispersy.estimate_lan_and_wan_addresses(candidate.sock_addr, payload.source_lan_address, payload.source_wan_address)
            candidate.update(candidate.tunnel, source_lan_address, source_wan_address, payload.connection_type)
            candidate.stumble(now)
            self.add_candidate(candidate)

            self.filter_duplicate_candidate(candidate)
            logger.debug("received introduction request from %s", candidate)

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
                    logger.debug("no candidates available to introduce")
            else:
                introduced = None

            if introduced:
                logger.debug("telling %s that %s exists %s", candidate, introduced, type(self))
                self._dispersy._statistics.walk_advice_outgoing_response += 1

                # create introduction response
                responses.append(meta_introduction_response.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=(candidate.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, introduced.lan_address, introduced.wan_address, self._dispersy._connection_type, introduced.tunnel, payload.identifier)))

                # create puncture request
                requests.append(meta_puncture_request.impl(distribution=(self.global_time,), destination=(introduced,), payload=(source_lan_address, source_wan_address, payload.identifier)))

            else:
                logger.debug("responding to %s without an introduction %s", candidate, type(self))

                none = ("0.0.0.0", 0)
                responses.append(meta_introduction_response.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=(candidate.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, none, none, self._dispersy._connection_type, False, payload.identifier)))

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
                        logger.debug("bandwidth throttle")
                        break

                if packets:
                    logger.debug("syncing %d packets (%d bytes) to %s", len(packets), sum(len(packet) for packet in packets), message.candidate)
                    self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-sync-", len(packets))
                    self._dispersy._endpoint.send([message.candidate], packets)

    def check_undo(self, messages):
        # Note: previously all MESSAGES have been checked to ensure that the sequence numbers are
        # correct.  this check takes into account the messages in the batch.  hence, if one of these
        # messages is dropped or delayed it can invalidate the sequence numbers of the other
        # messages in this batch!

        assert all(message.name in (u"dispersy-undo-own", u"dispersy-undo-other") for message in messages)

        dependencies = {}

        for message in messages:
            if message.payload.packet is None:
                # message.resume can be many things.  for example: another undo message (when delayed by
                # missing sequence) or a message (when delayed by missing message).
                if (message.resume and
                    message.resume.community.database_id == self.database_id and
                    message.resume.authentication.member.database_id == message.payload.member.database_id and
                        message.resume.distribution.global_time == message.payload.global_time):
                    logger.debug("using resume cache")
                    message.payload.packet = message.resume

                else:
                    # obtain the packet that we are attempting to undo
                    try:
                        packet_id, message_name, packet_data = self._dispersy._database.execute(u"SELECT sync.id, meta_message.name, sync.packet FROM sync JOIN meta_message ON meta_message.id = sync.meta_message WHERE sync.community = ? AND sync.member = ? AND sync.global_time = ?",
                                                                                               (self.database_id, message.payload.member.database_id, message.payload.global_time)).next()
                    except StopIteration:
                        delay = DelayMessageByMissingMessage(message, message.payload.member, message.payload.global_time)
                        dependencies[message.authentication.member.public_key] = (message.distribution.sequence_number, delay)
                        yield delay
                        continue

                    logger.debug("using packet from database")
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
                logger.debug("apply same consequence on later message (%s on #%d applies to #%d)", consequence, sequence_number, message.distribution.sequence_number)
                yield consequence.duplicate(message)
                continue

            try:
                undone, = self._dispersy._database.execute(u"SELECT undone FROM sync WHERE id = ?", (message.payload.packet.packet_id,)).next()
            except StopIteration:
                assert False, "The conversion ensures that the packet exists in the DB.  Hence this should never occur"
                undone = 0

            if undone and message.name == u"dispersy-undo-own":
                # the dispersy-undo-own message is a curious beast.  Anyone is allowed to create one
                # (regardless of the community settings) and everyone is responsible to propagate
                # these messages.  A malicious member could create an infinite number of
                # dispersy-undo-own messages and thereby take down a community.
                #
                # to prevent this, we allow only one dispersy-undo-own message per message.  When we
                # detect a second message, the member is declared to be malicious and blacklisted.
                # The proof of being malicious is forwarded to other nodes.  The malicious node is
                # now limited to creating only one dispersy-undo-own message per message that she
                # creates.  And that can be limited by revoking her right to create messages.

                # search for the second offending dispersy-undo message
                member = message.authentication.member
                undo_own_meta = self.get_meta_message(u"dispersy-undo-own")
                for packet_id, packet in self._dispersy._database.execute(u"SELECT id, packet FROM sync WHERE community = ? AND member = ? AND meta_message = ?",
                                                                         (self.database_id, member.database_id, undo_own_meta.database_id)):
                    msg = Packet(undo_own_meta, str(packet), packet_id).load_message()
                    if message.payload.global_time == msg.payload.global_time:
                        logger.warning("detected malicious behavior")
                        self._dispersy.declare_malicious_member(member, [msg, message])

                        # the sender apparently does not have the offending dispersy-undo message, lets give
                        self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, msg.name)
                        self._dispersy._endpoint.send([message.candidate], [msg.packet])

                        if member == self.my_member:
                            logger.error("fatal error.  apparently we are malicious")

                        yield DropMessage(message, "the message proves that the member is malicious")
                        break

                else:
                    # did not break, hence, the message is not malicious.  more than one members
                    # undid this message
                    yield message

                # continue.  either the message was malicious or it has already been yielded
                continue

            yield message

    def on_undo(self, messages):
        """
        Undo a single message.
        """
        assert all(message.name in (u"dispersy-undo-own", u"dispersy-undo-other") for message in messages)

        self._dispersy._database.executemany(u"UPDATE sync SET undone = ? WHERE community = ? AND member = ? AND global_time = ?",
                                            ((message.packet_id, self.database_id, message.payload.member.database_id, message.payload.global_time) for message in messages))
        for meta, iterator in groupby(messages, key=lambda x: x.payload.packet.meta):
            sub_messages = list(iterator)
            meta.undo_callback([(message.payload.member, message.payload.global_time, message.payload.packet) for message in sub_messages])

            # notify that global times have changed
            # community.update_sync_range(meta, [message.payload.global_time for message in sub_messages])

        # this might be a response to a dispersy-missing-sequence
        self.handle_missing_messages(messages, MissingSequenceCache)

    def check_introduction_response(self, messages):
        for message in messages:
            if not self.request_cache.has(IntroductionRequestCache.create_identifier(message.payload.identifier)):
                self._statistics.walk_invalid_response_identifier += 1
                yield DropMessage(message, "invalid response identifier")
                continue

            # check introduced LAN address, if given
            if not message.payload.lan_introduction_address == ("0.0.0.0", 0):
                if not self._dispersy.is_valid_address(message.payload.lan_introduction_address):
                    yield DropMessage(message, "invalid LAN introduction address [is_valid_address]")
                    continue

            # check introduced WAN address, if given
            if not message.payload.wan_introduction_address == ("0.0.0.0", 0):
                if not self._dispersy.is_valid_address(message.payload.wan_introduction_address):
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

            yield message

    def on_introduction_response(self, messages):
        now = time()

        for message in messages:
            payload = message.payload

            # modify either the senders LAN or WAN address based on how we perceive that node
            source_lan_address, source_wan_address = self._dispersy.estimate_lan_and_wan_addresses(message.candidate.sock_addr, payload.source_lan_address, payload.source_wan_address)

            if isinstance(message.candidate, WalkCandidate):
                candidate = message.candidate
                candidate.update(candidate.tunnel, source_lan_address, source_wan_address, payload.connection_type)
            else:
                candidate = self.create_candidate(message.candidate.sock_addr, message.candidate.tunnel, source_lan_address, source_wan_address, payload.connection_type)

            # until we implement a proper 3-way handshake we are going to assume that the creator of
            # this message is associated to this candidate
            candidate.associate(message.authentication.member)
            candidate.walk_response(now)
            self.filter_duplicate_candidate(candidate)
            logger.debug("introduction response from %s", candidate)

            # apply vote to determine our WAN address
            self._dispersy.wan_address_vote(payload.destination_address, candidate)

            # increment statistics only the first time
            self._dispersy._statistics.walk_success += 1
            if isinstance(candidate, BootstrapCandidate):
                self._dispersy._statistics.walk_bootstrap_success += 1
            self._dispersy._statistics.dict_inc(self._dispersy._statistics.incoming_introduction_response, candidate.sock_addr)

            # get cache object linked to this request and stop timeout from occurring
            cache = self.request_cache.get(IntroductionRequestCache.create_identifier(message.payload.identifier))
            cache.on_introduction_response()

            # handle the introduction
            lan_introduction_address = payload.lan_introduction_address
            wan_introduction_address = payload.wan_introduction_address
            if not (lan_introduction_address == ("0.0.0.0", 0) or wan_introduction_address == ("0.0.0.0", 0) or
                    lan_introduction_address in self._dispersy._bootstrap_candidates or wan_introduction_address in self._dispersy._bootstrap_candidates):
                assert self._dispersy.is_valid_address(lan_introduction_address), lan_introduction_address
                assert self._dispersy.is_valid_address(wan_introduction_address), wan_introduction_address

                # get or create the introduced candidate
                self._dispersy._statistics.walk_advice_incoming_response += 1
                sock_introduction_addr = lan_introduction_address if wan_introduction_address[0] == self._dispersy._wan_address[0] else wan_introduction_address
                introduce = self.get_candidate(sock_introduction_addr, replace=False, lan_address=lan_introduction_address)
                if introduce is None:
                    # create candidate but set its state to inactive to ensure that it will not be
                    # used.  note that we call candidate.intro to allow the candidate to be returned
                    # by get_walk_candidate and yield_candidates
                    self._dispersy._statistics.walk_advice_incoming_response_new += 1
                    introduce = self.create_candidate(sock_introduction_addr, payload.tunnel, lan_introduction_address, wan_introduction_address, u"unknown")
                    introduce.inactive(now)

                # reset the 'I have been introduced' timer
                self.add_candidate(introduce)
                introduce.intro(now)
                self.filter_duplicate_candidate(introduce)
                logger.debug("received introduction to %s from %s", introduce, candidate)

                cache.response_candidate = introduce

                # update statistics
                if self._dispersy._statistics.received_introductions is not None:
                    self._dispersy._statistics.received_introductions[candidate.sock_addr][introduce.sock_addr] += 1

                # TEMP: see which peers we get returned by the trackers
                if self._dispersy._statistics.bootstrap_candidates is not None and isinstance(message.candidate, BootstrapCandidate):
                    self._dispersy._statistics.bootstrap_candidates[introduce.sock_addr] = self._dispersy._statistics.bootstrap_candidates.get(introduce.sock_addr, 0) + 1

            else:
                # update statistics
                if self._dispersy._statistics.received_introductions is not None:
                    self._dispersy._statistics.received_introductions[candidate.sock_addr][wan_introduction_address] += 1

                # TEMP: see which peers we get returned by the trackers
                if self._dispersy._statistics.bootstrap_candidates is not None and isinstance(message.candidate, BootstrapCandidate):
                    self._dispersy._statistics.bootstrap_candidates["none"] = self._dispersy._statistics.bootstrap_candidates.get("none", 0) + 1

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

    def create_introduction_request(self, destination, allow_sync, forward=True):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]

        cache = self.request_cache.add(IntroductionRequestCache(self, destination))
        destination.walk(time())
        self.add_candidate(destination)

        # decide if the requested node should introduce us to someone else
        # advice = random() < 0.5 or len(community.candidates) <= 5
        advice = True

        # obtain sync range
        if not allow_sync or isinstance(destination, BootstrapCandidate):
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
                        logger.error("time_low:  %d", time_low)
                        logger.error("time_high: %d", time_high)
                        logger.error("2**63 - 1: %d", 2 ** 63 - 1)
                        logger.exception("the sqlite3 python module can not handle values 2**63 or larger.  limit time_low and time_high to 2**63-1")
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
                            logger.error("%d bits in: %s", bloom_filter.bits_checked, bloom_filter.bytes.encode("HEX"))
                            logger.error("%d bits in: %s", test_bloom_filter.bits_checked, test_bloom_filter.bytes.encode("HEX"))
                            assert False, "does not match the given range [%d:%d] %%%d+%d packets:%d" % (time_low, time_high, modulo, offset, len(packets))

        meta_request = self.get_meta_message(u"dispersy-introduction-request")
        request = meta_request.impl(authentication=(self.my_member,),
                                    distribution=(self.global_time,),
                                    destination=(destination,),
                                    payload=(destination.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address, advice, self._dispersy._connection_type, sync, cache.number))

        if forward:
            if sync:
                time_low, time_high, modulo, offset, _ = sync
                logger.debug("%s %s sending introduction request to %s [%d:%d] %%%d+%d", self.cid.encode("HEX"), type(self), destination, time_low, time_high, modulo, offset)
            else:
                logger.debug("%s %s sending introduction request to %s", self.cid.encode("HEX"), type(self), destination)

            self._dispersy.statistics.walk_attempt += 1
            if isinstance(destination, BootstrapCandidate):
                self._dispersy.statistics.walk_bootstrap_attempt += 1
            if request.payload.advice:
                self._dispersy.statistics.walk_advice_outgoing_request += 1
            self._dispersy._statistics.dict_inc(self._dispersy.statistics.outgoing_introduction_request, destination.sock_addr)

            self._dispersy._forward([request])

        return request

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
        logger.debug(sql)

        for message, time_low, time_high, offset, modulo in requests:
            sql_arguments = []
            for meta in meta_messages:
                if include_inactive:
                    _time_low = time_low
                else:
                    _time_low = min(max(time_low, self.global_time - meta.distribution.pruning.inactive_threshold + 1), 2 ** 63 - 1) if isinstance(meta.distribution.pruning, GlobalTimePruning) else time_low

                sql_arguments.extend((meta.database_id, _time_low, time_high, offset, modulo))
            logger.debug("%s", sql_arguments)

            yield message, ((str(packet),) for packet, in self._dispersy._database.execute(sql, sql_arguments))

    def check_puncture_request(self, messages):
        for message in messages:
            if message.payload.lan_walker_address == message.candidate.sock_addr:
                yield DropMessage(message, "invalid LAN walker address [puncture herself]")
                continue

            if message.payload.wan_walker_address == message.candidate.sock_addr:
                yield DropMessage(message, "invalid WAN walker address [puncture herself]")
                continue

            if not self._dispersy.is_valid_address(message.payload.lan_walker_address):
                yield DropMessage(message, "invalid LAN walker address [is_valid_address]")
                continue

            if not self._dispersy.is_valid_address(message.payload.wan_walker_address):
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
            assert self._dispersy.is_valid_address(lan_walker_address), lan_walker_address
            assert self._dispersy.is_valid_address(wan_walker_address), wan_walker_address

            # we are asked to send a message to a -possibly- unknown peer get the actual candidate
            # or create a dummy candidate
            sock_addr = lan_walker_address if wan_walker_address[0] == self._dispersy._wan_address[0] else wan_walker_address
            candidate = self.get_candidate(sock_addr, replace=False, lan_address=lan_walker_address)
            if candidate is None:
                # assume that tunnel is disabled
                tunnel = False
                candidate = Candidate(sock_addr, tunnel)

            punctures.append(meta_puncture.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(candidate,), payload=(self._dispersy._lan_address, self._dispersy._wan_address, message.payload.identifier)))
            logger.debug("%s asked us to send a puncture to %s", message.candidate, candidate)

        self._dispersy._forward(punctures)

    def check_puncture(self, messages):
        for message in messages:
            if not self.request_cache.has(IntroductionRequestCache.create_identifier(message.payload.identifier)):
                yield DropMessage(message, "invalid response identifier")
                continue

            yield message

    def on_puncture(self, messages):
        now = time()

        for message in messages:
            # get cache object linked to this request but does NOT stop timeout from occurring
            cache = self.request_cache.get(IntroductionRequestCache.create_identifier(message.payload.identifier))
            cache.on_puncture()

            # when the sender is behind a symmetric NAT and we are not, we will not be able to get
            # through using the port that the helper node gave us (symmetric NAT will give a
            # different port for each destination address).

            # we can match this source address (message.candidate.sock_addr) to the candidate and
            # modify the LAN or WAN address that has been proposed.
            sock_addr = message.candidate.sock_addr
            lan_address, wan_address = self._dispersy.estimate_lan_and_wan_addresses(sock_addr, message.payload.source_lan_address, message.payload.source_wan_address)

            if not (lan_address == ("0.0.0.0", 0) or wan_address == ("0.0.0.0", 0)):
                assert self._dispersy.is_valid_address(lan_address), lan_address
                assert self._dispersy.is_valid_address(wan_address), wan_address

                # get or create the introduced candidate
                candidate = self.get_candidate(sock_addr, replace=True, lan_address=lan_address)
                if candidate is None:
                    # create candidate but set its state to inactive to ensure that it will not be
                    # used.  note that we call candidate.intro to allow the candidate to be returned
                    # by get_walk_candidate
                    candidate = self.create_candidate(sock_addr, message.candidate.tunnel, lan_address, wan_address, u"unknown")
                    candidate.inactive(now)

                else:
                    # update candidate
                    candidate.update(message.candidate.tunnel, lan_address, wan_address, u"unknown")

                # reset the 'I have been introduced' timer
                self.add_candidate(candidate)
                candidate.intro(now)
                logger.debug("received introduction to %s", candidate)

                cache.puncture_candidate = candidate

    def create_missing_message(self, candidate, member, global_time, response_func=None, response_args=(), timeout=10.0):
        # ensure that the identifier is 'triggered' somewhere, i.e. using
        # handle_missing_messages(messages, MissingMessageCache)

        sendRequest = False

        cache = self.request_cache.get(MissingMessageCache.create_identifier(member, global_time))
        if not cache:
            cache = self.request_cache.add(MissingMessageCache(timeout, member, global_time))
            logger.debug("new cache: %s", cache)

            meta = self.get_meta_message(u"dispersy-missing-message")
            request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(member, [global_time]))
            self._dispersy._forward([request])

            sendRequest = True

        if response_func:
            cache.callbacks.append((response_func, response_args))

        return sendRequest

    def on_missing_message(self, messages):
        responses = []  # (candidate, packet) tuples
        for message in messages:
            candidate = message.candidate
            member_database_id = message.payload.member.database_id
            for global_time in message.payload.global_times:
                try:
                    packet, = self._dispersy._database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                              (self.database_id, member_database_id, global_time)).next()
                except StopIteration:
                    pass
                else:
                    responses.append((candidate, str(packet)))

        for candidate, responses in groupby(responses, key=lambda tup: tup[0]):
            # responses is an iterator, for __debug__ we need a list
            responses = list(responses)
            self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-missing-message", len(responses))
            self._dispersy._endpoint.send([candidate], [packet for _, packet in responses])

    def create_missing_last_message(self, candidate, member, message, count_, response_func=None, response_args=(), timeout=10.0):
        if __debug__:
            assert isinstance(candidate, Candidate)
            assert isinstance(member, Member)
            assert isinstance(message, Message)
            assert isinstance(count_, int)
            assert response_func is None or callable(response_func)
            assert isinstance(response_args, tuple)
            assert isinstance(timeout, float)
            assert timeout > 0.0

        sendRequest = False

        cache = self.request_cache.get(MissingLastMessageCache.create_identifier(member, message))
        if not cache:
            cache = self.request_cache.add(MissingLastMessageCache(timeout, member, message))
            logger.debug("new cache: %s", cache)

            meta = self.get_meta_message(u"dispersy-missing-last-message")
            request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(member, message, count_))
            self._dispersy._forward([request])
            sendRequest = True

        cache.callbacks.append((response_func, response_args))
        return sendRequest

    def on_missing_last_message(self, messages):
        for message in messages:
            payload = message.payload
            packets = [str(packet) for packet, in list(self._dispersy._database.execute(
                    u"SELECT packet FROM sync WHERE community = ? AND member = ? AND meta_message = ? ORDER BY global_time DESC LIMIT ?",
                    (self.database_id, payload.member.database_id, payload.message.database_id, payload.count)))]
            self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-missing-last-message", len(packets))
            self._dispersy._endpoint.send([message.candidate], packets)

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
        return message

    def create_missing_identity(self, candidate, dummy_member, response_func=None, response_args=(), timeout=4.5, forward=True):
        """
        Create a dispersy-missing-identity message.

        To verify a message signature we need the corresponding public key from the member who made
        the signature.  When we are missing a public key, we can request a dispersy-identity message
        which contains this public key.

        # @return True if actual request is made
        """
        if __debug__:
            assert isinstance(candidate, Candidate)
            assert isinstance(dummy_member, DummyMember)
            assert response_func is None or callable(response_func)
            assert isinstance(response_args, tuple)
            assert isinstance(timeout, float)
            assert isinstance(forward, bool)

        sendRequest = False

        cache = self.request_cache.get(MissingMemberCache.create_identifier(dummy_member))
        if not cache:
            cache = self.request_cache.add(MissingMemberCache(timeout, dummy_member))
            logger.debug("new cache: %s", cache)

            meta = self.get_meta_message(u"dispersy-missing-identity")
            request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(dummy_member.mid,))
            self._dispersy._forward([request])

            sendRequest = True

        cache.callbacks.append((response_func, response_args))
        return sendRequest

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
                    logger.debug("responding with %d identity messages", len(packets))
                    self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-dispersy-identity", len(packets))
                    self._dispersy._endpoint.send([message.candidate], packets)

                else:
                    assert not message.payload.mid == self.my_member.mid, "we should always have our own dispersy-identity"
                    logger.warning("could not find any missing members.  no response is sent [%s, mid:%s, cid:%s]", mid.encode("HEX"), self.my_member.mid.encode("HEX"), self.cid.encode("HEX"))

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
        the third parameter is a boolean indicating weather MESSAGE was modified.

        RESPONSE_FUNC must return a boolean value indicating weather the proposed message (the
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
        @type timeout: float

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
        assert len(members) == 1

        # temporary cache object
        cache = self.request_cache.add(SignatureRequestCache(self.request_cache, members, response_func, response_args, timeout))
        logger.debug("new cache: %s", cache)

        # the dispersy-signature-request message that will hold the
        # message that should obtain more signatures
        meta = self.get_meta_message(u"dispersy-signature-request")
        cache.request = meta.impl(distribution=(self.global_time,),
                                  destination=(candidate,),
                                  payload=(cache.number, message))

        logger.debug("asking %s", [member.mid.encode("HEX") for member in members])
        self._dispersy._forward([cache.request])
        return cache

    def create_missing_sequence(self, candidate, member, message, missing_low, missing_high, response_func=None, response_args=(), timeout=10.0):
        # ensure that the identifier is 'triggered' somewhere, i.e. using
        # handle_missing_messages(messages, MissingSequenceCache)

        sendRequest = False

        # the MissingSequenceCache allows us to match the missing_high to the response_func
        cache = self.request_cache.get(MissingSequenceCache.create_identifier(member, message, missing_high))
        if not cache:
            cache = self.request_cache.add(MissingSequenceCache(timeout, member, message, missing_high))
            logger.debug("new cache: %s", cache)

        if response_func:
            cache.callbacks.append((response_func, response_args))

        # the MissingSequenceOverviewCache ensures that we do not request duplicate ranges
        overview = self.request_cache.get(MissingSequenceOverviewCache.create_identifier(member, message))
        if not overview:
            overview = self.request_cache.add(MissingSequenceOverviewCache(timeout, member, message))
            logger.debug("new cache: %s", cache)

        if overview.missing_high == 0 or missing_high > overview.missing_high:
            missing_low = max(overview.missing_high, missing_low)
            overview.missing_high = missing_high

            logger.debug("%s sending missing-sequence %s %s [%d:%d]", candidate, member.mid.encode("HEX"), message.name, missing_low, missing_high)
            meta = self.get_meta_message(u"dispersy-missing-sequence")
            request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(member, message, missing_low, missing_high))
            self._dispersy._forward([request])

            sendRequest = True

        return sendRequest

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
        sources = defaultdict(lambda: defaultdict(set))

        logger.debug("received %d missing-sequence message for community %d", len(messages), self.database_id)

        # we know that there are buggy clients out there that give numerous overlapping requests.
        # we will filter these to perform as few queries on the database as possible
        for message in messages:
            member_id = message.payload.member.database_id
            message_id = message.payload.message.database_id
            logger.debug("%s requests member:%d message_id:%d range:[%d:%d]", message.candidate, member_id, message_id, message.payload.missing_low, message.payload.missing_high)
            for sequence in xrange(message.payload.missing_low, message.payload.missing_high + 1):
                if sequence in sources[message.candidate][(member_id, message_id)]:
                    logger.debug("ignoring duplicate request for %d:%d:%d from %s", member_id, message_id, sequence, message.candidate)
            sources[message.candidate][(member_id, message_id)].update(xrange(message.payload.missing_low, message.payload.missing_high + 1))

        for candidate, requests in sources.iteritems():
            assert isinstance(candidate, Candidate), type(candidate)

            # we limit the response by byte_limit bytes per incoming candidate
            byte_limit = self.dispersy_missing_sequence_response_limit

            # it is much easier to count packets... hence, to optimize we translate the byte_limit
            # into a packet limit.  we will assume a 256 byte packet size (security packets are
            # generally small)
            packet_limit = max(1, int(byte_limit / 128))
            logger.debug("will allow at most... byte_limit:%d packet_limit:%d for %s", byte_limit, packet_limit, candidate)

            packets = []
            for (member_id, message_id), sequences in requests.iteritems():
                if not sequences:
                    # empty set will fail min(...) and max(...)
                    continue
                lowest, highest = min(sequences), max(sequences)

                # limiter
                highest = min(lowest + packet_limit, highest)

                logger.debug("fetching member:%d message:%d %d packets from database for %s", member_id, message_id, highest - lowest + 1, candidate)
                for packet, in self._dispersy._database.execute(u"SELECT packet FROM sync WHERE member = ? AND meta_message = ? ORDER BY global_time LIMIT ? OFFSET ?",
                                                               (member_id, message_id, highest - lowest + 1, lowest - 1)):
                    packet = str(packet)
                    packets.append(packet)

                    packet_limit -= 1
                    byte_limit -= len(packet)
                    if byte_limit <= 0:
                        logger.debug("Bandwidth throttle.  byte_limit:%d  packet_limit:%d", byte_limit, packet_limit)
                        break

                if byte_limit <= 0 or packet_limit <= 0:
                    logger.debug("Bandwidth throttle.  byte_limit:%d  packet_limit:%d", byte_limit, packet_limit)
                    break

            if __debug__:
                # ensure we are sending the correct sequence numbers back
                for packet in packets:
                    msg = self._dispersy.convert_packet_to_message(packet, self)
                    assert msg
                    assert min(requests[(msg.authentication.member.database_id, msg.database_id)]) <= msg.distribution.sequence_number, ["giving back a seq-number that is smaller than the lowest request", msg.distribution.sequence_number, min(requests[(msg.authentication.member.database_id, msg.database_id)]), max(requests[(msg.authentication.member.database_id, msg.database_id)])]
                    assert msg.distribution.sequence_number <= max(requests[(msg.authentication.member.database_id, msg.database_id)]), ["giving back a seq-number that is larger than the highest request", msg.distribution.sequence_number, min(requests[(msg.authentication.member.database_id, msg.database_id)]), max(requests[(msg.authentication.member.database_id, msg.database_id)])]
                    logger.debug("syncing %d bytes, member:%d message:%d sequence:%d explicit:%s to %s", len(packet), msg.authentication.member.database_id, msg.database_id, msg.distribution.sequence_number, "T" if msg.distribution.sequence_number in requests[(msg.authentication.member.database_id, msg.database_id)] else "F", candidate)

            self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-sequence-", len(packets))
            self._dispersy._endpoint.send([candidate], packets)

    def create_missing_proof(self, candidate, message, response_func=None, response_args=(), timeout=10.0):
        # ensure that the identifier is 'triggered' somewhere, i.e. using
        # handle_missing_messages(messages, MissingProofCache)

        sendRequest = False
        cache = self.request_cache.get(MissingProofCache.create_identifier())
        if not cache:
            cache = self.request_cache.add(MissingProofCache(timeout))
            logger.debug("new cache: %s", cache)

        key = (message.meta, message.authentication.member)
        if not key in cache.duplicates:
            cache.duplicates.append(key)

            meta = self.get_meta_message(u"dispersy-missing-proof")
            request = meta.impl(distribution=(self.global_time,), destination=(candidate,), payload=(message.authentication.member, message.distribution.global_time))
            self._dispersy._forward([request])
            sendRequest = True

        if response_func:
            cache.callbacks.append((response_func, response_args))
        return sendRequest

    def on_missing_proof(self, messages):
        for message in messages:
            try:
                packet, = self._dispersy._database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ? LIMIT 1",
                                                          (self.database_id, message.payload.member.database_id, message.payload.global_time)).next()

            except StopIteration:
                logger.warning("someone asked for proof for a message that we do not have")

            else:
                packet = str(packet)
                msg = self._dispersy.convert_packet_to_message(packet, self, verify=False)
                allowed, proofs = self.timeline.check(msg)
                if allowed and proofs:
                    logger.debug("we found %d packets containing proof for %s", len(proofs), message.candidate)
                    self._dispersy._statistics.dict_inc(self._dispersy._statistics.outgoing, u"-proof-", len(proofs))
                    self._dispersy._endpoint.send([message.candidate], [proof.packet for proof in proofs])

                else:
                    logger.debug("unable to give %s missing proof.  allowed:%s.  proofs:%d packets", message.candidate, allowed, len(proofs))

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
        >>> bob = dispersy.get_member(bob_public_key)
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

    # def check_authorize(self, messages):
    #     check = message.community.timeline.check

    #     for message in messages:
    #         allowed, proofs = check(message)
    #         if allowed:

    # ensure that the author has the authorize permission
    #             authorize_allowed, authorize_proofs = check(messageauthor, global_time, [(message, u"authorize") for _, message, __ in permission_triplets])
    #             if not authorize_allowed:
    #                 yield DelayMessageByProof(message)

    #             yield message
    #         else:
    #             yield DelayMessageByProof(message)

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
        >>> bob = dispersy.get_member(bob_public_key)
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
                logger.error("you are attempting to undo the same message twice.  this should never be attempted as it is considered malicious behavior")

                # already undone.  refuse to undo again but return the previous undo message
                undo_own_meta = self.get_meta_message(u"dispersy-undo-own")
                undo_other_meta = self.get_meta_message(u"dispersy-undo-other")
                for packet_id, message_id, packet in self._dispersy._database.execute(u"SELECT id, meta_message, packet FROM sync WHERE community = ? AND member = ? AND meta_message IN (?, ?)",
                                                                                     (self.database_id, message.authentication.member.database_id, undo_own_meta.database_id, undo_other_meta.database_id)):
                    msg = Packet(undo_own_meta if undo_own_meta.database_id == message_id else undo_other_meta, str(packet), packet_id).load_message()
                    if message.distribution.global_time == msg.payload.global_time:
                        return msg

                # could not find the undo message that caused the sync.undone to be True.  the
                # undone was probably caused by changing permissions
                return None

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
            logger.debug("%s", message)

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

                # 3. cleanup the malicious_proof table.  we need nothing here anymore
                self._dispersy._database.execute(u"DELETE FROM malicious_proof WHERE community = ?", (self.database_id,))

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
        timeline = self.timeline
        global_time = self.global_time
        changes = {}

        for message in messages:
            logger.debug("received %s policy changes", len(message.payload.policies))
            for meta, policy in message.payload.policies:
                # TODO currently choosing the range that changed in a naive way, only using the
                # lowest global time value
                if meta in changes:
                    range_ = changes[meta]
                else:
                    range_ = [global_time, global_time]
                    changes[meta] = range_
                range_[0] = min(message.distribution.global_time + 1, range_[0])

                # apply new policy setting
                timeline.change_resolution_policy(meta, message.distribution.global_time, policy, message)

        if not initializing:
            logger.debug("updating %d ranges", len(changes))
            execute = self._dispersy._database.execute
            executemany = self._dispersy._database.executemany
            for meta, range_ in changes.iteritems():
                logger.debug("%s [%d:]", meta.name, range_[0])
                undo = []
                redo = []

                for packet_id, packet, undone in list(execute(u"SELECT id, packet, undone FROM sync WHERE meta_message = ? AND global_time BETWEEN ? AND ?",
                                                              (meta.database_id, range_[0], range_[1]))):
                    message = self._dispersy.convert_packet_to_message(str(packet), self)
                    if message:
                        message.packet_id = packet_id
                        allowed, _ = timeline.check(message)
                        if allowed and undone:
                            logger.debug("redo message %s at time %d", message.name, message.distribution.global_time)
                            redo.append(message)

                        elif not (allowed or undone):
                            logger.debug("undo message %s at time %d", message.name, message.distribution.global_time)
                            undo.append(message)

                        elif __debug__:
                            logger.debug("no change for message %s at time %d", message.name, message.distribution.global_time)

                if undo:
                    executemany(u"UPDATE sync SET undone = 1 WHERE id = ?", ((message.packet_id,) for message in undo))
                    assert self._dispersy._database.changes == len(undo), (self._dispersy._database.changes, len(undo))
                    meta.undo_callback([(message.authentication.member, message.distribution.global_time, message) for message in undo])

                    # notify that global times have changed
                    # meta.self.update_sync_range(meta, [message.distribution.global_time for message in undo])

                if redo:
                    executemany(u"UPDATE sync SET undone = 0 WHERE id = ?", ((message.packet_id,) for message in redo))
                    assert self._dispersy._database.changes == len(redo), (self._dispersy._database.changes, len(redo))
                    meta.handle_callback(redo)

                    # notify that global times have changed
                    # meta.self.update_sync_range(meta, [message.distribution.global_time for message in redo])

        # this might be a response to a dispersy-missing-proof or dispersy-missing-sequence
        self.handle_missing_messages(messages, MissingProofCache, MissingSequenceCache)

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

        except KeyError:
            # the dispersy version MUST BE available.  Currently we only support \x00: BinaryConversion
            if packet[0] == "\x00":
                self.add_conversion(BinaryConversion(self, packet[1]))

            # try again
            return super(HardKilledCommunity, self).get_conversion_for_packet(packet)

    def on_introduction_request(self, messages):
        if self._destroy_community_packet:
            self._dispersy.statistics.dict_inc(self._dispersy.statistics.outgoing, u"-destroy-community")
            self._dispersy.endpoint.send([message.candidate for message in messages], [self._destroy_community_packet])
