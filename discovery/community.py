# Written by Niels Zeilemaker, Egbert Bouman
import logging
import os
from collections import OrderedDict
from random import random, shuffle
from time import time

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import LoopingCall

from ..authentication import MemberAuthentication, NoAuthentication
from ..candidate import CANDIDATE_WALK_LIFETIME, Candidate, WalkCandidate
from ..community import Community
from ..conversion import DefaultConversion
from ..destination import CandidateDestination
from ..distribution import DirectDistribution
from ..member import Member
from ..message import DelayMessageByProof, DropMessage, Message
from ..requestcache import RandomNumberCache
from ..resolution import PublicResolution
from .bootstrap import Bootstrap
from .conversion import DiscoveryConversion
from .payload import (ExtendedIntroPayload, PingPayload, PongPayload, SimilarityRequestPayload,
                      SimilarityResponsePayload)


DEBUG_VERBOSE = False

PING_INTERVAL = CANDIDATE_WALK_LIFETIME / 5
PING_TIMEOUT = CANDIDATE_WALK_LIFETIME / 2
INSERT_TRACKER_INTERVAL = 300
PEERCACHE_FILENAME = 'peercache.txt'
TIME_BETWEEN_CONNECTION_ATTEMPTS = 10.0

BOOTSTRAP_FILE_ENVNAME = 'DISPERSY_BOOTSTRAP_FILE'


class LimitedOrderedDict(OrderedDict):

    def __init__(self, limit, *args, **kargs):
        super(LimitedOrderedDict, self).__init__(*args, **kargs)
        self._limit = limit

    def __setitem__(self, *args, **kargs):
        super(LimitedOrderedDict, self).__setitem__(*args, **kargs)
        if len(self) > self._limit:
            self.popitem(last=False)


class TasteBuddy(object):

    def __init__(self, overlap, preferences, sock_addr):
        assert isinstance(overlap, int), type(overlap)
        assert isinstance(preferences, set), type(preferences)
        assert all(isinstance(cur_preference, str) for cur_preference in preferences)

        super(TasteBuddy, self).__init__()

        self.overlap = overlap
        self.preferences = preferences
        self.sock_addr = sock_addr
        self.random_sort_value = random()

    def update_overlap(self, other, compute_overlap):
        self.preferences = self.preferences | other.preferences
        self.overlap = compute_overlap(self.preferences)

    def does_overlap(self, preference):
        return preference in self.preferences

    def __cmp__(self, other):
        if isinstance(other, TasteBuddy):
            # we sort by overlap, then random
            return cmp((self.overlap, self.random_sort_value),
                       (other.overlap, other.random_sort_value))

        elif isinstance(other, int):
            return cmp(self.overlap, other)

    def __str__(self):
        return "TB_%s_%s_%s" % (self.overlap, self.preferences, self.sock_addr)

    def __hash__(self):
        return hash(self.sock_addr)


class ActualTasteBuddy(TasteBuddy):

    def __init__(self, overlap, preferences, timestamp, candidate):
        TasteBuddy.__init__(self, overlap, preferences, candidate.sock_addr)
        assert isinstance(timestamp, (int, float)), type(timestamp)
        assert isinstance(candidate, WalkCandidate), type(candidate)
        assert candidate.get_member()

        self.timestamp = timestamp
        self.candidate = candidate
        self.candidate_mid = candidate.get_member().mid

    def should_cache(self):
        return self.candidate.connection_type == "public"

    def time_remaining(self):
        too_old = time() - PING_TIMEOUT
        diff = self.timestamp - too_old
        return diff if diff > 0 else 0

    def __eq__(self, other):
        if isinstance(other, TasteBuddy):
            return self.sock_addr == other.sock_addr

        elif isinstance(other, Member):
            return self.candidate_mid == other.mid

        elif isinstance(other, Candidate):
            return self.candidate == other

        elif isinstance(other, tuple):
            return self.candidate.sock_addr == other

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return "ATB_%d_%s_%s_%s" % (self.timestamp, self.overlap, self.candidate_mid.encode('HEX'), self.candidate)


class PossibleTasteBuddy(TasteBuddy):

    def __init__(self, overlap, preferences, timestamp, candidate_mid, received_from):
        assert isinstance(timestamp, (int, float)), type(timestamp)
        assert isinstance(candidate_mid, str), type(candidate_mid)
        assert len(candidate_mid) == 20, len(candidate_mid)
        assert isinstance(received_from, WalkCandidate), type(received_from)

        TasteBuddy.__init__(self, overlap, preferences, None)
        self.timestamp = timestamp
        self.candidate_mid = candidate_mid
        self.received_from = received_from

    def time_remaining(self):
        too_old = time() - PING_TIMEOUT
        diff = self.timestamp - too_old
        return diff if diff > 0 else 0

    def did_received_from(self, candidate):
        return candidate == self.received_from

    def __cmp__(self, other):
        if isinstance(other, PossibleTasteBuddy):
            # we want to sort based on overlap, then time desc, then random
            return cmp((self.overlap, self.timestamp, self.random_sort_value),
                       (other.overlap, other.timestamp, other.random_sort_value))

        return TasteBuddy.__cmp__(self, other)

    def __eq__(self, other):
        if isinstance(other, Member):
            return self.candidate_mid == other.mid

        if isinstance(other, Candidate):
            return self.candidate_mid == other.get_member().mid

        if isinstance(other, PossibleTasteBuddy):
            return self.candidate_mid == other.candidate_mid

        return False

    def __str__(self):
        return "PTB_%d_%d_%s_%s" % (self.timestamp, self.overlap, self.candidate_mid.encode("HEX"), self.received_from)

    def __hash__(self):
        return hash(self.candidate_mid)


class SimilarityAttempt(RandomNumberCache):

    def __init__(self, community, requested_candidate, preference_list, allow_sync):
        RandomNumberCache.__init__(self, community.request_cache, "similarity")
        assert isinstance(requested_candidate, WalkCandidate), type(requested_candidate)
        assert isinstance(preference_list, list), type(preference_list)
        self.community = community
        self.requested_candidate = requested_candidate
        self.preference_list = preference_list
        self.allow_sync = allow_sync

    def on_timeout(self):
        self.community.send_introduction_request(self.requested_candidate, allow_sync=self.allow_sync)
        self.community.peer_cache.inc_num_fails(self.requested_candidate)


class PingRequestCache(RandomNumberCache):

    def __init__(self, community, requested_candidate):
        RandomNumberCache.__init__(self, community.request_cache, "ping")
        self.community = community
        self.requested_candidate = requested_candidate

    def on_timeout(self):
        self._logger.debug("DiscoveryCommunity: no response on ping, removing from taste_buddies %s", self.requested_candidate)
        self.community.remove_taste_buddy(self.requested_candidate)


class DiscoveryCommunity(Community):

    def initialize(self, max_prefs=25, max_tbs=25):
        self._logger.debug('initializing DiscoveryComunity, max_prefs = %d, max_tbs = %d', max_prefs, max_tbs)

        # needs to be called before super.initialize
        self.peer_cache = PeerCache(os.path.join(self._dispersy._working_directory, PEERCACHE_FILENAME), self)
        self.max_prefs = max_prefs
        self.max_tbs = max_tbs
        self.taste_buddies = []
        self.possible_taste_buddies = []
        self.requested_introductions = {}
        self.recent_taste_buddies = LimitedOrderedDict(limit=1000)

        self.send_packet_size = 0
        self.reply_packet_size = 0

        def on_bootstrap_started(_):
            """
            Get's called when the resolving of the bootstrap servers
            has been initiated. Starts the periodically_insert_trackers
            looping call.
            :param _: ignored success parameter of the bootstrap resolve function.
            """

            # TODO(Martijn): second condition is a workaround for the fact that bootstrapping can be completed
            # after shutdown. This prevents the lc from being registered, leaving a dirty reactor.
            # When Dispersy becomes asynchronous, we should wait for the dns resolution to be completed on shutdown.
            if not self.is_pending_task_active("insert_trackers") and self._dispersy.running:
                self.register_task("insert_trackers",
                                   LoopingCall(self.periodically_insert_trackers)).start(INSERT_TRACKER_INTERVAL, now=True)

        bootstrap_file = os.environ.get(BOOTSTRAP_FILE_ENVNAME, os.path.join(self._dispersy._working_directory, "bootstraptribler.txt"))
        alternate_addresses = None
        if bootstrap_file:
            self._logger.debug("Expecting bootstrapfile at %s %s", os.path.abspath(
                bootstrap_file), os.path.exists(bootstrap_file))
            alternate_addresses = Bootstrap.load_addresses_from_file(bootstrap_file)

        default_addresses = Bootstrap.get_default_addresses()
        self.bootstrap = Bootstrap(alternate_addresses or default_addresses)
        self.bootstrap.start().addCallback(on_bootstrap_started)

        self.register_task('create_ping_requests',
                           LoopingCall(self.create_ping_requests)).start(PING_INTERVAL)

        super(DiscoveryCommunity, self).initialize()

    @inlineCallbacks
    def unload_community(self):
        yield super(DiscoveryCommunity, self).unload_community()
        if self.bootstrap:
            yield self.bootstrap.stop()

    def periodically_insert_trackers(self):
        communities = [community for community in self._dispersy.get_communities() if community.dispersy_enable_candidate_walker]
        if self not in communities:  # make sure we are in the communities list
            communities.append(self)

        for community in communities:
            for candidate in self.bootstrap.candidates:
                self._logger.debug("Adding %s %s as discovered candidate", type(community), candidate)
                community.add_discovered_candidate(candidate)

    def dispersy_get_walk_candidate(self):
        candidate = super(DiscoveryCommunity, self).dispersy_get_walk_candidate() or self.peer_cache.get_peer()

        # If we don't have a candidate to walk to, call self.periodically_insert_trackers() in a minute
        if candidate:
            self.cancel_pending_task("insert_trackers_when_no_candidates")

        elif not self.is_pending_task_active("insert_trackers_when_no_candidates"):
            self.register_task("insert_trackers_when_no_candidates",
                               reactor.callLater(60, self.periodically_insert_trackers))

        return candidate

    @classmethod
    def get_master_members(cls, dispersy):
# generated: Fri Apr 25 13:37:28 2014
# curve: NID_sect571r1
# len: 571 bits ~ 144 bytes signature
# pub: 170 3081a7301006072a8648ce3d020106052b81040027038192000403b3ab059ced9b20646ab5e01762b3595c5e8855227ae1e424cff38a1e4edee73734ff2e2e829eb4f39bab20d7578284fcba7251acd74e7daf96f21d01ea17077faf4d27a655837d072baeb671287a88554e1191d8904b0dc572d09ff95f10ff092c8a5e2a01cd500624376aec875a6e3028aab784cfaf0bac6527245db8d93900d904ac2a922a02716ccef5a22f7968
# pub-sha1 7e313685c1912a141279f8248fc8db5899c5df5a
#-----BEGIN PUBLIC KEY-----
# MIGnMBAGByqGSM49AgEGBSuBBAAnA4GSAAQDs6sFnO2bIGRqteAXYrNZXF6IVSJ6
# 4eQkz/OKHk7e5zc0/y4ugp6085urINdXgoT8unJRrNdOfa+W8h0B6hcHf69NJ6ZV
# g30HK662cSh6iFVOEZHYkEsNxXLQn/lfEP8JLIpeKgHNUAYkN2rsh1puMCiqt4TP
# rwusZSckXbjZOQDZBKwqkioCcWzO9aIveWg=
#-----END PUBLIC KEY-----
        master_key = "3081a7301006072a8648ce3d020106052b81040027038192000403b3ab059ced9b20646ab5e01762b3595c5e8855227ae1e424cff38a1e4edee73734ff2e2e829eb4f39bab20d7578284fcba7251acd74e7daf96f21d01ea17077faf4d27a655837d072baeb671287a88554e1191d8904b0dc572d09ff95f10ff092c8a5e2a01cd500624376aec875a6e3028aab784cfaf0bac6527245db8d93900d904ac2a922a02716ccef5a22f7968".decode(
            "HEX")
        master = dispersy.get_member(public_key=master_key)
        return [master]

    def initiate_meta_messages(self):
        meta_messages = super(DiscoveryCommunity, self).initiate_meta_messages()

        for i, mm in enumerate(meta_messages):
            if mm.name == "dispersy-introduction-request":
                meta_messages[i] = Message(self, mm.name, mm.authentication, mm.resolution, mm.distribution,
                                           mm.destination, ExtendedIntroPayload(), mm.check_callback, mm.handle_callback)

        return meta_messages + [Message(self, "similarity-request", MemberAuthentication(), PublicResolution(), DirectDistribution(),
                                        CandidateDestination(), SimilarityRequestPayload(), self.check_similarity_request, self.on_similarity_request),
                                Message(self, "similarity-response", MemberAuthentication(), PublicResolution(), DirectDistribution(),
                                        CandidateDestination(), SimilarityResponsePayload(), self.check_similarity_response, self.on_similarity_response),
                                Message(self, "ping", NoAuthentication(), PublicResolution(), DirectDistribution(), CandidateDestination(),
                                        PingPayload(), self._generic_timeline_check, self.on_ping),
                                Message(self, "pong", NoAuthentication(), PublicResolution(), DirectDistribution(), CandidateDestination(),
                                        PongPayload(), self.check_pong, self.on_pong)]

    def initiate_conversions(self):
        return [DefaultConversion(self), DiscoveryConversion(self)]

    @property
    def dispersy_enable_bloom_filter_sync(self):
        return False

    def my_preferences(self):
        my_prefs = [community.cid for community in self._dispersy.get_communities() if community.dispersy_enable_candidate_walker]
        shuffle(my_prefs)
        return my_prefs

    def new_community(self, community):
        if community.dispersy_enable_candidate_walker:
            for candidate in self.bootstrap.candidates:
                self._logger.debug("Adding %s %s as discovered candidate", type(community), candidate)
                community.add_discovered_candidate(candidate)

    def add_taste_buddies(self, new_taste_buddies):
        my_communities = dict((community.cid, community)
                              for community in self._dispersy.get_communities() if community.dispersy_enable_candidate_walker)

        for i in range(len(new_taste_buddies) - 1, -1, -1):
            new_taste_buddy = new_taste_buddies[i]
            self._logger.debug("DiscoveryCommunity: new taste buddy? %s", new_taste_buddy)

            if new_taste_buddy.should_cache():
                self.peer_cache.add_or_update_peer(new_taste_buddy.candidate)

            for taste_buddy in self.taste_buddies:
                if new_taste_buddy == taste_buddy:
                    self._logger.debug(
                        "DiscoveryCommunity: new taste buddy? no, equal to %s %s", new_taste_buddy, taste_buddy)

                    taste_buddy.update_overlap(new_taste_buddy, self.compute_overlap)
                    new_taste_buddies.pop(i)
                    break

            # new peer
            else:
                self._logger.debug("DiscoveryCommunity: new taste buddy? yes, adding to list")
                self.taste_buddies.append(new_taste_buddy)

            # add taste buddy to overlapping communities
            for cid in new_taste_buddy.preferences:
                if cid in my_communities:
                    my_communities[cid].add_discovered_candidate(new_taste_buddy.candidate)

        self.taste_buddies.sort(reverse=True)
        self.taste_buddies = self.taste_buddies[:self.max_tbs * 4]

        if DEBUG_VERBOSE:
            self._logger.debug("DiscoveryCommunity: current tastebuddy list %s %s", len(
                self.taste_buddies), list(map(str, self.taste_buddies)))
        else:
            self._logger.debug("DiscoveryCommunity: current tastebuddy list %s", len(self.taste_buddies))

    def yield_taste_buddies(self, ignore_candidate=None):
        for i in range(len(self.taste_buddies) - 1, -1, -1):
            if self.taste_buddies[i].time_remaining() == 0:
                self._logger.debug("DiscoveryCommunity: removing tastebuddy too old %s", self.taste_buddies[i])
                self.taste_buddies.pop(i)

        taste_buddies = self.taste_buddies[:]
        shuffle(taste_buddies)
        ignore_sock_addr = ignore_candidate.sock_addr if ignore_candidate else None

        for taste_buddy in taste_buddies:
            if taste_buddy.overlap and taste_buddy.candidate.sock_addr != ignore_sock_addr:
                yield taste_buddy

    def is_taste_buddy(self, candidate):
        for tb in self.yield_taste_buddies():
            if tb == candidate:
                return tb

    def is_taste_buddy_mid(self, mid):
        assert isinstance(mid, str)
        assert len(mid) == 20

        for tb in self.yield_taste_buddies():
            if mid == tb.candidate_mid:
                return tb

    def reset_taste_buddy(self, candidate):
        for tb in self.yield_taste_buddies():
            if tb == candidate:
                tb.timestamp = time()
                if tb.should_cache():
                    self.peer_cache.add_or_update_peer(tb.candidate)
                break

    def remove_taste_buddy(self, candidate):
        for tb in self.yield_taste_buddies():
            if tb == candidate:
                self.taste_buddies.remove(tb)
                break

    def is_recent_taste_buddy(self, candidate):
        member = candidate.get_member()
        if member:
            return self.is_recent_taste_buddy_mid(member.mid)
        return False

    def is_recent_taste_buddy_mid(self, mid):
        assert isinstance(mid, str)
        assert len(mid) == 20

        return mid in self.recent_taste_buddies

    def add_possible_taste_buddies(self, possibles):
        if __debug__:
            for possible in possibles:
                assert isinstance(possible, PossibleTasteBuddy), type(possible)

        low_sim = self.get_least_similar_tb()
        for i in range(len(possibles) - 1, -1, -1):
            new_possible = possibles[i]

            self._logger.debug("DiscoveryCommunity: new possible taste buddy? %s", new_possible)

            if new_possible < low_sim or self.is_taste_buddy_mid(new_possible.candidate_mid) or new_possible == self.my_member:
                self._logger.debug("DiscoveryCommunity: new possible taste buddy? no, %s %s %s", new_possible < low_sim, self.is_taste_buddy_mid(new_possible.candidate_mid), new_possible == self.my_member)
                possibles.pop(i)
                continue

            for i, possible in enumerate(self.possible_taste_buddies):
                if possible == new_possible:
                    new_possible.update_overlap(possible, self.compute_overlap)

                    # replace in list
                    self.possible_taste_buddies[i] = new_possible
                    break

            # new peer
            else:
                self._logger.debug("DiscoveryCommunity: new possible taste buddy? yes, adding to list")
                self.possible_taste_buddies.append(new_possible)

        self.possible_taste_buddies.sort(reverse=True)
        if possibles:
            if DEBUG_VERBOSE:
                self._logger.debug("DiscoveryCommunity: got possible taste buddies, current list %s %s",
                                   len(self.possible_taste_buddies), list(map(str, self.possible_taste_buddies)))
            else:
                self._logger.debug("DiscoveryCommunity: got possible taste buddies, current list %s",
                                   len(self.possible_taste_buddies))

    def clean_possible_taste_buddies(self):
        low_sim = self.get_least_similar_tb()
        for i in range(len(self.possible_taste_buddies) - 1, -1, -1):
            to_low_sim = self.possible_taste_buddies[i] < low_sim
            too_old = self.possible_taste_buddies[i].time_remaining() == 0
            is_tb = self.is_taste_buddy_mid(self.possible_taste_buddies[i].candidate_mid)

            if to_low_sim or too_old or is_tb:
                self._logger.debug("DiscoveryCommunity: removing possible tastebuddy %s %s %s %s",
                                   to_low_sim, too_old, is_tb, self.possible_taste_buddies[i])
                self.possible_taste_buddies.pop(i)

    def has_possible_taste_buddies(self, candidate):
        for possible in self.possible_taste_buddies:
            if possible.did_received_from(candidate):
                return True
        return False

    def is_possible_taste_buddy_mid(self, mid):
        assert isinstance(mid, str)
        assert len(mid) == 20

        for ptb in self.possible_taste_buddies:
            if mid == ptb.candidate_mid:
                return ptb

    def get_most_similar(self, candidate):
        assert isinstance(candidate, WalkCandidate), [type(candidate), candidate]

        self.clean_possible_taste_buddies()

        if self.possible_taste_buddies:
            most_similar = self.possible_taste_buddies.pop(0)
            return most_similar.received_from, most_similar.candidate_mid

        return candidate, None

    def get_least_similar_tb(self):
        if self.taste_buddies:
            return self.taste_buddies[-1]
        return 0

    def create_introduction_request(self, destination, allow_sync, forward=True, is_fast_walker=False):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]

        self._logger.debug("DiscoveryCommunity: creating intro request %s %s %s", self.is_taste_buddy(
            destination), self.has_possible_taste_buddies(destination), destination)

        send = False
        if not self.is_recent_taste_buddy(destination):
            send = self.create_similarity_request(destination, allow_sync=allow_sync)

        if not send:
            self.send_introduction_request(destination, allow_sync=allow_sync)

    def create_similarity_request(self, destination, allow_sync=True):
        payload = self.my_preferences()[:self.max_prefs]
        if payload:
            cache = self._request_cache.add(SimilarityAttempt(self, destination, payload, allow_sync))
            destination.walk(time())

            self._logger.debug("DiscoveryCommunity: create similarity request for %s with identifier %s %s",
                               destination, cache.number, len(payload))

            meta_request = self.get_meta_message("similarity-request")
            request = meta_request.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(destination,), payload=(
                cache.number, self._dispersy.lan_address, self._dispersy.wan_address, self._dispersy.connection_type, payload))

            if self._dispersy._forward([request]):
                self.send_packet_size += len(request.packet)

                self._logger.debug("DiscoveryCommunity: sending similarity request to %s containing %d preferences: %s",
                                   destination, len(payload), [preference.encode('HEX') for preference in payload])
            return True

        return False

    def check_similarity_request(self, messages):
        for message in messages:
            accepted, _ = self._timeline.check(message)
            if not accepted:
                yield DelayMessageByProof(message)
                continue

            if self._request_cache.has("similarity", message.payload.identifier):
                yield DropMessage(message, "got similarity request issued by myself?")
                continue

            yield message

    def on_similarity_request(self, messages):
        meta = self.get_meta_message("similarity-response")

        # similar to on_introduction_request, we first add all requests to our taste_buddies
        # and then create the replies
        for message in messages:
            wcandidate = self.create_or_update_walkcandidate(message.candidate.sock_addr, message.payload.lan_address,
                                                             message.payload.wan_address, message.candidate.tunnel,
                                                             message.payload.connection_type, message.candidate)
            wcandidate.associate(message.authentication.member)

            # Update actual taste buddies.
            his_preferences = message.payload.preference_list[:self.max_prefs]
            assert all(isinstance(his_preference, str) for his_preference in his_preferences)

            overlap_count = self.compute_overlap(his_preferences)
            self.add_taste_buddies([ActualTasteBuddy(overlap_count, set(his_preferences),
                                                     time(), wcandidate)])

        for message in messages:
            self._logger.debug("DiscoveryCommunity: got similarity request from %s %s", message.candidate, overlap_count)

            his_preferences = message.payload.preference_list[:self.max_prefs]

            # Determine overlap for top taste buddies
            bitfields = []
            tbs = []
            for tb in self.taste_buddies:
                if tb.time_remaining() > 5.0:
                    if tb != message.candidate or True:
                        tbs.append((self.compute_overlap(his_preferences, tb.preferences), random(), tb))

            sorted_tbs = sorted(tbs, reverse=True)
            for _, _, tb in sorted_tbs[:self.max_tbs]:
                # Size of the bitfield is fixed and set to 4 bytes.
                bitfield = sum([2 ** index for index in range(min(len(his_preferences), 4 * 8))
                                if his_preferences[index] in tb.preferences])
                bitfields.append((tb.candidate_mid, bitfield))

            payload = (message.payload.identifier, self.my_preferences()[:self.max_prefs], bitfields)
            response_message = meta.impl(
                authentication=(self.my_member,), distribution=(self.global_time,), payload=payload)

            self._logger.debug("DiscoveryCommunity: sending similarity response to %s containing %s",
                               message.candidate, [preference.encode('HEX') for preference in payload[1]])

            self._dispersy._send([message.candidate], [response_message])

    def compute_overlap(self, his_prefs, my_prefs=None):
        return len(set(his_prefs) & set(my_prefs or self.my_preferences()))

    def check_similarity_response(self, messages):
        identifiers_seen = {}
        for message in messages:
            accepted, _ = self._timeline.check(message)
            if not accepted:
                yield DelayMessageByProof(message)
                continue

            if not self._request_cache.has("similarity", message.payload.identifier):
                yield DropMessage(message, "invalid identifier")
                continue

            if message.payload.identifier in identifiers_seen:
                self._logger.error("already seen this identifier in this batch, previous candidate %s this one %s",
                                   identifiers_seen[message.payload.identifier], message.candidate)
                yield DropMessage(message, "invalid identifier")
                continue

            identifiers_seen[message.payload.identifier] = message.candidate
            yield message

    def on_similarity_response(self, messages):
        for message in messages:
            # Update possible taste buddies.
            request = self._request_cache.pop("similarity", message.payload.identifier)

            # use walkcandidate stored in request_cache
            w_candidate = request.requested_candidate
            w_candidate.associate(message.authentication.member)
            self._logger.debug("DiscoveryCommunity: got similarity response from %s", w_candidate)
            self.peer_cache.set_last_checked(w_candidate, time())

            # Update actual taste buddies.
            payload = message.payload
            his_preferences = set(payload.preference_list)

            assert all(isinstance(his_preference, str) for his_preference in his_preferences)

            overlap_count = self.compute_overlap(his_preferences)
            self.add_taste_buddies([ActualTasteBuddy(overlap_count, his_preferences, time(),
                                                     w_candidate)])

            self.recent_taste_buddies[message.authentication.member.mid] = overlap_count

            now = time()
            possibles = []
            original_list = request.preference_list
            for candidate_mid, bitfield in message.payload.tb_overlap:
                tb_preferences = set([original_list[index] for index in
                                      range(min(len(original_list), 4 * 8)) if bool(bitfield & 2 ** index)])
                possibles.append(PossibleTasteBuddy(len(tb_preferences), tb_preferences,
                                                    now, candidate_mid, w_candidate))

            self._logger.debug("DiscoveryCommunity: got possibles %s %s", message.payload.tb_overlap, [str(possible) for possible in possibles])

            self.add_possible_taste_buddies(possibles)

            destination, introduce_me_to = self.get_most_similar(w_candidate)
            self.send_introduction_request(destination, introduce_me_to, request.allow_sync)

            self.reply_packet_size += len(message.packet)

    def send_introduction_request(self, destination, introduce_me_to=None, allow_sync=True):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]
        assert not introduce_me_to or isinstance(introduce_me_to, str), type(introduce_me_to)

        extra_payload = [introduce_me_to]
        super(DiscoveryCommunity, self).create_introduction_request(destination, allow_sync, extra_payload=extra_payload)

        self._logger.debug("DiscoveryCommunity: sending introduction-request to %s (%s,%s)", destination,
                           introduce_me_to.encode("HEX") if introduce_me_to else '', allow_sync)

    def on_introduction_request(self, messages):
        for message in messages:
            introduce_me_to = ''
            if message.payload.introduce_me_to:
                ctb = self.is_taste_buddy(message.candidate)
                self._logger.debug("Got intro request from %s %s", ctb, ctb.overlap if ctb else 0)

                rtb = self.get_tb_or_candidate_mid(message.payload.introduce_me_to)
                if rtb:
                    self.requested_introductions[message.candidate.get_member().mid] = introduce_me_to = rtb

            self._logger.debug("DiscoveryCommunity: got introduction request %s %s %s",
                               message.payload.introduce_me_to.encode("HEX") if message.payload.introduce_me_to else '-',
                               introduce_me_to, self.requested_introductions)

        super(DiscoveryCommunity, self).on_introduction_request(messages)

    def get_tb_or_candidate_mid(self, mid):
        tb = self.is_taste_buddy_mid(mid)
        if tb:
            return tb.candidate

        return self.get_candidate_mid(mid)

    def dispersy_get_introduce_candidate(self, exclude_candidate=None):
        if exclude_candidate:
            exclude_candidate_mid = exclude_candidate.get_member().mid
            if exclude_candidate_mid in self.requested_introductions:
                intro_me_candidate = self.requested_introductions[exclude_candidate_mid]
                del self.requested_introductions[exclude_candidate_mid]
                return intro_me_candidate

        return super(DiscoveryCommunity, self).dispersy_get_introduce_candidate(exclude_candidate)

    def create_ping_requests(self):
        tbs = list(self.yield_taste_buddies())[:self.max_tbs]
        for tb in tbs:
            if tb.time_remaining() < PING_INTERVAL:
                cache = self._request_cache.add(PingRequestCache(self, tb.candidate))
                self._create_pingpong("ping", tb.candidate, cache.number)

    def on_ping(self, messages):
        for message in messages:
            self._create_pingpong("pong", message.candidate, message.payload.identifier)

            self._logger.debug("DiscoveryCommunity: got ping from %s", message.candidate)
            self.reset_taste_buddy(message.candidate)

    def check_pong(self, messages):
        identifiers_seen = {}
        for message in messages:
            request = self._request_cache.get("ping", message.payload.identifier)
            if not request:
                yield DropMessage(message, "invalid ping identifier")
                continue

            if message.payload.identifier in identifiers_seen:
                self._logger.error("already seen this identifier in this batch, previous candidate %s this one %s", identifiers_seen[message.payload.identifier], message.candidate)
                yield DropMessage(message, "invalid ping identifier")
                continue

            identifiers_seen[message.payload.identifier] = message.candidate
            yield message

    def on_pong(self, messages):
        for message in messages:
            self._request_cache.pop("ping", message.payload.identifier)

            self._logger.debug("DiscoveryCommunity: got pong from %s", message.candidate)

            self.reset_taste_buddy(message.candidate)

    def _create_pingpong(self, meta_name, candidate, identifier):
        meta = self.get_meta_message(meta_name)
        message = meta.impl(distribution=(self.global_time,), payload=(identifier,))
        self._dispersy._send([candidate, ], [message])

        self._logger.debug("DiscoveryCommunity: send %s to %s",
                           meta_name, str(candidate))


class PeerCache(object):

    def __init__(self, filename, community, limit=100):
        assert isinstance(filename, str), type(filename)

        super(PeerCache, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self.filename = filename
        self.community = community
        self.walkcandidates = {}
        self.walkcandidates_limit = limit
        self.info_keys = ['last_seen', 'last_checked', 'num_fails']
        self.load()

        self.community.register_task("clean_and_save_peer_cache", LoopingCall(self.clean_and_save)).start(30, now=False)

    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as fp:
                for line in fp.readlines():
                    if not line.startswith('#'):
                        result = self.parse_line(line)
                        if result is None:
                            continue
                        wcandidate, info = result
                        self.walkcandidates[wcandidate] = info
            self._logger.info('PeerCache: loaded %s, got %d peers', self.filename, len(self.walkcandidates))

    def clean_and_save(self):
        old_num_candidates = len(self.walkcandidates)

        for wcandidate, info in list(self.walkcandidates.items()):
            if info['num_fails'] > 3:
                del self.walkcandidates[wcandidate]

        if len(self.walkcandidates) > self.walkcandidates_limit:
            sorted_keys = sorted([(info['last_seen'], wcandidate) for wcandidate, info in self.walkcandidates.items()], reverse=True)
            for _, wcandidate in sorted_keys[:self.walkcandidates_limit]:
                del self.walkcandidates[wcandidate]

        self._logger.debug('PeerCache: removed %d peers', old_num_candidates - len(self.walkcandidates))

        with open(self.filename, 'w') as fp:
            print('# WAN address\tLAN address\tTunnel', end=' ', file=fp)
            print("\t".join(self.info_keys), file=fp)

            for wcandidate, info in self.walkcandidates.items():
                print('%s:%d\t%s:%d\t%r\t' % (wcandidate.wan_address + wcandidate.lan_address + (wcandidate.tunnel,)), end=' ', file=fp)
                print('\t'.join([str(info[key]) for key in self.info_keys]), file=fp)

            self._logger.debug('PeerCache: saved %d peers to %s', len(self.walkcandidates), self.filename)

    def add_or_update_peer(self, wcandidate):
        assert isinstance(wcandidate, WalkCandidate), type(wcandidate)

        if wcandidate in self.walkcandidates:
            self.walkcandidates[wcandidate]['last_seen'] = time()
        else:
            self.walkcandidates[wcandidate] = {'last_seen': time(), 'last_checked': 0, 'num_fails': 0}

    def get_peer(self):
        sorted_keys = sorted([(info['last_checked'], wcandidate) for wcandidate, info in self.walkcandidates.items()])
        candidate = sorted_keys[0][1] if sorted_keys else None
        self._logger.debug('PeerCache: returning walk candidate %s', candidate)
        return candidate

    def get_peer_info(self, wcandidate):
        return self.walkcandidates.get(wcandidate, None)

    def inc_num_fails(self, wcandidate):
        if wcandidate in self.walkcandidates:
            self.walkcandidates[wcandidate]['num_fails'] += 1

    def set_last_checked(self, wcandidate, last_checked):
        if wcandidate in self.walkcandidates:
            self.walkcandidates[wcandidate]['last_checked'] = last_checked

    def parse_line(self, line):
        trimmed_line = line.replace("\t\t", "\t")
        row = trimmed_line.split('\t')

        # check if the line is invalid
        if len(row) != 6:
            self._logger.warn("Invalid row number (%d) on line: %s", len(row), line)
            return

        wan_addr = row[0].split(':')
        if len(wan_addr) != 2:
            self._logger.warn("Invalid wan_addr (%s) on line: %s", row[0], line)
            return
        wan_addr[1] = int(wan_addr[1])
        wan_addr = tuple(wan_addr)

        lan_addr = row[1].split(':')
        if len(lan_addr) != 2:
            self._logger.warn("Invalid lan_addr (%s) on line: %s", row[0], line)
            return
        lan_addr[1] = int(lan_addr[1])
        lan_addr = tuple(lan_addr)

        tunnel = row[2] == 'True'

        sock_addr = lan_addr if wan_addr[0] == self.community._dispersy._wan_address[0] else wan_addr
        wcandidate = self.community.create_or_update_walkcandidate(sock_addr, lan_addr, wan_addr, tunnel, 'public')

        info_dict = {"last_seen": float(row[3]),
                     "last_checked": float(row[4]),
                     "num_fails": int(row[5])
                     }
        return wcandidate, info_dict
