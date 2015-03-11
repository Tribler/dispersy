# Written by Niels Zeilemaker, Egbert Bouman
import logging
import os
from random import shuffle, random, choice as random_choice
from time import time

from twisted.internet import reactor
from twisted.internet.task import LoopingCall

from ..authentication import NoAuthentication, MemberAuthentication
from ..candidate import CANDIDATE_WALK_LIFETIME, WalkCandidate, Candidate
from ..community import Community
from ..conversion import DefaultConversion
from ..destination import CandidateDestination
from ..distribution import DirectDistribution
from ..member import Member
from ..message import Message, DelayMessageByProof, DropMessage
from ..requestcache import IntroductionRequestCache, RandomNumberCache
from ..resolution import PublicResolution
from .bootstrap import Bootstrap
from conversion import DiscoveryConversion
from payload import *


DEBUG_VERBOSE = False

PING_INTERVAL = CANDIDATE_WALK_LIFETIME / 5
PING_TIMEOUT = CANDIDATE_WALK_LIFETIME / 2
INSERT_TRACKER_INTERVAL = 300
PEERCACHE_FILENAME = 'peercache.txt'
TIME_BETWEEN_CONNECTION_ATTEMPTS = 10.0


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
    def __init__(self, overlap, preferences, timestamp, candidate_mid, candidate):
        TasteBuddy.__init__(self, overlap, preferences, candidate.sock_addr)
        assert isinstance(timestamp, (long, float)), type(timestamp)
        assert isinstance(candidate_mid, str), type(candidate_mid)
        assert len(candidate_mid) == 20, len(candidate_mid)
        assert isinstance(candidate, WalkCandidate), type(candidate)

        self.timestamp = timestamp
        self.candidate = candidate
        self.candidate_mid = candidate_mid

    def should_cache(self):
        return self.candidate.connection_type == u"public"

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
            if other.get_member():
                return self.candidate_mid == other.get_member().mid
            return self.candidate.sock_addr == other.sock_addr

        elif isinstance(other, tuple):
            return self.candidate.sock_addr == other

    def __str__(self):
        return "ATB_%d_%s_%s_%s" % (self.timestamp, self.overlap, self.candidate_mid.encode('HEX'), self.candidate)


class PossibleTasteBuddy(TasteBuddy):
    def __init__(self, overlap, preferences, timestamp, candidate_mid, received_from):
        assert isinstance(timestamp, (long, float)), type(timestamp)
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
            return self.received_from == other
        return self.candidate_mid == other.candidate_mid

    def __str__(self):
        return "PTB_%d_%d_%s_%s" % (self.timestamp, self.overlap, self.candidate_mid.encode("HEX"), self.received_from)

    def __hash__(self):
        return hash(self.candidate_mid)


class DiscoveryCommunity(Community):

    def initialize(self, max_prefs=25, max_tbs=25):
        # needs to be called before super.initialize
        self.peer_cache = PeerCache(os.path.join(self._dispersy._working_directory, PEERCACHE_FILENAME), self)
        self.max_prefs = max_prefs
        self.max_tbs = max_tbs
        self.taste_buddies = []
        self.possible_taste_buddies = []
        self.requested_introductions = {}

        self.send_packet_size = 0
        self.reply_packet_size = 0

        def on_results(success):
            assert isinstance(success, bool), type(success)

            if not self.is_pending_task_active("insert_trackers"):
                self.register_task("insert_trackers",
                                LoopingCall(self.periodically_insert_trackers)).start(INSERT_TRACKER_INTERVAL, now=True)

            if success:
                self._logger.debug("Resolved all bootstrap addresses")

        bootstrap_file = os.path.join(self._dispersy._working_directory, "bootstraptribler.txt")
        self._logger.debug("Expecting bootstrapfile at %s %s", os.path.abspath(
            bootstrap_file), os.path.exists(bootstrap_file))
        alternate_addresses = Bootstrap.load_addresses_from_file(bootstrap_file)

        default_addresses = Bootstrap.get_default_addresses()
        self.bootstrap = Bootstrap(alternate_addresses or default_addresses)

        lc = self.bootstrap.resolve_until_success(now=True, callback=on_results)
        if lc:
            self.register_task("bootstrap_resolution", lc)

        self.register_task('create_ping_requests',
                           LoopingCall(self.create_ping_requests)).start(PING_INTERVAL)

        super(DiscoveryCommunity, self).initialize()

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
        # If we don't get candidates to walk to in a minute, call self.periodically_insert_trackers()
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
            if mm.name == u"dispersy-introduction-request":
                meta_messages[i] = Message(self, mm.name, mm.authentication, mm.resolution, mm.distribution,
                                           mm.destination, ExtendedIntroPayload(), mm.check_callback, mm.handle_callback)

        return meta_messages + [Message(self, u"similarity-request", MemberAuthentication(), PublicResolution(), DirectDistribution(),
                                        CandidateDestination(), SimilarityRequestPayload(), self.check_similarity_request, self.on_similarity_request),
                                Message(self, u"similarity-response", MemberAuthentication(), PublicResolution(), DirectDistribution(),
                                        CandidateDestination(), SimilarityResponsePayload(), self.check_similarity_response, self.on_similarity_response),
                                Message(self, u"ping", NoAuthentication(), PublicResolution(), DirectDistribution(), CandidateDestination(),
                                        PingPayload(), self._generic_timeline_check, self.on_ping),
                                Message(self, u"pong", NoAuthentication(), PublicResolution(), DirectDistribution(), CandidateDestination(),
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
        for new_taste_buddy in new_taste_buddies:
            if DEBUG_VERBOSE:
                self._logger.debug("DiscoveryCommunity: new taste buddy? %s", new_taste_buddy)

            if new_taste_buddy.should_cache():
                self.peer_cache.add_or_update_peer(new_taste_buddy.candidate)

            for taste_buddy in self.taste_buddies:
                if new_taste_buddy == taste_buddy:
                    if DEBUG_VERBOSE:
                        self._logger.debug(
                            "DiscoveryCommunity: new taste buddy? no, equal to %s %s", new_taste_buddy, taste_buddy)

                    taste_buddy.update_overlap(new_taste_buddy, self.compute_overlap)
                    new_taste_buddies.remove(new_taste_buddy)
                    break

            # new peer
            else:
                if DEBUG_VERBOSE:
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
                self.taste_buddies), map(str, self.taste_buddies))
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

    def add_possible_taste_buddies(self, possibles):
        if __debug__:
            for possible in possibles:
                assert isinstance(possible, PossibleTasteBuddy), type(possible)

        low_sim = self.get_least_similar_tb()
        for new_possible in possibles:
            if new_possible <= low_sim or self.is_taste_buddy_mid(new_possible.candidate_mid) or new_possible == self.my_member:
                possibles.remove(new_possible)
                continue

            for i, possible in enumerate(self.possible_taste_buddies):
                if possible == new_possible:
                    new_possible.update_overlap(possible, self.compute_overlap)

                    # replace in list
                    self.possible_taste_buddies[i] = new_possible
                    break

            # new peer
            else:
                self.possible_taste_buddies.append(new_possible)

        self.possible_taste_buddies.sort(reverse=True)
        if DEBUG_VERBOSE and possibles:
            self._logger.debug("DiscoveryCommunity: got possible taste buddies, current list %s %s", len(
                self.possible_taste_buddies), map(str, self.possible_taste_buddies))
        elif possibles:
            self._logger.debug("DiscoveryCommunity: got possible taste buddies, current list %s",
                               len(self.possible_taste_buddies))

    def clean_possible_taste_buddies(self):
        low_sim = self.get_least_similar_tb()
        for i in range(len(self.possible_taste_buddies) - 1, -1, -1):
            to_low_sim = self.possible_taste_buddies[i] <= low_sim
            too_old = self.possible_taste_buddies[i].time_remaining() == 0
            is_tb = self.is_taste_buddy_mid(self.possible_taste_buddies[i].candidate_mid)

            if to_low_sim or too_old or is_tb:
                self._logger.debug("DiscoveryCommunity: removing possible tastebuddy %s %s %s %s",
                                   to_low_sim, too_old, is_tb, self.possible_taste_buddies[i])
                self.possible_taste_buddies.pop(i)

    def has_possible_taste_buddies(self, candidate):
        for possible in self.possible_taste_buddies:
            if possible == candidate:
                return True
        return False

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

    class SimilarityAttempt(RandomNumberCache):
        def __init__(self, community, requested_candidate, preference_list):
            RandomNumberCache.__init__(self, community.request_cache, u"similarity")
            assert isinstance(requested_candidate, WalkCandidate), type(requested_candidate)
            assert isinstance(preference_list, list), type(preference_list)
            self.community = community
            self.requested_candidate = requested_candidate
            self.preference_list = preference_list

        @property
        def timeout_delay(self):
            return 10.5

        def on_timeout(self):
            self.community.send_introduction_request(self.requested_candidate)
            self.community.peer_cache.inc_num_fails(self.requested_candidate)

    def create_introduction_request(self, destination, allow_sync):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]

        self._logger.debug("DiscoveryCommunity: creating intro request %s %s %s", self.is_taste_buddy(
            destination), self.has_possible_taste_buddies(destination), destination)

        send = False
        if not self.is_taste_buddy(destination) and not self.has_possible_taste_buddies(destination):
            send = self.create_similarity_request(destination)

        if not send:
            self.send_introduction_request(destination, allow_sync=allow_sync)

    def create_similarity_request(self, destination):
        payload = self.my_preferences()[:self.max_prefs]
        if payload:
            cache = self._request_cache.add(DiscoveryCommunity.SimilarityAttempt(self, destination, payload))
            destination.walk(time())

            if DEBUG_VERBOSE:
                self._logger.debug("DiscoveryCommunity: create similarity request for %s with identifier %s %s",
                                   destination, cache.number, len(payload))

            meta_request = self.get_meta_message(u"similarity-request")
            request = meta_request.impl(authentication=(self.my_member,), distribution=(self.global_time,), destination=(destination,), payload=(
                cache.number, self._dispersy.lan_address, self._dispersy.wan_address, self._dispersy.connection_type, payload))

            if self._dispersy._forward([request]):
                self.send_packet_size += len(request.packet)

                self._logger.debug("DiscoveryCommunity: sending similarity request to %s containing %s",
                                   destination, [preference.encode('HEX') for preference in payload])
            return True

        return False

    def check_similarity_request(self, messages):
        for message in messages:
            accepted, proof = self._timeline.check(message)
            if not accepted:
                yield DelayMessageByProof(message)
                continue

            if self._request_cache.has(u"similarity", message.payload.identifier):
                yield DropMessage(message, "got similarity request issued by myself?")
                continue

            yield message

    def on_similarity_request(self, messages):
        meta = self.get_meta_message(u"similarity-response")

        # similar to on_introduction_request, we first add all requests to our taste_buddies
        # and then create the replies
        for message in messages:
            wcandidate = self.create_or_update_walkcandidate(message.candidate.sock_addr, message.payload.lan_address,
                                                             message.payload.wan_address, message.candidate.tunnel,
                                                             message.payload.connection_type, message.candidate)

            # Update actual taste buddies.
            his_preferences = message.payload.preference_list
            assert all(isinstance(his_preference, str) for his_preference in his_preferences)

            overlap_count = self.compute_overlap(his_preferences)
            self.add_taste_buddies([ActualTasteBuddy(overlap_count, set(his_preferences),
                                                     time(), message.authentication.member.mid, wcandidate)])


        for message in messages:
            self._logger.debug("DiscoveryCommunity: got similarity request from %s %s", message.candidate, overlap_count)

            his_preferences = message.payload.preference_list

            # Determine overlap for top taste buddies
            bitfields = []
            sorted_tbs = sorted([(self.compute_overlap(his_preferences, tb.preferences), random(), tb)
                                for tb in self.taste_buddies if tb != message.candidate and tb.time_remaining() > 5.0], reverse=True)

            for _, _, tb in sorted_tbs[:self.max_tbs]:
                # Size of the bitfield is fixed and set to 4 bytes.
                bitfield = sum([2 ** index for index in range(min(len(his_preferences), 4 * 8))
                                if his_preferences[index] in tb.preferences])
                bitfields.append((tb.candidate_mid, bitfield))

            payload = (message.payload.identifier, self.my_preferences()[:self.max_prefs], bitfields)
            response_message = meta.impl(
                authentication=(self.my_member,), distribution=(self.global_time,), payload=payload)

            if DEBUG_VERBOSE:
                self._logger.debug("DiscoveryCommunity: sending similarity response to %s containing %s",
                                   message.candidate, payload)

            self._dispersy._send([message.candidate], [response_message])

    def compute_overlap(self, his_prefs, my_prefs=None):
        return len(set(his_prefs) & set(my_prefs or self.my_preferences()))

    def check_similarity_response(self, messages):
        for message in messages:
            accepted, proof = self._timeline.check(message)
            if not accepted:
                yield DelayMessageByProof(message)
                continue

            request = self._request_cache.get(u"similarity", message.payload.identifier)
            if not request:
                yield DropMessage(message, "unknown identifier")
                continue

            yield message

    def on_similarity_response(self, messages):
        for message in messages:
            # Update possible taste buddies.
            request = self._request_cache.pop(u"similarity", message.payload.identifier)
            if request:
                # use walkcandidate stored in request_cache
                w_candidate = request.requested_candidate
                self._logger.debug("DiscoveryCommunity: got similarity response from %s", w_candidate)
                self.peer_cache.set_last_checked(w_candidate, time())

                # Update actual taste buddies.
                payload = message.payload
                his_preferences = set(payload.preference_list)

                assert all(isinstance(his_preference, str) for his_preference in his_preferences)

                overlap_count = self.compute_overlap(his_preferences)
                self.add_taste_buddies([ActualTasteBuddy(overlap_count, his_preferences, time(),
                                                         message.authentication.member.mid, w_candidate)])

                now = time()
                possibles = []
                original_list = request.preference_list
                for candidate_mid, bitfield in message.payload.tb_overlap:
                    tb_preferences = set([original_list[index] for index in
                                          range(min(len(original_list), 4 * 8)) if bool(bitfield & 2 ** index)])
                    possibles.append(PossibleTasteBuddy(len(tb_preferences), tb_preferences,
                                                        now, candidate_mid, w_candidate))

                self.add_possible_taste_buddies(possibles)

                destination, introduce_me_to = self.get_most_similar(w_candidate)
                self.send_introduction_request(destination, introduce_me_to)

                self.reply_packet_size += len(message.packet)
            else:
                self._logger.debug("DiscoveryCommunity: could not get similarity requestcache for %s",
                                   message.payload.identifier)

    def send_introduction_request(self, destination, introduce_me_to=None, allow_sync=True, advice=True):
        assert isinstance(destination, WalkCandidate), [type(destination), destination]
        assert not introduce_me_to or isinstance(introduce_me_to, str), type(introduce_me_to)

        cache = self._request_cache.add(IntroductionRequestCache(self, destination))
        destination.walk(time())

        if allow_sync:
            sync = self.dispersy_claim_sync_bloom_filter(cache)
        else:
            sync = None
        payload = (destination.sock_addr, self._dispersy._lan_address, self._dispersy._wan_address,
                   advice, self._dispersy._connection_type, sync, cache.number, introduce_me_to)

        meta_request = self.get_meta_message(u"dispersy-introduction-request")
        request = meta_request.impl(authentication=(self.my_member,), distribution=(
            self.global_time,), destination=(destination,), payload=payload)

        self._dispersy._forward([request])

        self._logger.debug("DiscoveryCommunity: sending introduction-request to %s (%s,%s,%s)", destination,
                           introduce_me_to.encode("HEX") if introduce_me_to else '', allow_sync, advice)

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

        return super(DiscoveryCommunity, self).dispersy_get_introduce_candidate(self, exclude_candidate)

    class PingRequestCache(RandomNumberCache):

        def __init__(self, community, requested_candidates):
            RandomNumberCache.__init__(self, community.request_cache, u"ping")
            self.community = community
            self.requested_candidates = requested_candidates
            self.received_candidates = set()

        @property
        def timeout_delay(self):
            # we will accept the response at most 10.5 seconds after our request
            return 10.5

        def on_success(self, candidate):
            if self.did_request(candidate):
                self.received_candidates.add(candidate)

            return self.is_complete()

        def is_complete(self):
            return len(self.received_candidates) == len(self.requested_candidates)

        def did_request(self, candidate):
            return candidate in self.requested_candidates

        def on_timeout(self):
            for candidate in self.requested_candidates:
                if candidate not in self.received_candidates:
                    self._logger.debug("DiscoveryCommunity: no response on ping, removing from taste_buddies %s", candidate)
                    self.community.remove_taste_buddy(candidate)

    def create_ping_requests(self):
        tbs = list(self.yield_taste_buddies())[:self.max_tbs]
        tbs = [tb.candidate for tb in tbs if tb.time_remaining() < PING_INTERVAL]

        if tbs:
            cache = self._request_cache.add(DiscoveryCommunity.PingRequestCache(self, tbs))
            self._create_pingpong(u"ping", tbs, cache.number)

    def on_ping(self, messages):
        for message in messages:
            self._create_pingpong(u"pong", [message.candidate], message.payload.identifier)

            self._logger.debug("DiscoveryCommunity: got ping from %s", message.candidate)

            self.reset_taste_buddy(message.candidate)

    def check_pong(self, messages):
        for message in messages:
            request = self._request_cache.get(u"ping", message.payload.identifier)
            if not request:
                yield DropMessage(message, "invalid response identifier")
                continue

            if not request.did_request(message.candidate):
                self._logger.debug("did not send request to %s %s", message.candidate.sock_addr,
                                   [rcandidate.sock_addr for rcandidate in request.requested_candidates])
                yield DropMessage(message, "did not send ping to this candidate")
                continue

            yield message

    def on_pong(self, messages):
        for message in messages:
            request = self._request_cache.get(u"ping", message.payload.identifier)
            if request:
                if request.on_success(message.candidate):
                    self._request_cache.pop(u"ping", message.payload.identifier)

                self._logger.debug("DiscoveryCommunity: got pong from %s", message.candidate)

                self.reset_taste_buddy(message.candidate)
            else:
                self._logger.warning("Ignoring unexpected pong message: %s", message)

    def _create_pingpong(self, meta_name, candidates, identifier):
        meta = self.get_meta_message(meta_name)
        message = meta.impl(distribution=(self.global_time,), payload=(identifier,))
        self._dispersy._send(candidates, [message])

        self._logger.debug("DiscoveryCommunity: send %s to %s candidates: %s",
                           meta_name, len(candidates), map(str, candidates))


class PeerCache(object):

    def __init__(self, filename, community, limit=100):
        assert isinstance(filename, (str, unicode)), type(filename)

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

        for wcandidate, info in self.walkcandidates.items():
            if info['num_fails'] > 3:
                del self.walkcandidates[wcandidate]

        if len(self.walkcandidates) > self.walkcandidates_limit:
            sorted_keys = sorted([(info['last_seen'], wcandidate) for wcandidate, info in self.walkcandidates.iteritems()], reverse=True)
            for _, wcandidate in sorted_keys[:self.walkcandidates_limit]:
                del self.walkcandidates[wcandidate]

        self._logger.debug('PeerCache: removed %d peers', old_num_candidates - len(self.walkcandidates))

        with open(self.filename, 'w') as fp:
            print >> fp, '# WAN address\tLAN address\tTunnel',
            print >> fp, "\t".join(self.info_keys)

            for wcandidate, info in self.walkcandidates.iteritems():
                print >> fp, '%s:%d\t%s:%d\t%r\t' % (wcandidate.wan_address + wcandidate.lan_address + (wcandidate.tunnel,)),
                print >> fp, '\t'.join([str(info[key]) for key in self.info_keys])

            self._logger.debug('PeerCache: saved %d peers to %s', len(self.walkcandidates), self.filename)

    def add_or_update_peer(self, wcandidate):
        assert isinstance(wcandidate, WalkCandidate), type(wcandidate)

        if self.walkcandidates.has_key(wcandidate):
            self.walkcandidates[wcandidate]['last_seen'] = time()
        else:
            self.walkcandidates[wcandidate] = {'last_seen': time(), 'last_checked': 0, 'num_fails': 0}

    def get_peer(self):
        sorted_keys = sorted([(info['last_checked'], wcandidate) for wcandidate, info in self.walkcandidates.iteritems()])
        candidate = sorted_keys[0][1] if sorted_keys else None
        self._logger.debug('PeerCache: returning walk candidate %s', candidate)
        return candidate

    def get_peer_info(self, wcandidate):
        return self.walkcandidates.get(wcandidate, None)

    def inc_num_fails(self, wcandidate):
        if self.walkcandidates.has_key(wcandidate):
            self.walkcandidates[wcandidate]['num_fails'] += 1

    def set_last_checked(self, wcandidate, last_checked):
        if self.walkcandidates.has_key(wcandidate):
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
        wcandidate = self.community.create_or_update_walkcandidate(sock_addr, lan_addr, wan_addr, tunnel, u'public')

        info_dict = {"last_seen": float(row[3]),
                     "last_checked": float(row[4]),
                     "num_fails": int(row[5])
                     }
        return wcandidate, info_dict
