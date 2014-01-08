
import logging
import netifaces
import os
import sys

try:
    # python 2.7 only...
    from collections import OrderedDict
except ImportError:
    from .python27_ordereddict import OrderedDict

from collections import defaultdict
from itertools import groupby, islice, count
from pprint import pformat
from socket import inet_aton, error as socket_error
from struct import unpack_from
from time import time

from .authentication import NoAuthentication, MemberAuthentication, DoubleMemberAuthentication
from .bloomfilter import BloomFilter
from .bootstrap import Bootstrap
from .candidate import BootstrapCandidate, LoopbackCandidate, WalkCandidate, Candidate
from .crypto import DispersyCrypto, ECCrypto
from .destination import CommunityDestination, CandidateDestination
from .dispersydatabase import DispersyDatabase
from .distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution, DirectDistribution, GlobalTimePruning
from .logger import get_logger
from .member import DummyMember, Member
from .message import BatchConfiguration, Packet, Message
from .message import DropMessage, DelayMessage, DelayMessageByProof, DelayMessageBySequence, DelayMessageByMissingMessage
from .message import DropPacket, DelayPacket
from .payload import AuthorizePayload, RevokePayload, UndoPayload
from .payload import DestroyCommunityPayload
from .payload import DynamicSettingsPayload
from .payload import IdentityPayload, MissingIdentityPayload
from .payload import IntroductionRequestPayload, IntroductionResponsePayload, PunctureRequestPayload, PuncturePayload
from .payload import MissingMessagePayload, MissingLastMessagePayload
from .payload import MissingSequencePayload, MissingProofPayload
from .payload import SignatureRequestPayload, SignatureResponsePayload
from .requestcache import Cache, NumberCache
from .resolution import PublicResolution, LinearResolution
from .statistics import DispersyStatistics

logger = get_logger(__name__)

class SignatureRequestCache(NumberCache):

    @staticmethod
    def create_identifier(number):
        assert isinstance(number, (int, long)), type(number)
        return u"request-cache:signature-request:%d" % (number,)

    def __init__(self, request_cache, members, response_func, response_args, timeout):
        super(SignatureRequestCache, self).__init__(request_cache)
        self.request = None
        # MEMBERS is a list containing all the members that should add their signature.  currently
        # we only support double signed messages, hence MEMBERS contains only a single Member
        # instance.
        self.members = members
        self.response_func = response_func
        self.response_args = response_args
        self._timeout_delay = timeout

    @property
    def timeout_delay(self):
        return self._timeout_delay

    def on_timeout(self):
        logger.debug("signature timeout")
        self.response_func(self, None, True, *self.response_args)


class IntroductionRequestCache(NumberCache):
    @staticmethod
    def create_identifier(number):
        assert isinstance(number, (int, long)), type(number)
        return u"request-cache:introduction-request:%d" % (number,)

    @property
    def timeout_delay(self):
        # we will accept the response at most 10.5 seconds after our request
        return 10.5

    def __init__(self, community, helper_candidate):
        super(IntroductionRequestCache, self).__init__(community.request_cache)
        self.community = community
        self.helper_candidate = helper_candidate
        self.response_candidate = None
        self.puncture_candidate = None
        self._introduction_response_received = False
        self._puncture_received = False

    def on_timeout(self):
        # helper_candidate did not respond to a request message in this community.  after some time
        # inactive candidates become obsolete and will be removed by
        # _periodically_cleanup_candidates
        logger.debug("walker timeout for %s", self.helper_candidate)

        self.community.dispersy.statistics.dict_inc(self.community.dispersy.statistics.walk_fail, self.helper_candidate.sock_addr)

        # set the candidate to obsolete
        self.helper_candidate.obsolete(time())

    def _check_if_both_received(self):
        if self._introduction_response_received and self._puncture_received:
            self.community.dispersy.request_cache.pop(self.identifier)

    def on_introduction_response(self):
        self._introduction_response_received = True
        self._check_if_both_received()

    def on_puncture(self):
        self._puncture_received = True
        self._check_if_both_received()


class MissingSomethingCache(Cache):

    def __init__(self, timeout, *create_identifier_args):
        super(MissingSomethingCache, self).__init__(self.create_identifier(*create_identifier_args))
        logger.debug("%s: waiting for %.1f seconds", self.__class__.__name__, timeout)
        self._timeout_delay = timeout
        self.callbacks = []

    @property
    def timeout_delay(self):
        return self._timeout_delay

    def on_timeout(self):
        logger.debug("%s: timeout on %d callbacks", self.__class__.__name__, len(self.callbacks))
        for func, args in self.callbacks:
            func(None, *args)


class MissingMemberCache(MissingSomethingCache):

    @staticmethod
    def create_identifier(member):
        assert isinstance(member, DummyMember), type(member)
        return u"request-cache:missing-member:%s" % (member.mid.encode("HEX"),)


class MissingMessageCache(MissingSomethingCache):

    @staticmethod
    def create_identifier(member, global_time):
        assert isinstance(member, DummyMember), type(member)
        assert isinstance(global_time, (int, long)), type(global_time)
        return u"request-cache:missing-message:%s:%d" % (member.mid.encode("HEX"), global_time)

    @classmethod
    def create_identifier_from_message(cls, message):
        assert isinstance(message, Message.Implementation), type(message)
        return cls.create_identifier(message.authentication.member, message.distribution.global_time)


class MissingLastMessageCache(MissingSomethingCache):

    @staticmethod
    def create_identifier(member, message):
        assert isinstance(member, DummyMember), type(member)
        assert isinstance(message, (Message, Message.Implementation)), type(message)
        return u"request-cache:missing-last-message:%s:%s" % (member.mid.encode("HEX"), message.name.encode("UTF-8"))


class MissingProofCache(MissingSomethingCache):

    @staticmethod
    def create_identifier():
        return u"request-cache:missing-proof"

    @classmethod
    def create_identifier_from_message(cls, message):
        assert isinstance(message, Message.Implementation), type(message)
        return cls.create_identifier()

    def __init__(self, timeout):
        super(MissingProofCache, self).__init__(timeout)

        # duplicates contains the (meta messages, member) for which we have already requesting
        # proof, this allows us send fewer duplicate requests
        self.duplicates = []


class MissingSequenceOverviewCache(Cache):

    @staticmethod
    def create_identifier(member, message):
        assert isinstance(member, Member), type(member)
        assert isinstance(message, (Message, Message.Implementation)), type(message)
        return u"request-cache:missing-sequence-overview:%s:%s" % (member.mid.encode("HEX"), message.name.encode("UTF-8"))

    def __init__(self, timeout, *create_identifier_args):
        super(MissingSequenceOverviewCache, self).__init__(self.create_identifier(*create_identifier_args))
        self._timeout_delay = timeout
        self.missing_high = 0

    @property
    def timeout_delay(self):
        return self._timeout_delay

    def on_timeout(self):
        pass


class MissingSequenceCache(MissingSomethingCache):

    @staticmethod
    def create_identifier(member, message, missing_global_time_high):
        assert isinstance(member, Member), type(member)
        assert isinstance(message, (Message, Message.Implementation)), type(message)
        assert isinstance(missing_global_time_high, (int, long)), type(missing_global_time_high)
        return u"request-cache:missing-sequence:%s:%s:%d" % (member.mid.encode("HEX"), message.name.encode("UTF-8"), missing_global_time_high)

    @classmethod
    def create_identifier_from_message(cls, message):
        assert isinstance(message, Message.Implementation), type(message)
        return cls.create_identifier(message.authentication.member, message, message.distribution.sequence_number)
