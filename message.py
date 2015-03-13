import logging
from abc import ABCMeta, abstractmethod, abstractproperty
from time import time

from .authentication import Authentication
from .candidate import Candidate, LoopbackCandidate
from .destination import Destination
from .distribution import Distribution
from .meta import MetaObject
from .member import Member
from .payload import Payload
from .resolution import Resolution, DynamicResolution


class DelayPacket(Exception):

    """
    Uses an identifier to match request to response.
    """

    __metaclass__ = ABCMeta

    def __init__(self, community, msg):
        from .community import Community
        assert isinstance(community, Community), type(community)

        super(DelayPacket, self).__init__(msg)
        self._delayed = None
        self._community = community
        self._cid = community.cid
        self._candidate = None
        self._timestamp = time()

    @property
    def delayed(self):
        return self._delayed
    @delayed.setter
    def delayed(self, delayed):
        self._delayed = delayed

    @property
    def candidate(self):
        return self._candidate
    @candidate.setter
    def candidate(self, candidate):
        self._candidate = candidate

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def resume_immediately(self):
        return False

    @abstractproperty
    def match_info(self):
        # return the matchinfo to be used to trigger the resume
        pass

    @abstractmethod
    def send_request(self, community, candidate):
        pass

    def on_success(self):
        return self.candidate, self.delayed

    def on_timeout(self):
        pass


class DelayPacketByMissingMember(DelayPacket):

    def __init__(self, community, missing_member_id):
        assert isinstance(missing_member_id, str), type(missing_member_id)
        assert len(missing_member_id) == 20, len(missing_member_id)

        super(DelayPacketByMissingMember, self).__init__(community, "Missing member")
        self._missing_member_id = missing_member_id

    @property
    def match_info(self):
        return (self._cid, u"dispersy-identity", self._missing_member_id, None, []),

    def send_request(self, community, candidate):
        return community.create_missing_identity(candidate,
                    community.dispersy.get_member(mid=self._missing_member_id))


class DelayPacketByMissingMessage(DelayPacket):

    def __init__(self, community, member, global_time):
        assert isinstance(member, Member), type(member)
        assert isinstance(global_time, (int, long)), type(global_time)
        super(DelayPacketByMissingMessage, self).__init__(community, "Missing message")
        self._member = member
        self._global_time = global_time

    @property
    def match_info(self):
        return (self._cid, None, self._member.mid, self._global_time, []),

    def send_request(self, community, candidate):
        return community.create_missing_message(candidate, self._member, self._global_time)


class DropPacket(Exception):

    """
    Raised by Conversion.decode_message when the packet is invalid.
    I.e. does not conform to valid syntax, contains malicious
    behaviour, etc.
    """
    pass


class DelayMessage(DelayPacket):

    def __init__(self, delayed):
        assert isinstance(delayed, Message.Implementation), delayed
        super(DelayMessage, self).__init__(delayed.community, self.__class__.__name__)
        self._delayed = delayed

    def duplicate(self, delayed):
        """
        Create another instance of the same class with another DELAYED.
        """
        return self.__class__(delayed)

    def on_success(self):
        return self.delayed

class DelayMessageByProof(DelayMessage):

    @property
    def match_info(self):
        return (self._cid, u"dispersy-authorize", None, None, []), (self._cid, u"dispersy-dynamic-settings", None, None, [])

    @property
    def resume_immediately(self):
        return True

    def send_request(self, community, candidate):
        community.create_missing_proof(candidate, self._delayed)


class DelayMessageBySequence(DelayMessage):

    def __init__(self, delayed, missing_low, missing_high):
        assert isinstance(missing_low, (int, long)), type(missing_low)
        assert isinstance(missing_high, (int, long)), type(missing_high)
        assert 0 < missing_low <= missing_high, (missing_low, missing_high)
        super(DelayMessageBySequence, self).__init__(delayed)
        self._missing_low = missing_low
        self._missing_high = missing_high

    def duplicate(self, delayed):
        return self.__class__(delayed, self._missing_low, self._missing_high)

    @property
    def match_info(self):
        return (self._cid, None, self._delayed.authentication.member.mid, None, range(self._missing_low, self._missing_high + 1)),

    def send_request(self, community, candidate):
        community.create_missing_sequence(candidate, self._delayed.authentication.member,
                                          self._delayed.meta, self._missing_low, self._missing_high)


class DelayMessageByMissingMessage(DelayMessage):

    def __init__(self, delayed, member, global_time):
        assert isinstance(member, Member), type(member)
        assert isinstance(global_time, (int, long)), type(global_time)
        super(DelayMessageByMissingMessage, self).__init__(delayed)
        self._member = member
        self._global_time = global_time

    def duplicate(self, delayed):
        return self.__class__(delayed, self._member, self._global_time)

    @property
    def match_info(self):
        return (self._cid, None, self._member.mid, self._global_time, []),

    def send_request(self, community, candidate):
        community.create_missing_message(candidate, self._member, self._global_time)


class DropMessage(Exception):

    """
    Raised during Community.on_message.

    Drops a message because it violates 'something'.  More specific
    reasons can be given with by raising a spectific subclass.
    """
    def __init__(self, dropped, msg):
        assert isinstance(dropped, Message.Implementation), type(dropped)
        assert isinstance(msg, (str, unicode)), type(msg)
        self._dropped = dropped
        super(DropMessage, self).__init__(msg)

    @property
    def dropped(self):
        return self._dropped

    def duplicate(self, dropped):
        """
        Create another instance of the same class with another DELAYED.
        """
        return self.__class__(dropped, self.message)

    def __str__(self):
        return "".join((super(DropMessage, self).__str__(), " [", self._dropped.name, "]"))


#
# batch
#
class BatchConfiguration(object):

    def __init__(self, max_window=0.0):
        """
        Per meta message configuration on batch handling.

        MAX_WINDOW sets the maximum size, in seconds, of the window.  A larger window results in
        larger batches and a longer average delay for incoming messages.  Setting MAX_WINDOW to zero
        disables batching, in this case all other parameters are ignored.
        """
        assert isinstance(max_window, float), type(max_window)
        assert 0.0 <= max_window, max_window
        self._max_window = max_window

    @property
    def enabled(self):
        # enabled when max_window is positive
        return 0.0 < self._max_window

    @property
    def max_window(self):
        return self._max_window


#
# packet
#
class Packet(MetaObject.Implementation):

    def __init__(self, meta, packet, packet_id):
        assert isinstance(packet, str), type(packet)
        assert isinstance(packet_id, (int, long)), type(packet_id)
        super(Packet, self).__init__(meta)
        self._packet = packet
        self._packet_id = packet_id

    @property
    def community(self):
        return self._meta._community

    @property
    def name(self):
        return self._meta._name

    @property
    def database_id(self):
        return self._meta._database_id

    @property
    def resolution(self):
        return self._meta._resolution

    @property
    def check_callback(self):
        return self._meta._check_callback

    @property
    def handle_callback(self):
        return self._meta._handle_callback

    @property
    def undo_callback(self):
        return self._meta._undo_callback

    @property
    def priority(self):
        return self._meta._priority

    @property
    def delay(self):
        return self._meta._delay

    @property
    def packet(self):
        return self._packet

    @property
    def packet_id(self):
        return self._packet_id

    @packet_id.setter
    def packet_id(self, packet_id):
        assert isinstance(packet_id, (int, long))
        self._packet_id = packet_id

    def load_message(self):
        message = self._meta.community.dispersy.convert_packet_to_message(self._packet, self._meta.community, verify=False)
        message.packet_id = self._packet_id
        return message

    def __str__(self):
        return "<%s.%s %s %dbytes>" % (self._meta.__class__.__name__, self.__class__.__name__, self._meta._name, len(self._packet))


#
# message
#
class Message(MetaObject):

    class Implementation(Packet):

        def __init__(self, meta, authentication, resolution, distribution, destination, payload, conversion=None, candidate=None, source=u"unknown", packet="", packet_id=0, sign=True):
            from .conversion import Conversion
            assert isinstance(meta, Message), "META has invalid type '%s'" % type(meta)
            assert isinstance(authentication, meta.authentication.Implementation), "AUTHENTICATION has invalid type '%s'" % type(authentication)
            assert isinstance(resolution, meta.resolution.Implementation), "RESOLUTION has invalid type '%s'" % type(resolution)
            assert isinstance(distribution, meta.distribution.Implementation), "DISTRIBUTION has invalid type '%s'" % type(distribution)
            assert isinstance(destination, meta.destination.Implementation), "DESTINATION has invalid type '%s'" % type(destination)
            assert isinstance(payload, meta.payload.Implementation), "PAYLOAD has invalid type '%s'" % type(payload)
            assert conversion is None or isinstance(conversion, Conversion), "CONVERSION has invalid type '%s'" % type(conversion)
            assert candidate is None or isinstance(candidate, Candidate), type(candidate)
            assert isinstance(packet, str), type(packet)
            assert isinstance(packet_id, (int, long)), type(packet_id)
            super(Message.Implementation, self).__init__(meta, packet, packet_id)
            self._authentication = authentication
            self._resolution = resolution
            self._distribution = distribution
            self._destination = destination
            self._payload = payload
            self._candidate = candidate
            self._source = source

            # _RESUME contains the message that caused SELF to be processed after it was delayed
            self._resume = None

            # allow setup parts.  used to setup callback when something changes that requires the
            # self._packet to be generated again
            self._authentication.setup(self)
            # self._resolution.setup(self)
            # self._distribution.setup(self)
            # self._destination.setup(self)
            # self._payload.setup(self)

            if conversion:
                self._conversion = conversion
            elif packet:
                self._conversion = meta.community.get_conversion_for_packet(packet)
            else:
                self._conversion = meta.community.get_conversion_for_message(self)

            if not packet:
                self._packet = self._conversion.encode_message(self, sign=sign)

                if __debug__:  # attempt to decode the message when running in debug
                    self._conversion.decode_message(LoopbackCandidate(), self._packet, verify=sign, allow_empty_signature=True)

        @property
        def conversion(self):
            return self._conversion

        @property
        def authentication(self):
            return self._authentication

        @property
        def resolution(self):
            return self._resolution

        @property
        def distribution(self):
            return self._distribution

        @property
        def destination(self):
            return self._destination

        @property
        def payload(self):
            return self._payload

        @property
        def candidate(self):
            return self._candidate

        @property
        def source(self):
            return self._source

        @property
        def resume(self):
            return self._resume

        @resume.setter
        def resume(self, message):
            assert isinstance(message, Message.Implementation), type(message)
            self._resume = message

        def load_message(self):
            return self

        def regenerate_packet(self, packet=""):
            if packet:
                self._packet = packet
            else:
                self._packet = self._conversion.encode_message(self)

        def __str__(self):
            return "<%s.%s %s>" % (self._meta.__class__.__name__, self.__class__.__name__, self._meta._name)

    def __init__(self, community, name, authentication, resolution, distribution, destination, payload, check_callback, handle_callback, undo_callback=None, batch=None):
        from .community import Community
        assert isinstance(community, Community), "COMMUNITY has invalid type '%s'" % type(community)
        assert isinstance(name, unicode), "NAME has invalid type '%s'" % type(name)
        assert isinstance(authentication, Authentication), "AUTHENTICATION has invalid type '%s'" % type(authentication)
        assert isinstance(resolution, Resolution), "RESOLUTION has invalid type '%s'" % type(resolution)
        assert isinstance(distribution, Distribution), "DISTRIBUTION has invalid type '%s'" % type(distribution)
        assert isinstance(destination, Destination), "DESTINATION has invalid type '%s'" % type(destination)
        assert isinstance(payload, Payload), "PAYLOAD has invalid type '%s'" % type(payload)
        assert callable(check_callback), type(check_callback)
        assert callable(handle_callback), type(handle_callback)
        assert undo_callback is None or callable(undo_callback), undo_callback
        if isinstance(resolution, DynamicResolution):
            assert callable(undo_callback), "UNDO_CALLBACK must be specified when using the DynamicResolution policy"
        assert batch is None or isinstance(batch, BatchConfiguration), type(batch)
        assert self.check_policy_combination(authentication, resolution, distribution, destination)
        self._community = community
        self._name = name
        self._authentication = authentication
        self._resolution = resolution
        self._distribution = distribution
        self._destination = destination
        self._payload = payload
        self._check_callback = check_callback
        self._handle_callback = handle_callback
        self._undo_callback = undo_callback
        self._batch = BatchConfiguration() if batch is None else batch

        community.meta_message_cache[name] = {"priority": 128, "direction": 1}

        self._database_id = None

        # allow optional setup methods to initialize the specific parts of the meta message
        self._authentication.setup(self)
        self._resolution.setup(self)
        self._distribution.setup(self)
        self._destination.setup(self)
        self._payload.setup(self)

    @property
    def community(self):
        return self._community

    @property
    def name(self):
        return self._name

    @property
    def database_id(self):
        return self._database_id

    @property
    def authentication(self):
        return self._authentication

    @property
    def resolution(self):
        return self._resolution

    @property
    def distribution(self):
        return self._distribution

    @property
    def destination(self):
        return self._destination

    @property
    def payload(self):
        return self._payload

    @property
    def check_callback(self):
        return self._check_callback

    @property
    def handle_callback(self):
        return self._handle_callback

    @property
    def undo_callback(self):
        return self._undo_callback

    @property
    def batch(self):
        return self._batch

    def impl(self, authentication=(), resolution=(), distribution=(), destination=(), payload=(), *args, **kargs):
        if __debug__:
            assert isinstance(authentication, tuple), type(authentication)
            assert isinstance(resolution, tuple), type(resolution)
            assert isinstance(distribution, tuple), type(distribution)
            assert isinstance(destination, tuple), type(destination)
            assert isinstance(payload, tuple), type(payload)
            try:
                authentication_impl = self._authentication.Implementation(self._authentication, *authentication)
                resolution_impl = self._resolution.Implementation(self._resolution, *resolution)
                distribution_impl = self._distribution.Implementation(self._distribution, *distribution)
                destination_impl = self._destination.Implementation(self._destination, *destination)
                payload_impl = self._payload.Implementation(self._payload, *payload)
            except TypeError:
                self._logger = logging.getLogger(self.__class__.__name__)
                self._logger.error("message name:   %s", self._name)
                self._logger.error("authentication: %s.Implementation", self._authentication.__class__.__name__)
                self._logger.error("resolution:     %s.Implementation", self._resolution.__class__.__name__)
                self._logger.error("distribution:   %s.Implementation", self._distribution.__class__.__name__)
                self._logger.error("destination:    %s.Implementation", self._destination.__class__.__name__)
                self._logger.error("payload:        %s.Implementation", self._payload.__class__.__name__)
                raise
            else:
                return self.Implementation(self, authentication_impl, resolution_impl, distribution_impl, destination_impl, payload_impl, *args, **kargs)

        return self.Implementation(self,
                                   self._authentication.Implementation(self._authentication, *authentication),
                                   self._resolution.Implementation(self._resolution, *resolution),
                                   self._distribution.Implementation(self._distribution, *distribution),
                                   self._destination.Implementation(self._destination, *destination),
                                   self._payload.Implementation(self._payload, *payload),
                                   *args, **kargs)

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self._name)

    @staticmethod
    def check_policy_combination(authentication, resolution, distribution, destination):
        from .authentication import Authentication, NoAuthentication, MemberAuthentication, DoubleMemberAuthentication
        from .resolution import Resolution, PublicResolution, LinearResolution, DynamicResolution
        from .distribution import Distribution, RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution
        from .destination import Destination, CandidateDestination, CommunityDestination

        assert isinstance(authentication, Authentication), type(authentication)
        assert isinstance(resolution, Resolution), type(resolution)
        assert isinstance(distribution, Distribution), type(distribution)
        assert isinstance(destination, Destination), type(destination)

        def require(a, b, c):
            if not isinstance(b, c):
                raise ValueError("%s does not support %s.  Allowed options are: %s" % (a.__class__.__name__, b.__class__.__name__, ", ".join([x.__name__ for x in c])))

        if isinstance(authentication, NoAuthentication):
            require(authentication, resolution, PublicResolution)
            require(authentication, distribution, (RelayDistribution, DirectDistribution))
            require(authentication, destination, (CandidateDestination, CommunityDestination))
        elif isinstance(authentication, MemberAuthentication):
            require(authentication, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(authentication, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(authentication, destination, (CandidateDestination, CommunityDestination))
        elif isinstance(authentication, DoubleMemberAuthentication):
            require(authentication, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(authentication, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(authentication, destination, (CandidateDestination, CommunityDestination))
        else:
            raise ValueError("%s is not supported" % authentication.__class_.__name__)

        if isinstance(resolution, PublicResolution):
            require(resolution, authentication, (NoAuthentication, MemberAuthentication, DoubleMemberAuthentication))
            require(resolution, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(resolution, destination, (CandidateDestination, CommunityDestination))
        elif isinstance(resolution, LinearResolution):
            require(resolution, authentication, (MemberAuthentication, DoubleMemberAuthentication))
            require(resolution, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(resolution, destination, (CandidateDestination, CommunityDestination))
        elif isinstance(resolution, DynamicResolution):
            pass
        else:
            raise ValueError("%s is not supported" % resolution.__class_.__name__)

        if isinstance(distribution, RelayDistribution):
            require(distribution, authentication, (NoAuthentication, MemberAuthentication, DoubleMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(distribution, destination, (CandidateDestination,))
        elif isinstance(distribution, DirectDistribution):
            require(distribution, authentication, (NoAuthentication, MemberAuthentication, DoubleMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(distribution, destination, (CandidateDestination, CommunityDestination))
        elif isinstance(distribution, FullSyncDistribution):
            require(distribution, authentication, (MemberAuthentication, DoubleMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(distribution, destination, (CommunityDestination,))
            if isinstance(authentication, DoubleMemberAuthentication) and distribution.enable_sequence_number:
                raise ValueError("%s may not be used with %s when sequence numbers are enabled" % (distribution.__class__.__name__, authentication.__class__.__name__))
        elif isinstance(distribution, LastSyncDistribution):
            require(distribution, authentication, (MemberAuthentication, DoubleMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(distribution, destination, (CommunityDestination,))
        else:
            raise ValueError("%s is not supported" % distribution.__class_.__name__)

        if isinstance(destination, CandidateDestination):
            require(destination, authentication, (NoAuthentication, MemberAuthentication, DoubleMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(destination, distribution, (RelayDistribution, DirectDistribution))
        elif isinstance(destination, CommunityDestination):
            require(destination, authentication, (NoAuthentication, MemberAuthentication, DoubleMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution, DynamicResolution))
            require(destination, distribution, (DirectDistribution, FullSyncDistribution, LastSyncDistribution))
        else:
            raise ValueError("%s is not supported" % destination.__class_.__name__)

        return True
