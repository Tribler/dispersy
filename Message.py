from Meta import MetaObject
from Payload import Permit
from Payload import IdentityRequestPayload, MissingSequencePayload, SimilarityRequestPayload

#
# Exceptions
#
class DelayPacket(Exception):
    """
    Raised by Conversion.decode_message when the packet can not be
    converted into a Message yet.  Delaying for 'some time' or until
    'some event' occurs.
    """
    def __init__(self, msg, pattern, request_packet):
        if __debug__:
            import re
        assert isinstance(msg, str)
        assert isinstance(pattern, str)
        assert re.compile(pattern)
        assert isinstance(request_packet, str)
        super(DelayPacket, self).__init__(msg)
        self._pattern = pattern
        self._request_packet = request_packet

    @property
    def pattern(self):
        return self._pattern

    @property
    def request_packet(self):
        return self._request_packet

class DelayPacketByMissingMember(DelayPacket):
    """
    Raised during Conversion.decode_message when an unknown member id
    was received.  A member id is the sha1 hash over the member's
    public key, hence there is a small chance that members with
    different public keys will have the same member id.

    Raising this exception should result in a request for all public
    keys associated to the missing member id.
    """
    def __init__(self, community, missing_member_id):
        if __debug__:
            from Community import Community
        assert isinstance(community, Community)
        assert isinstance(missing_member_id, str)
        assert len(missing_member_id) == 20
        # the footprint that will trigger the delayed packet
        footprint = community.get_meta_message(u"dispersy-identity").generate_footprint()

        # the request message that asks for the message that will
        # trigger the delayed packet
        meta = community.get_meta_message(u"dispersy-identity-request")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(community._timeline.global_time),
                                 meta.destination.implement(),
                                 IdentityRequestPayload(missing_member_id))

        super(DelayPacketByMissingMember, self).__init__("Missing member", footprint, message.encode())

class DelayPacketBySimilarity(DelayPacket):
    """
    Raised during Conversion.decode_message when no similarity is
    known for the message owner.

    Delaying until a dispersy-similarity-message is received that
    contains the missing similarity bitstream
    """
    def __init__(self, community, member, destination):
        if __debug__:
            from Community import Community
            from Member import Member
            from Destination import SimilarityDestination
        assert isinstance(community, Community)
        assert isinstance(member, Member)
        assert isinstance(destination, SimilarityDestination)
        # the footprint that will trigger the delayed packet
        meta = community.get_meta_message(u"dispersy-identity")
        footprint = meta.generate_footprint()
        # footprint = "dispersy-identity Community:{0.cid} MemberAuthentication:{1.mid} LastSyncDistribution SimilarityDestination{2.cluster}".format(community, member, destination)

        # the request message that asks for the message that will
        # trigger the delayed packet
        meta = community.get_meta_message(u"dispersy-identity-request")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(community._timeline.global_time),
                                 meta.destination.implement(),
                                 IdentityRequestPayload(member.mid))

        super(DelayPacketBySimilarity, self).__init__("Missing similarity", footprint, message.encode())

class DropPacket(Exception):
    """
    Raised by Conversion.decode_message when the packet is invalid.
    I.e. does not conform to valid syntax, contains malicious
    behaviour, etc.
    """
    pass

class DelayMessage(Exception):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_message; delaying for 'some time' or until
    'some event' occurs.
    """
    def __init__(self, msg, pattern, request_packet):
        if __debug__:
            import re
        assert isinstance(msg, str)
        assert isinstance(pattern, str)
        assert re.compile(pattern)
        assert isinstance(request_packet, str)
        super(DelayMessage, self).__init__(msg)
        self._pattern = pattern
        self._request_packet = request_packet

    @property
    def pattern(self):
        return self._pattern

    @property
    def request_packet(self):
        return self._request_packet

class DelayMessageBySequence(DelayMessage):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_message.

    Delaying until all missing sequence numbers have been received.
    """
    def __init__(self, message, missing_low, missing_high):
        if __debug__:
            from Message import Message
        assert isinstance(message, Message.Implementation)
        assert isinstance(missing_low, (int, long))
        assert isinstance(missing_high, (int, long))
        assert 0 < missing_low <= missing_high
        # the footprint that will trigger the delayed packet
        footprint = "".join((message.name.encode("UTF-8"),
                             " Community:", message.community.cid.encode("HEX"),
                             " MemberAuthentication:", message.authentication.member.mid.encode("HEX"),
                             " FullSyncDistribution:", str(missing_high),
                             " CommunityDestination"))

        # the request message that asks for the message that will
        # trigger the delayed packet
        meta = message.community.get_meta_message(u"dispersy-missing-sequence")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(message.community._timeline.global_time),
                                 meta.destination.implement(),
                                 MissingSequencePayload(message.authentication.member, message.meta, missing_low, missing_high))

        super(DelayMessageBySequence, self).__init__("Missing sequence numbers", footprint, message.encode())

class DelayMessageBySimilarity(DelayMessage):
    """
    Raised during Community.on_message when no similarity is known for
    the message owner.

    Delaying until a dispersy-similarity-message is received that
    contains the missing similarity bitstream
    """
    def __init__(self, message, cluster):
        if __debug__:
            from Message import Message
        assert isinstance(message, Message.Implementation)
        assert isinstance(cluster, int)
        # the footprint that will trigger the delayed packet
        meta = message.community.get_meta_message(u"dispersy-similarity")
        footprint = meta.generate_footprint(authentication=([message.authentication.member.mid],))

        # the request message that asks for the message that will
        # trigger the delayed packet
        meta = message.community.get_meta_message(u"dispersy-similarity-request")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(message.community._timeline.global_time),
                                 meta.destination.implement(),
                                 SimilarityRequestPayload(cluster, [message.authentication.member]))

        super(DelayMessageBySimilarity, self).__init__("Missing similarity", footprint, message.encode())

class DropMessage(Exception):
    """
    Raised during Community.on_message.

    Drops a message because it violates 'something'.  More specific
    reasons can be given with by raising a spectific subclass.
    """
    pass

class DropMessageByProof(DropMessage):
    """
    Raised during Community.on_message.

    Drops a message because it violates a previously received message.
    This message should be provided to the origionator of this message
    to allow them to correct their mistake.
    """
    def __init__(self, message):
        DropMessage.__init__(self, "Provide proof")
        self._proof = message

    @property
    def proof(self):
        return self._proof

#
# message
#
class Message(MetaObject):
    class Implementation(MetaObject.Implementation, Permit):
        def __init__(self, meta, authentication, distribution, destination, payload):
            if __debug__:
                from Authentication import Authentication
                from Destination import Destination
                from Distribution import Distribution
                from Payload import Authorize, Revoke
            assert isinstance(meta, Message), "META has invalid type '{0}'".format(type(meta))
            assert isinstance(authentication, Authentication.Implementation), "AUTHENTICATION has invalid type '{0}'".format(type(authentication))
            assert isinstance(distribution, Distribution.Implementation), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
            assert isinstance(destination, Destination.Implementation), "DESTINATION has invalid type '{0}'".format(type(destination))
            assert isinstance(payload, (Permit, Authorize, Revoke)), "PAYLOAD has invalid type '{0}'".format(type(payload))
            super(Message.Implementation, self).__init__(meta)
            self._authentication = authentication
            self._distribution = distribution
            self._destination = destination
            self._payload = payload
            self._packet = ""

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
        def authentication(self):
            return self._authentication

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
        def packet(self):
            return self._packet

        @packet.setter
        def packet(self, packet):
            assert isinstance(packet, str)
            self._packet = packet

        @property
        def footprint(self):
            assert isinstance(self._authentication.footprint, str)
            assert isinstance(self._distribution.footprint, str)
            assert isinstance(self._destination.footprint, str)
            return "".join((self._meta._name.encode("UTF-8"), " Community:", self._meta._community.cid.encode("HEX"), " ", self._authentication.footprint, " ", self._distribution.footprint, " ", self._destination.footprint))

        def encode(self, prefix=None):
            """
            Shortcut for message.community.get_conversion(prefix).encode_message(message)
            """
            return self._meta._community.get_conversion(prefix).encode_message(self)

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__} {0.name} {1}>".format(self, len(self._packet))

    def __init__(self, community, name, authentication, resolution, distribution, destination):
        if __debug__:
            from Community import Community
            from Authentication import Authentication
            from Resolution import Resolution
            from Destination import Destination
            from Distribution import Distribution
        assert isinstance(community, Community), "COMMUNITY has invalid type '{0}'".format(type(community))
        assert isinstance(name, unicode), "NAME has invalid type '{0}'".format(type(name))
        assert isinstance(authentication, Authentication), "AUTHENTICATION has invalid type '{0}'".format(type(authentication))
        assert isinstance(resolution, Resolution), "RESOLUTION has invalid type '{0}'".format(type(resolution))
        assert isinstance(distribution, Distribution), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
        assert isinstance(destination, Destination), "DESTINATION has invalid type '{0}'".format(type(destination))
        assert self.check_policy_combination(authentication.__class__, resolution.__class__, distribution.__class__, destination.__class__)
        self._community = community
        self._name = name
        self._authentication = authentication
        self._resolution = resolution
        self._distribution = distribution
        self._destination = destination

    @property
    def community(self):
        return self._community

    @property
    def name(self):
        return self._name

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

    def generate_footprint(self, authentication=(), distribution=(), destination=()):
        assert isinstance(authentication, tuple)
        assert isinstance(distribution, tuple)
        assert isinstance(destination, tuple)
        return "".join((self._name.encode("UTF-8"),
                        " Community:", self._community.cid.encode("HEX"),
                        " ", self._authentication.generate_footprint(*authentication),
                        " ", self._distribution.generate_footprint(*distribution),
                        " ", self._destination.generate_footprint(*destination)))

    def __str__(self):
        return "<{0.__class__.__name__} {0.name}>".format(self)

    @staticmethod
    def check_policy_combination(authentication, resolution, distribution, destination):
        from Authentication import Authentication, NoAuthentication, MemberAuthentication, MultiMemberAuthentication
        from Resolution import Resolution, PublicResolution, LinearResolution
        from Distribution import Distribution, RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution
        from Destination import Destination, AddressDestination, MemberDestination, CommunityDestination, SimilarityDestination

        assert issubclass(authentication, Authentication)
        assert issubclass(resolution, Resolution)
        assert issubclass(distribution, Distribution)
        assert issubclass(destination, Destination)

        def require(a, b, c):
            if not issubclass(b, c):
                raise ValueError("{0.__name__} does not support {1.__name__}".format(a, b))

        if issubclass(authentication, NoAuthentication):
            require(authentication, resolution, PublicResolution)
            require(authentication, distribution, (RelayDistribution, DirectDistribution))
            require(authentication, destination, (AddressDestination, MemberDestination, CommunityDestination))
        elif issubclass(authentication, MemberAuthentication):
            require(authentication, resolution, (PublicResolution, LinearResolution))
            require(authentication, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(authentication, destination, (AddressDestination, MemberDestination, CommunityDestination, SimilarityDestination))
        elif issubclass(authentication, MultiMemberAuthentication):
            require(authentication, resolution, (PublicResolution, LinearResolution))
            require(authentication, distribution, (RelayDistribution, DirectDistribution, LastSyncDistribution))
            require(authentication, destination, (AddressDestination, MemberDestination, CommunityDestination, SimilarityDestination))
        else:
            raise ValueError("{0.__name__} is not supported".format(authentication))

        if issubclass(resolution, PublicResolution):
            require(resolution, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(resolution, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(resolution, destination, (AddressDestination, MemberDestination, CommunityDestination, SimilarityDestination))
        elif issubclass(resolution, LinearResolution):
            require(resolution, authentication, (MemberAuthentication, MultiMemberAuthentication))
            require(resolution, distribution, (RelayDistribution, DirectDistribution, FullSyncDistribution, LastSyncDistribution))
            require(resolution, destination, (AddressDestination, MemberDestination, CommunityDestination, SimilarityDestination))
        else:
            raise ValueError("{0.__name__} is not supported".format(resolution))

        if issubclass(distribution, RelayDistribution):
            require(distribution, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution))
            require(distribution, destination, (AddressDestination, MemberDestination))
        elif issubclass(distribution, DirectDistribution):
            require(distribution, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution))
            require(distribution, destination, (AddressDestination, MemberDestination, CommunityDestination))
        elif issubclass(distribution, FullSyncDistribution):
            require(distribution, authentication, MemberAuthentication)
            require(distribution, resolution, (PublicResolution, LinearResolution))
            require(distribution, destination, (CommunityDestination, SimilarityDestination))
        elif issubclass(distribution, LastSyncDistribution):
            require(distribution, authentication, (MemberAuthentication, MultiMemberAuthentication))
            require(distribution, resolution, (PublicResolution, LinearResolution))
            require(distribution, destination, (CommunityDestination, SimilarityDestination))
        else:
            raise ValueError("{0.__name__} is not supported".format(distribution))
        
        if issubclass(destination, AddressDestination):
            require(destination, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution))
            require(destination, distribution, (RelayDistribution, DirectDistribution))
        elif issubclass(destination, MemberDestination):
            require(destination, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution))
            require(destination, distribution, (RelayDistribution, DirectDistribution))
        elif issubclass(destination, CommunityDestination):
            require(destination, authentication, (NoAuthentication, MemberAuthentication, MultiMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution))
            require(destination, distribution, (DirectDistribution, FullSyncDistribution, LastSyncDistribution))
        elif issubclass(destination, SimilarityDestination):
            require(destination, authentication, (MemberAuthentication, MultiMemberAuthentication))
            require(destination, resolution, (PublicResolution, LinearResolution))
            require(destination, distribution, (FullSyncDistribution, LastSyncDistribution))
        else:
            raise ValueError("{0.__name__} is not supported".format(destination))

        return True
