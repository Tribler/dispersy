#
# Exceptions
#
class DelayPacket(Exception):
    """
    Raised by Conversion.decode_message when the packet can not be
    converted into a Message yet.  Delaying for 'some time' or until
    'some event' occurs.
    """
    pass

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
    Community.on_incoming_dispersy_message (these call
    Community.on_message and Community.on_dispersy_message,
    respectively).  Delaying for 'some time' or until 'some event'
    occurs.
    """
    pass

class DelayMessageBySequence(DelayMessage):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_dispersy_message (these call
    Community.on_message and Community.on_dispersy_message,
    respectively).

    Delaying until all missing sequence numbers have been received.  
    """
    def __init__(self, missing_low, missing_high):
        assert isinstance(missing_low, (int, long))
        assert isinstance(missing_high, (int, long))
        assert 0 < missing_low <= missing_high
        DelayMessage.__init__(self, "Missing sequence number(s)")
        self._missing_low = missing_low
        self._missing_high = missing_high

    @property
    def missing_low(self):
        return self._missing_low

    @property
    def missing_high(self):
        return self._missing_high

    def __str__(self):
        return "<{0.__class__.__name__} missing_low:{0.missing_low} missing_high:{0.missing_high}>".format(self)

class DelayMessageByProof(DelayMessage):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_dispersy_message (these call
    Community.on_message and Community.on_dispersy_message,
    respectively).

    Delaying until a message is received that proves that the message
    is permitted.
    """
    def __init__(self):
        DelayMessage.__init__(self, "Missing proof")

class DropMessage(Exception):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_dispersy_message (these call
    Community.on_message and Community.on_dispersy_message,
    respectively).

    Drops a message because it violates 'something'.  More specific
    reasons can be given with by raising a spectific subclass.
    """
    pass

class DropMessageByProof(DropMessage):
    """
    Raised during Community.on_incoming_message or
    Community.on_incoming_dispersy_message (these call
    Community.on_message and Community.on_dispersy_message,
    respectively).

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
# Message
#
class Message(object):
    class Implementation(object):
        def __init__(self, meta, signed_by, distribution, destination, payload):
            if __debug__:
                from Payload import Permit, Authorize, Revoke
                from Destination import DestinationBase
                from Distribution import DistributionBase
                from Member import Member
            assert isinstance(meta, Message), "META has invalid type '{0}'".format(type(meta))
            assert isinstance(signed_by, Member), "SIGNED_BY has invalid type '{0}'".format(type(signed_by))
            assert isinstance(distribution, DistributionBase.Implementation), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
            assert isinstance(destination, DestinationBase.Implementation), "DESTINATION has invalid type '{0}'".format(type(destination))
            assert isinstance(payload, (Permit, Authorize, Revoke)), "PAYLOAD has invalid type '{0}'".format(type(payload))
            self._meta = meta
            self._signed_by = signed_by
            self._distribution = distribution
            self._destination = destination
            self._payload = payload

        @property
        def community(self):
            return self._meta._community

        @property
        def meta(self):
            return self._meta

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
        def signed_by(self):
            return self._signed_by

        @property
        def distribution(self):
            return self._distribution

        @property
        def destination(self):
            return self._destination

        @property
        def payload(self):
            return self._payload

        def __str__(self):
            return "<{0.__class__.__name__} {0.payload.__class__.__name__} {0.distribution} {0.destination}>".format(self)

    def __init__(self, community, name, resolution, distribution, destination):
        if __debug__:
            from Resolution import Resolution
            from Community import Community
            from Destination import DestinationBase
            from Distribution import DistributionBase
        assert isinstance(community, Community), "COMMUNITY has invalid type '{0}'".format(type(community))
        assert isinstance(name, unicode), "NAME has invalid type '{0}'".format(type(name))
        assert isinstance(resolution, Resolution), "RESOLUTION has invalid type '{0}'".format(type(resolution))
        assert isinstance(distribution, DistributionBase), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
        assert isinstance(destination, DestinationBase), "DESTINATION has invalid type '{0}'".format(type(destination))
        self._community = community
        self._name = name
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
    def resolution(self):
        return self._resolution

    @property
    def distribution(self):
        return self._distribution

    @property
    def destination(self):
        return self._destination

    def __str__(self):
        return "<{0.__class__.__name__} resolution:{0.resolution.__class__.__name__} distribution:{0.distribution.__class__.__name__} destination:{0.destination.__class__.__name__} name:{0.name}>".format(self)

    def implement(self, signed_by, distribution, destination, payload):
        return self.Implementation(self, signed_by, distribution, destination, payload)


# class Carrier(object):
#     def __init__(self, community, distribution, destination
