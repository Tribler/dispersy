if __debug__:
    from Distribution import LastSyncDistribution, FullSyncDistribution, DirectDistribution, RelayDistribution
    from Destination import DestinationBase

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

    Delaying until a message is received with a
    self.missing_sequence_number is received.
    """
    def __init__(self, missing_sequence_number):
        assert isinstance(missing_sequence_number, (int, long))
        DelayMessage.__init__(self, "Missing sequence number")
        self._missing_sequence_number = missing_sequence_number

    @property
    def missing_sequence_number(self):
        return self._missing_sequence_number

    def __str__(self):
        return "<{0.__class__.__name__} missing_sequence_number:{0.missing_sequence_number}>".format(self)

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
    def __init__(self, community, signed_by, distribution, destination, permission):
        if __debug__:
            from Member import Member
            from Community import Community
            from Permission import PermitPermission, AuthorizePermission, RevokePermission
        assert isinstance(community, Community)
        assert isinstance(signed_by, Member)
        assert isinstance(distribution, (FullSyncDistribution.Implementation,
                                         DirectDistribution.Implementation,
                                         RelayDistribution.Implementation,
                                         LastSyncDistribution.Implementation)), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
        assert isinstance(destination, DestinationBase.Implementation)
        assert isinstance(permission, (AuthorizePermission, RevokePermission, PermitPermission))

        # the community
        self._community = community

        # the member who signed the message
        self._signed_by = signed_by

        # the distribution policy
        self._distribution = distribution

        # the destination type
        self._destination = destination

        # the permission that is used
        self._permission = permission

    @property
    def community(self):
        return self._community

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
    def permission(self):
        return self._permission

    def __str__(self):
        return "<{0.__class__.__name__} {0.distribution} {0.destination} {0.permission}>".format(self)



