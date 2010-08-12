from Permission import AuthorizePermission, RevokePermission

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
        self.missing_sequence_number = missing_sequence_number

    def __str__(self):
        return "%s #%d" % (DelayMessage.__str__(self), self.missing_sequence_number)

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
        self.proof = message
        
#
# Distribution
#
class DistributionBase(object):
    def __init__(self, global_time):
        assert isinstance(global_time, (int, long))
        # the last known global time + 1 (from the user who signed the
        # message)
        self.global_time = global_time

    def __str__(self):
        return "<{0} {1}:->".format(self.__class__.__name__, self.global_time)

class FullSyncDistribution(DistributionBase):
    def __init__(self, global_time, sequence_number):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))

        # super
        DistributionBase.__init__(self, global_time)

        # the sequence number (from the user who signed the messaged)
        self.sequence_number = sequence_number

    def __str__(self):
        return "<{0} {1}:{2}>".format(self.__class__.__name__, self.global_time, self.sequence_number)

class LastSyncDistribution(DistributionBase):
    pass

class MinimalSyncDistribution(DistributionBase):
    def __init__(self, global_time, minimal_count):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))
        assert isinstance(minimal_count, (int, long))

        # super
        SyncDistributionBase.__init__(self, sequence_number)

        # the minimal number of nodes online that should have the
        # message
        self.minimal_count = minimal_count

    def __str__(self):
        return "<{0} {1}:- {2}>".format(self.__class__.__name__, self.global_time, self.minimal_count)

class DirectDistribution(DistributionBase):
    pass

class RelayDistribution(DistributionBase):
    pass


#
# Destination
#
class DestinationBase(object):
    def __str__(self):
        return "<%s>" % (self.__class__.__name__)

class UserDestination(DestinationBase):
    pass

class MemberDestination(DestinationBase):
    pass

class CommunityDestination(DestinationBase):
    pass

class PrivilegedDestination(DestinationBase):
    pass


#
# Message
#
class MessageBase(object):
    def __init__(self, community, signed_by, distribution, destination, is_dispersy_specific):
        if __debug__:
            from Member import Member
            from Community import Community
        assert isinstance(community, Community)
        assert isinstance(signed_by, Member)
        assert isinstance(distribution, DistributionBase)
        assert isinstance(destination, DestinationBase)

        # the community
        self.community = community

        # the member who signed the message
        self.signed_by = signed_by

        # the distribution policy {FullSyncDistribution, MinimalSyncDistribution, DirectDistribution, RelayDistribution}
        self.distribution = distribution

        # the destination type {UserDestination, MemberDestination, CommunityDestination, PrivilegedDestination}
        self.destination = destination

        # is it a dispersy specific message
        self.is_dispersy_specific = is_dispersy_specific

    def __str__(self):
        return "<%s>" % (self.__class__.__name__)


class SyncMessage(MessageBase):
    def __init__(self, community, signed_by, distribution, destination, permission):
        if __debug__:
            from Permission import PermissionBase
        assert isinstance(distribution, (FullSyncDistribution, MinimalSyncDistribution, LastSyncDistribution))
        assert isinstance(destination, (CommunityDestination, PrivilegedDestination))
        assert isinstance(permission, PermissionBase)

        is_dispersy_specific = isinstance(permission, (AuthorizePermission, RevokePermission))

        # super
        MessageBase.__init__(self, community, signed_by, distribution, destination, is_dispersy_specific)

        # the permission that is used
        self.permission = permission

    def __str__(self):
        return "<%s %s %s %s>" % (self.__class__.__name__, self.distribution, self.destination, self.permission)

class DirectMessage(MessageBase):
    def __init__(self, community, signed_by, distribution, destination, identifier, payload):
        assert isinstance(distribution, (DirectDistribution, RelayDistribution))
        assert isinstance(destination, (UserDestination, MemberDestination))
        assert isinstance(identifier, unicode)
        assert isinstance(payload, (tuple, list))
        assert len(payload) > 0

        is_dispersy_specific = isinstance(payload[0], unicode) and payload[0].startswith(u"dispersy_")

        # super
        MessageBase.__init__(self, community, signed_by, distribution, destination, is_dispersy_specific)

        # the message identifier
        self.identifier = identifier

        # the payload
        self.payload = payload
