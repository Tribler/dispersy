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
        return "%s #%d" % (DelayMessage.__str__(self), self._missing_sequence_number)

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
# Distribution
#
class DistributionBase(object):
    def __init__(self, global_time):
        assert isinstance(global_time, (int, long))
        # the last known global time + 1 (from the user who signed the
        # message)
        self._global_time = global_time

    @property
    def global_time(self):
        return self._global_time

    def __str__(self):
        return "<{0} {1}:->".format(self.__class__.__name__, self._global_time)

class SyncDistribution(DistributionBase):
    pass

class FullSyncDistribution(SyncDistribution):
    def __init__(self, global_time, sequence_number):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))

        # super
        DistributionBase.__init__(self, global_time)

        # the sequence number (from the user who signed the messaged)
        self._sequence_number = sequence_number

    @property
    def sequence_number(self):
        return self._sequence_number

    def __str__(self):
        return "<{0} {1}:{2}>".format(self.__class__.__name__, self._global_time, self._sequence_number)

class LastSyncDistribution(SyncDistribution):
    pass

class MinimalSyncDistribution(SyncDistribution):
    def __init__(self, global_time, minimal_count):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))
        assert isinstance(minimal_count, (int, long))

        # super
        SyncDistributionBase.__init__(self, sequence_number)

        # the minimal number of nodes online that should have the
        # message
        self._minimal_count = minimal_count

    @property
    def minimal_count(self):
        return self._minimal_count

    def __str__(self):
        return "<{0} {1}:- {2}>".format(self.__class__.__name__, self._global_time, self._minimal_count)

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
class Message(object):
    def __init__(self, community, signed_by, distribution, destination, permission):
        if __debug__:
            from Member import Member
            from Community import Community
            from Permission import PermitPermission, AuthorizePermission, RevokePermission
        assert isinstance(community, Community)
        assert isinstance(signed_by, Member)
        assert isinstance(distribution, (FullSyncDistribution, MinimalSyncDistribution, DirectDistribution, RelayDistribution, LastSyncDistribution)), "DISTRIBUTION has invalid type '{0}'".format(type(distribution))
        assert isinstance(destination, DestinationBase)
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
        return "<%s>" % (self.__class__.__name__)



