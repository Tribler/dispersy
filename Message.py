from Permission import AuthorizePermission, RevokePermission

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
        return "<%s>" % (self.__class__.__name__)

class SyncDistributionBase(DistributionBase):
    def __init__(self, global_time, sequence_number):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))

        # super
        DistributionBase.__init__(self, global_time)

        # the sequence number (from the user who signed the messaged)
        self.sequence_number = sequence_number

    def __str__(self):
        return "<%s %d:%d>" % (self.__class__.__name__, self.global_time, self.sequence_number)

class FullSyncDistribution(SyncDistributionBase):
    pass

class MinimalSyncDistribution(SyncDistributionBase):
    def __init__(self, global_time, sequence_number, minimal_count):
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))
        assert isinstance(minimal_count, (int, long))

        # super
        SyncDistributionBase.__init__(self, sequence_number)

        # the minimal number of nodes online that should have the
        # message
        self.minimal_count = minimal_count

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
    def __init__(self, community, signed_by, distribution, destination):
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
        self.is_dispersy_specific = False

    def __str__(self):
        return "<%s>" % (self.__class__.__name__)


class SyncMessage(MessageBase):
    def __init__(self, community, signed_by, distribution, destination, permission):
        if __debug__:
            from Permission import PermissionBase
        assert isinstance(distribution, (FullSyncDistribution, MinimalSyncDistribution))
        assert isinstance(destination, (CommunityDestination, PrivilegedDestination))
        assert isinstance(permission, PermissionBase)

        # super
        MessageBase.__init__(self, community, signed_by, distribution, destination)

        # the permission that is used
        self.permission = permission

        # override baseclass!
        if isinstance(permission, (AuthorizePermission, RevokePermission)):
            self.is_dispersy_specific = True

    def __str__(self):
        return "<%s %s %s %s>" % (self.__class__.__name__, self.distribution, self.destination, self.permission)

class DirectMessage(MessageBase):
    def __init__(self, community, signed_by, distribution, destination, payload):
        assert isinstance(distribution, (DirectDistribution, RelayDistribution))
        assert isinstance(destination, (UserDestination, MemberDestination))
        assert isinstance(payload, (tuple, list))

        # super
        MessageBase.__init__(self, community, signed_by, distribution, destination)

        # the payload
        self.payload = payload
