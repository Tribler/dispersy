if __debug__:
    from Distribution import DistributionBase
    from Destination import DestinationBase

class PrivilegeBase(object):
    def __init__(self, name, distribution, destination):
        assert isinstance(name, unicode)
        assert isinstance(distribution, DistributionBase)
        assert isinstance(destination, DestinationBase)
        self._name = name
        self._distribution = distribution
        self._destination = destination

    @property
    def name(self):
        return self._name

    @property
    def distribution(self):
        return self._distribution

    @property
    def destination(self):
        return self._destination

    def __str__(self):
        return "<{0.__class__.__name__} distribution:{0.distribution.__class__.__name__} destination:{0.destination.__class__.__name__} name:{0.name}>".format(self)

class PublicPrivilege(PrivilegeBase):
    """
    Privilege that everyone always has.
    """
    pass

class LinearPrivilege(PrivilegeBase):
    """
    Privilege with the Linear policy.
    """
    pass

class TimelinePrivilege(PrivilegeBase):
    """
    Privilege with the Timeline policy.
    """
    pass

