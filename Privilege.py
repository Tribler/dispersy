class PrivilegeBase(object):
    def __init__(self, name):
        assert isinstance(name, unicode)
        self._name = name

    @property
    def name(self):
        return self._name

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

