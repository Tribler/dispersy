class PrivilegeBase(object):
    def __init__(self, name):
        assert isinstance(name, str)
        self._name = name

    def get_name(self):
        return self._name

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

