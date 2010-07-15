class PermissionBase(object):
    def __init__(self, privilege):
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(privilege, PrivilegeBase)
        self._privilege = privilege

    @staticmethod
    def get_name():
        raise NotImplemented()

    def get_privilege(self):
        return self._privilege

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self._privilege.get_name())

class AuthorizePermission(PermissionBase):
    def __init__(self, privilege, to, permission):
        """
        User TO is given PERMISSION for PRIVILEGE.

        PRIVILEGE the Privilege that TO obtains PERMISSION for.
        TO the User that obtains PERMISSION.
        PERMISSION the Permission that is authorized.
        """
        if __debug__:
            from Privilege import PrivilegeBase
            from Member import Member
        assert isinstance(privilege, PrivilegeBase)
        assert isinstance(to, Member)
        assert issubclass(permission, PermissionBase)
        PermissionBase.__init__(self, privilege)
        self._to = to
        self._permission = permission

    @staticmethod
    def get_name():
        return u"authorize"

    def get_to(self):
        return self._to

    def get_permission(self):
        return self._permission

    def __str__(self):
        return "<%s %s:%s>" % (self.__class__.__name__, self._privilege.get_name(), self._permission.get_name())

class RevokePermission(PermissionBase):
    def __init__(self, privilege, by, to, permission):
        """
        Revoking PERMISSION for PRIVILEGE previously granted to TO.

        PRIVILEGE the Privilege for which PERMISSION is revoked.
        TO the User that has PERMISSION revoked.
        PERMISSION the Permission that is revoked.
        """
        if __debug__:
            from Privilege import PrivilegeBase
            from Member import Member
        assert isinstance(privilege, PrivilegeBase)
        assert isinstance(to, Member)
        assert issubclass(permission, PermissionBase)
        PermissionBase.__init__(self, privilege)
        self._to = to
        self._permission = permission

    @staticmethod
    def get_name():
        return u"revoke"

    def get_to(self):
        return self._to

    def get_permission(self):
        return self._permission

class PermitPermission(PermissionBase):
    def __init__(self, privilege, container):
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(privilege, PrivilegeBase)
        assert isinstance(container, tuple)
        PermissionBase.__init__(self, privilege)
        self._container = container
        
    @staticmethod
    def get_name():
        return u"permit"

    def get_container(self):
        return self._container

    def __str__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self._privilege.get_name(), repr(self._container))
