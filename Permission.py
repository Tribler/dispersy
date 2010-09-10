class PermissionBase(object):
    def __init__(self, name, privilege):
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(name, unicode)
        assert isinstance(privilege, PrivilegeBase)
        self._privilege = privilege
        self._name = name

    @property
    def name(self):
        return self._name

    @property
    def privilege(self):
        return self._privilege

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self._privilege.name)

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
        PermissionBase.__init__(self, u"authorize", privilege)
        self._to = to
        self._permission = permission

    @property
    def to(self):
        return self._to

    @property
    def permission(self):
        return self._permission

    def __str__(self):
        return "<%s %s:%s>" % (self.__class__.__name__, self._privilege.name, self._permission.name)

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
        PermissionBase.__init__(self, u"revoke", privilege)
        self._to = to
        self._permission = permission

    @property
    def to(self):
        return self._to

    @property
    def permission(self):
        return self._permission

class PermitPermission(PermissionBase):
    def __init__(self, privilege, payload):
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(privilege, PrivilegeBase)
        assert isinstance(payload, (tuple, dict, str, unicode, int, long, bool, float))
        PermissionBase.__init__(self, u"permit", privilege)
        self._payload = payload
        
    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self._privilege.name, repr(self._payload))
