class PermissionBase(object):
    def __init__(self, name, privilege):
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(name, unicode)
        assert isinstance(privilege, PrivilegeBase.Implementation)
        self._name = name
        self._privilege = privilege

    @property
    def name(self):
        return self._name

    @property
    def privilege(self):
        return self._privilege

    def __str__(self):
        return "<{0.__class__.__name__} privilege.name:{0.privilege.name}>".format(self)

class AuthorizePermission(PermissionBase):
    def __init__(self, privilege, to, permission):
        """
        User TO is given PERMISSION for PRIVILEGE.

        PRIVILEGE the Privilege.Implementation that TO obtains PERMISSION for.
        TO the User that obtains PERMISSION.
        PERMISSION the Permission that is authorized.
        """
        if __debug__:
            from Privilege import PrivilegeBase
            from Member import Member
        assert isinstance(privilege, PrivilegeBase.Implementation)
        assert isinstance(to, Member)
        assert issubclass(permission, PermissionBase)
        super(AuthorizePermission, self).__init__(u"authorize", privilege)
        self._to = to
        self._permission = permission

    @property
    def to(self):
        return self._to

    @property
    def permission(self):
        return self._permission

    def __str__(self):
        return "<{0.__class__.__name__} privilege.name:{0.privilege.name} permission.name:{0.permission.name}>".format(self)

class RevokePermission(PermissionBase):
    def __init__(self, privilege, by, to, permission):
        """
        Revoking PERMISSION for PRIVILEGE previously granted to TO.

        PRIVILEGE the Privilege.Implementation for which PERMISSION is revoked.
        TO the User that has PERMISSION revoked.
        PERMISSION the Permission that is revoked.
        """
        if __debug__:
            from Privilege import PrivilegeBase
            from Member import Member
        assert isinstance(privilege, PrivilegeBase.Implementation)
        assert isinstance(to, Member)
        assert issubclass(permission, PermissionBase)
        super(RevokePermission, self).__init__(u"revoke", privilege)
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
        assert isinstance(privilege, PrivilegeBase.Implementation)
        # payload may NOT be a tuple
        assert isinstance(payload, (tuple, dict, str, unicode, int, long, bool, float, type(None))), type(payload)
        super(PermitPermission, self).__init__(u"permit", privilege)
        self._payload = payload
        
    @property
    def payload(self):
        return self._payload

    def __str__(self):
        return "<{0.__class__.__name__} privilege.name:{0.privilege.name} payload:{0.payload!r}>".format(self)
