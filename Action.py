class Action(object):
    def __init__(self, permission):
        self._permission = permission

    def get_permission(self):
        return self._permission

class AuthorizeAction(Action):
    def __init__(self, permission, user, permissions):
        """
        PERMISSIONS: the permission used to sign this action
        USER: the user who will receive further permissions
        PERMISSIONS: the permissions that USER is given
        """
        Action.__init__(permission)
        self._user = user
        self._permissions = permissions

    def get_user(self):
        return self._user

    def get_permissions(self):
        return self._permissions

class RevokeAction(Action):
    def __init__(self, permission, user, permissions):
        """
        PERMISSION: the permission used to sign this action
        USER: the user who's permissions are revoked
        PERMISSIONS: the permissions that USER no longer has
        """
        Action.__init__(permission)
        self._user = user
        self._permissions = permissions

class GrantAction(Action):
    def __init__(self, permission, data):
        """
        PERMISSION: the permission used to sign this action
        DATA: the raw data from the message
        """
        Action.__init__(permission)
        self._data = data
        
