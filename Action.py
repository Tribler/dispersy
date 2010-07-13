# from Permission import Permission
# from Member import User

# class Action(object):
#     def __init__(self, permission):
#         self._permission = permission

#     def get_permission(self):
#         return self._permission

# class AuthorizeAction(Action):
#     def __init__(self, permission, users, permissions):
#         """
#         PERMISSIONS: the permission used to sign this action
#         USERS: the users who will receive further permissions
#         PERMISSIONS: the permissions that USER is given
#         """
#         assert isinstance(permission, Permission)
#         assert isinstance(users, list)
#         assert not filter(lambda x: not isinstance(x, User), users)
#         assert isinstance(permissions, list)
#         assert not filter(lambda x: not isinstance(x, Permission), permissions)
#         Action.__init__(self, permission)
#         self._users = users
#         self._permissions = permissions

#     def get_users(self):
#         return self._users

#     def get_permissions(self):
#         return self._permissions

# class RevokeAction(Action):
#     def __init__(self, permission, users, permissions):
#         """
#         PERMISSION: the permission used to sign this action
#         USERS: the users who's permissions are revoked
#         PERMISSIONS: the permissions that USER no longer has
#         """
#         assert isinstance(permission, Permission)
#         assert isinstance(users, list)
#         assert not filter(lambda x: not isinstance(x, User), users)
#         assert isinstance(permissions, list)
#         assert not filter(lambda x: not isinstance(x, Permission), permissions)
#         Action.__init__(permission)
#         self._users = users
#         self._permissions = permissions

# class GrantAction(Action):
#     def __init__(self, permission, data):
#         """
#         PERMISSION: the permission used to sign this action
#         DATA: the raw data from the message
#         """
#         assert isinstance(permission, Permission)
#         assert isinstance(data, str)
#         Action.__init__(permission)
#         self._data = data
        
