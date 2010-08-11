"""
The Timeline is an important part of Dispersy.  The Timeline can be
queried as to who had what permissions at some point in time.
"""

from Member import Member, MasterMember
from Permission import AuthorizePermission, RevokePermission
from Privilege import PublicPrivilege, LinearPrivilege
from Print import dprint

class Timeline(object):
    class Node(object):
        def __init__(self):
            self.timeline = [] # (global_time, [permissions])

        def get_privileges(self, global_time):
            assert isinstance(global_time, (int, long))
            for time, allowed_permissions in reversed(self.timeline):
                if global_time >= time:
                    return time, allowed_permissions
            return -1, []

        def __str__(self):
            def time_pair((global_time, permissions)):
                return "%d=[%s]" % (global_time, ",".join(["%s:%s" % (permission[0], permission[1]) for permission in permissions]))
            return "<Node " + ", ".join(map(time_pair, reversed(self.timeline))) + ">"

    def __init__(self, community):
        self._global_time = 0
        self._nodes = {}

    def __str__(self):
        def node_pair((hash, node)):
            return "HASH: " + str(node)
        return "\n".join(map(node_pair, self._nodes.iteritems()))

    def claim_global_time(self):
        self._global_time += 1
        return self._global_time

    def check(self, signed_by, permission, global_time):
        """
        Check is SIGNED_BY has PERMISSION at GLOBAL_TIME.
        """
        if __debug__:
            from Permission import PermissionBase
        assert isinstance(signed_by, Member)
        assert isinstance(permission, PermissionBase)
        assert isinstance(global_time, (int, long))
        if isinstance(signed_by, MasterMember):
            return True

        privilege = permission.get_privilege()
        if isinstance(privilege, PublicPrivilege):
            return True
        elif isinstance(privilege, LinearPrivilege):
            node = self._get_node(signed_by, False)
            if node:
                pair = (privilege.get_name(), permission.get_name())
                _, allowed_permissions = node.get_privileges(global_time)
                if pair in allowed_permissions:
                    self._global_time = max(self._global_time, global_time)
                return True
        dprint("FAIL: Check ", signed_by.get_database_id(), "; ", permission, "@", global_time, level="warning")
        return False

    def update(self, signed_by, permission, global_time):
        """
        Add a new edge, and possibly a new node, to the privilege
        tree.

        Returns True on success, otherwise False is returned.
        """
        assert isinstance(signed_by, Member)
        assert isinstance(permission, (AuthorizePermission, RevokePermission))
        assert isinstance(global_time, (int, long))
        assert self.check(signed_by, permission, global_time)

        privilege = permission.get_privilege()
        if isinstance(privilege, LinearPrivilege):
            return self._update_linear_privilege(signed_by, permission, global_time)
        else:
            raise NotImplementedError

    def _get_node(self, signed_by, create_new):
        """
        Get a Node from a signed_by.get_pem().
        """
        isinstance(signed_by, Member)
        isinstance(create_new, bool)
        pem = signed_by.get_pem()
        if create_new and not pem in self._nodes:
            self._nodes[pem] = self.Node()
        return self._nodes.get(pem, None)

    def _update_linear_privilege(self, signed_by, permission, global_time):
        if isinstance(permission, AuthorizePermission):
            # SIGNED_BY authorizes PERMISSION.get_to() to use
            # PERMISSION.get_permission() for
            # PERMISSION.get_privilege() starting at GLOBAL_TIME + 1.
            node = self._get_node(permission.get_to(), True)
            time, allowed_permissions = node.get_privileges(global_time + 1)
            pair = (permission.get_privilege().get_name(), permission.get_permission().get_name())

            if not pair in allowed_permissions:
                if time == global_time + 1:
                    allowed_permissions.append(pair)
                else:
                    node.timeline.append((global_time + 1, allowed_permissions + [pair]))

            return True

        else:
            raise NotImplementedError
