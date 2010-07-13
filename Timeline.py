"""
The Timeline is an important part of Dispersy.  The Timeline can be
queried as to who had what permissions at some point in time.
"""

from Member import Member, MasterMember
from Permission import PermissionBase, AuthorizePermission
from Privilege import LinearPrivilege

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

    def check(self, member, permission, global_time):
        """
        Check is MEMBER has PERMISSION at GLOBAL_TIME.
        """
        assert isinstance(member, Member)
        assert isinstance(permission, PermissionBase)
        assert isinstance(global_time, (int, long))
        if isinstance(member, MasterMember):
            return True

        node = self._get_node(member, False)
        if node:
            pair = (permission.get_privilege().get_name(), permission.get_name())
            _, allowed_permissions = node.get_privileges(global_time)
            if pair in allowed_permissions:
                self._global_time = max(self._global_time, global_time)
                return True
        return False

    def update(self, message):
        """
        Add a new edge, and possibly a new node, to the privilege
        tree.

        Returns True on success, otherwise False is returned.
        """
        if __debug__:
            from Message import SyncMessage
        assert isinstance(message, SyncMessage)

        # check if this action is allowed
        if self.check(message.signed_by, message.permission, message.distribution.global_time):
            print "YES", message

            privilege = message.permission.get_privilege()
            if isinstance(privilege, LinearPrivilege):
                return self._update_linear_privilege(message.signed_by, message.permission, message.distribution.global_time)
            else:
                raise NotImplemented()

        print "NO", message
        return False

    def _get_node(self, member, create_new):
        """
        Get a Node from a member.get_pem().
        """
        isinstance(member, Member)
        isinstance(create_new, bool)
        pem = member.get_pem()
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

            print node
            return True

        else:
            raise NotImplemented()
