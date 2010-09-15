import socket

from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Privilege import PublicPrivilege
from Message import Message
from Destination import CommunityDestination
from Distribution import LastSyncDistribution, FullSyncDistribution
from Permission import PermitPermission
from Member import MyMember
from Print import dprint

class Node(object):
    def __init__(self):
        self._socket = None
        self._my_member = None
        self._community = None

    @property
    def socket(self):
        return self._socket

    def init_socket(self, port):
        assert isinstance(port, int)
        assert self._socket is None
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("localhost", port))
        self._socket.setblocking(True)

    @property
    def my_member(self):
        return self._my_member

    def init_my_member(self, bits=512):
        rsa = rsa_generate_key(bits)
        self._my_member = MyMember.get_instance(rsa_to_public_pem(rsa), rsa_to_private_pem(rsa), False)

    @property
    def community(self):
        return self._community

    def set_community(self, community):
        self._community = community

    def create_message(self, distribution, destination, permission):
        return Message(self._community, self._my_member, distribution, destination, permission)

    def send_message(self, message, address):
        payload = self._community.get_conversion().encode_message(message)
        try:
            return self._socket.sendto(payload, address)
        except:
            dprint("Error while sending ", len(payload), " bytes to ", address[0], ":", address[1])
            raise

    def receive_message(self, timeout=30.0):
        assert isinstance(timeout, float)
        self._socket.settimeout(timeout)
        try:
            data, address = self._socket.recvfrom(1024)
        except:
            raise
        else:
            message = self._community.get_conversion().decode_message(data)
            dprint(message)
            dprint(address)

class DiscoveryNode(Node):
    def __init__(self, *args, **kargs):
        Node.__init__(self, *args, **kargs)
        self._user_metadata_privilege = PublicPrivilege(u"user-metadata", LastSyncDistribution(100, 100, 0.001), CommunityDestination())
        self._community_metadata_privilege = PublicPrivilege(u"community-metadata", FullSyncDistribution(100, 100, 0.001), CommunityDestination())

    def create_user_metadata_message(self, address, alias, comment, global_time):
        distribution = self._user_metadata_privilege.distribution.implement(global_time)
        destination = self._user_metadata_privilege.destination.implement()
        permission = PermitPermission(self._user_metadata_privilege, (address, alias, comment))
        return self.create_message(distribution, destination, permission)
    
