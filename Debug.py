import socket

from Bloomfilter import BloomFilter
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination
from Distribution import DirectDistribution, LastSyncDistribution, FullSyncDistribution
from Member import MyMember, Member
from Message import Message
from Payload import MissingSequencePayload, SyncPayload
from Print import dprint
from Resolution import PublicResolution, LinearResolution

from Tribler.Community.Discovery.DiscoveryPayload import UserMetadataPayload, CommunityMetadataPayload

class Node(object):
    _socket_range = (8000, 8999)
    _socket_pool = {}
    _socket_counter = 0

    def __init__(self):
        self._socket = None
        self._my_member = None
        self._community = None
        self._dispersy_sync_message = None

    @property
    def socket(self):
        return self._socket

    def init_socket(self):
        assert self._socket is None
        port = Node._socket_range[0] + Node._socket_counter % (Node._socket_range[1] - Node._socket_range[0])
        Node._socket_counter += 1

        if not port in Node._socket_pool:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("localhost", port))
            s.setblocking(True)
            Node._socket_pool[port] = s
            if __debug__: dprint("create socket ", port)

        elif __debug__:
            dprint("reuse socket ", port, level="warning")

        self._socket = Node._socket_pool[port]

    @property
    def my_member(self):
        return self._my_member

    def init_my_member(self, bits=512):
        rsa = rsa_generate_key(bits)
        self._my_member = MyMember.get_instance(rsa_to_public_pem(rsa), rsa_to_private_pem(rsa))

    @property
    def community(self):
        return self._community

    def set_community(self, community):
        self._community = community
        self._dispersy_sync_message = Message(community, u"dispersy-sync", PublicResolution(), DirectDistribution(), CommunityDestination())
        self._dispersy_missing_sequence_message = Message(community, u"dispersy-missing-sequence", PublicResolution(), DirectDistribution(), AddressDestination())

    def encode_message(self, message):
        return self._community.get_conversion().encode_message(message)

    def send_packet(self, packet, address):
        dprint(len(packet), " bytes to ", address[0], ":", address[1])
        return self._socket.sendto(packet, address)

    def send_message(self, message, address):
        dprint(message.payload.type, "^", message.name, " to ", address[0], ":", address[1])
        return self.send_packet(self.encode_message(message), address)

    def receive_packet(self, timeout=10.0, addresses=None, packets=None):
        assert isinstance(timeout, float)
        assert isinstance(addresses, (type(None), list))
        assert isinstance(packets, (type(None), list))
        self._socket.settimeout(timeout)
        while True:
            try:
                packet, address = self._socket.recvfrom(10240)
            except:
                raise

            if not (addresses is None or address in addresses or (address[0] == "127.0.0.1" and ("0.0.0.0", address[1]) in addresses)):
                continue

            if not (packets is None or packet in packets):
                continue

            dprint(len(packet), " bytes from ", address[0], ":", address[1])
            return address, packet
        
    def receive_message(self, timeout=10.0, addresses=None, packets=None, message_names=None, payload_types=None, distributions=None, destinations=None):
        assert isinstance(timeout, float)
        assert isinstance(addresses, (type(None), list))
        assert isinstance(packets, (type(None), list))
        assert isinstance(message_names, (type(None), list))
        assert isinstance(payload_types, (type(None), list))
        assert isinstance(distributions, (type(None), list))
        assert isinstance(destinations, (type(None), list))
        self._socket.settimeout(timeout)
        while True:
            address, packet = self.receive_packet(timeout, addresses, packets)
            message = self._community.get_conversion().decode_message(packet)

            if not (message_names is None or message.name in message_names):
                continue

            if not (payload_types is None or message.payload.type in payload_types):
                continue

            if not (distributions is None or isinstance(message.distribution, distributions)):
                continue

            if not (destinations is None or isinstance(message.destination, destinations)):
                continue

            dprint(message.payload.type, "^", message.name, " (", len(packet), " bytes) from ", address[0], ":", address[1])
            return address, packet, message
            
    def create_dispersy_sync_message(self, bloom_global_time, bloom_packets, global_time):
        assert isinstance(bloom_global_time, (int, long))
        assert isinstance(bloom_packets, list)
        assert not filter(lambda x: not isinstance(x, str), bloom_packets)
        assert isinstance(global_time, (int, long))
        bloom_filter = BloomFilter(1000, 0.001)
        map(bloom_filter.add, bloom_packets)
        distribution = self._dispersy_sync_message.distribution.implement(global_time)
        destination = self._dispersy_sync_message.destination.implement()
        payload = SyncPayload(bloom_global_time, bloom_filter)
        return self._dispersy_sync_message.implement(self._my_member, distribution, destination, payload)

    def create_dispersy_missing_sequence_message(self, missing_member, missing_message_meta, missing_low, missing_high, global_time, destination_address):
        assert isinstance(missing_member, Member)
        assert isinstance(missing_message_meta, Message)
        assert isinstance(missing_low, (int, long))
        assert isinstance(missing_high, (int, long))
        assert isinstance(global_time, (int, long))
        assert isinstance(destination_address, tuple)
        assert len(destination_address) == 2
        assert isinstance(destination_address[0], str)
        assert isinstance(destination_address[1], int)
        distribution = self._dispersy_missing_sequence_message.distribution.implement(global_time)
        destination = self._dispersy_missing_sequence_message.destination.implement(destination_address)
        payload = MissingSequencePayload(missing_member, missing_message_meta, missing_low, missing_high)
        return self._dispersy_missing_sequence_message.implement(self._my_member, distribution, destination, payload)

class DiscoveryNode(Node):
    def __init__(self, *args, **kargs):
        super(DiscoveryNode, self).__init__(*args, **kargs)
        self._community_metadata_message = None
        self._user_metadata_message = None

    def set_community(self, community):
        super(DiscoveryNode, self).set_community(community)
        self._community_metadata_message = Message(community, u"community-metadata", PublicResolution(), FullSyncDistribution(), CommunityDestination())
        self._user_metadata_message = Message(community, u"user-metadata", PublicResolution(), LastSyncDistribution(), CommunityDestination())

    def create_community_metadata_message(self, cid, alias, comment, global_time, sequence_number):
        distribution = self._community_metadata_message.distribution.implement(global_time, sequence_number)
        destination = self._community_metadata_message.destination.implement()
        payload = CommunityMetadataPayload(cid, alias, comment)
        return self._community_metadata_message.implement(self._my_member, distribution, destination, payload)

    def create_user_metadata_message(self, address, alias, comment, global_time):
        distribution = self._user_metadata_message.distribution.implement(global_time)
        destination = self._user_metadata_message.destination.implement()
        payload = UserMetadataPayload(address, alias, comment)
        return self._user_metadata_message.implement(self._my_member, distribution, destination, payload)
    
class ForumNode(DiscoveryNode):
    def __init__(self, *args, **kargs):
        super(ForumNode, self).__init__(*args, **kargs)
        self._set_settings_message = None
        self._create_thread_message = None
        self._create_post_message = None

    def set_community(self, community):
        super(ForumNode, self).set_community(community)
        self._set_settings_message = Message(community, u"set-settings", LinearResolution(), LastSyncDistribution(100, 100, 0.001), CommunityDestination())
        self._create_thread_message = Message(community, u"create-thread", LinearResolution(), FullSyncDistribution(100, 100, 0.001), CommunityDestination())
        self._create_post_message = Message(community, u"create-post", LinearResolution(), FullSyncDistribution(100, 100, 0.001), CommunityDestination())

    def create_set_settings_message(self, title, description, global_time):
        distribution = self._set_settings_privilege.distribution.implement(global_time)
        destination = self._set_settings_privilege.destination.implement()
        permission = PermitPermission(self._set_settings_privilege, (title, description))
        return self.create_message(distribution, destination, permission)

    def create_create_thread_message(self, key, title, comment, global_time, sequence_number):
        distribution = self._create_thread_privilege.distribution.implement(global_time, sequence_number)
        destination = self._create_thread_privilege.destination.implement()
        permission = PermitPermission(self._create_thread_privilege, (key, title, comment))
        return self.create_message(distribution, destination, permission)

    def create_create_post_message(self, key, comment, global_time, sequence_number):
        distribution = self._create_post_privilege.distribution.implement(global_time, sequence_number)
        destination = self._create_post_privilege.destination.implement()
        permission = PermitPermission(self._create_post_privilege, (key, comment))
        return self.create_message(distribution, destination, permission)
        
