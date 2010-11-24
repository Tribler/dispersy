import socket

from Authentication import NoAuthentication
from Bloomfilter import BloomFilter
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination
from Distribution import DirectDistribution, LastSyncDistribution, FullSyncDistribution
from Member import MyMember, Member
from Message import Message
from Payload import MissingSequencePayload, SyncPayload, SignatureResponsePayload, CallbackRequestPayload, IdentityPayload, SimilarityPayload
from Print import dprint
from Resolution import PublicResolution, LinearResolution
from Member import PrivateMember

class Node(object):
    _socket_range = (8000, 8999)
    _socket_pool = {}
    _socket_counter = 0

    def __init__(self):
        self._socket = None
        self._my_member = None
        self._community = None

    @property
    def socket(self):
        return self._socket

    def init_socket(self):
        assert self._socket is None
        port = Node._socket_range[0] + Node._socket_counter % (Node._socket_range[1] - Node._socket_range[0])
        Node._socket_counter += 1

        if not port in Node._socket_pool:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
            s.setblocking(True)
            while True:
                try:
                    s.bind(("localhost", port))
                except socket.error as error:
                    port = Node._socket_range[0] + Node._socket_counter % (Node._socket_range[1] - Node._socket_range[0])
                    Node._socket_counter += 1
                    continue
                break

            Node._socket_pool[port] = s
            if __debug__: dprint("create socket ", port)

        elif __debug__:
            dprint("reuse socket ", port, level="warning")

        self._socket = Node._socket_pool[port]

    @property
    def my_member(self):
        return self._my_member

    def init_my_member(self, bits=512, sync_with_database=False, callback=True, identity=True):
        class DebugPrivateMember(PrivateMember):
            @property
            def database_id(self):
                return Member.get_instance(self.pem).database_id

        assert not sync_with_database, "The parameter sync_with_database is depricated and must be False"

        # specifically do NOT use PrivateMember.get_instance(...) here!
        rsa = rsa_generate_key(bits)
        self._my_member = DebugPrivateMember(rsa_to_public_pem(rsa), rsa_to_private_pem(rsa), sync_with_database=False)

        if callback:
            # update routing information
            assert self._socket, "Socket needs to be set to callback"
            assert self._community, "Community needs to be set to callback"
            source_address = self._socket.getsockname()
            destination_address = self._community._dispersy.socket.get_address()
            message = self.create_dispersy_callback_request_message(source_address, destination_address, 1)
            self.send_message(message, destination_address)

        if identity:
            # update database and memory
            # Member.get_instance(self._my_member.pem)

            # update routing information
            assert self._socket, "Socket needs to be set to callback"
            assert self._community, "Community needs to be set to callback"
            source_address = self._socket.getsockname()
            destination_address = self._community._dispersy.socket.get_address()
            message = self.create_dispersy_identity_message(source_address, 2)
            self.send_message(message, destination_address)

    @property
    def community(self):
        return self._community

    def set_community(self, community):
        self._community = community

    def encode_message(self, message):
        return self._community.get_conversion().encode_message(message)

    def send_packet(self, packet, address):
        dprint(len(packet), " bytes to ", address[0], ":", address[1])
        return self._socket.sendto(packet, address)

    def send_message(self, message, address):
        self.encode_message(message)
        dprint(message.payload.type, "^", message.name, " (", len(message.packet), " bytes) to ", address[0], ":", address[1])
        return self.send_packet(message.packet, address)

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
            try:
                message = self._community.get_conversion(packet[:22]).decode_message(packet)
            except KeyError:
                # not for this community
                continue

            if not (message_names is None or message.name in message_names):
                continue

            if not (payload_types is None or message.payload.type in payload_types):
                continue

            if not (distributions is None or isinstance(message.distribution, distributions)):
                continue

            if not (destinations is None or isinstance(message.destination, destinations)):
                continue

            dprint(message.payload.type, "^", message.name, " (", len(packet), " bytes) from ", address[0], ":", address[1])
            return address, message

    def create_dispersy_identity_message(self, address, global_time):
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-identity")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(),
                              IdentityPayload(address))

    def create_dispersy_callback_request_message(self, source_address, destination_address, global_time):
        assert isinstance(source_address, tuple)
        assert len(source_address) == 2
        assert isinstance(source_address[0], str)
        assert isinstance(source_address[1], int)
        assert isinstance(destination_address, tuple)
        assert len(destination_address) == 2
        assert isinstance(destination_address[0], str)
        assert isinstance(destination_address[1], int)
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-callback-request")
        return meta.implement(meta.authentication.implement(),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(destination_address),
                              CallbackRequestPayload(source_address, destination_address))
            
    def create_dispersy_sync_message(self, bloom_global_time, bloom_packets, global_time):
        assert isinstance(bloom_global_time, (int, long))
        assert isinstance(bloom_packets, list)
        assert not filter(lambda x: not isinstance(x, str), bloom_packets)
        assert isinstance(global_time, (int, long))
        bloom_filter = BloomFilter(1000, 0.001)
        map(bloom_filter.add, bloom_packets)
        meta = self._community.get_meta_message(u"dispersy-sync")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(),
                              SyncPayload(bloom_global_time, bloom_filter))

    def create_dispersy_similarity_message(self, cluster, community, similarity, global_time):
        assert isinstance(cluster, int)
        assert 0 < cluster < 2^8, "CLUSTER must fit in one byte"
        assert isinstance(similarity, BloomFilter)
        meta = self._community.get_meta_message(u"dispersy-similarity")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(),
                              SimilarityPayload(cluster, similarity))

    def create_taste_aware_message(self, number, sequence, global_time):
        assert isinstance(number, (int, long))
        meta = self._community.get_meta_message(u"taste-aware-record")
        authentication = meta.authentication.implement(self._my_member)
        distribution = meta.distribution.implement(sequence, global_time)
        destination = meta.destination.implement()

        from DebugCommunity import TasteAwarePayload
        payload = TasteAwarePayload(number)

        return meta.implement(authentication, distribution, destination, payload)

    def create_taste_aware_message_last(self, number, global_time):
        assert isinstance(number, (int, long))
        meta = self._community.get_meta_message(u"taste-aware-record-last")
        authentication = meta.authentication.implement(self._my_member)
        distribution = meta.distribution.implement(global_time)
        destination = meta.destination.implement()

        from DebugCommunity import TasteAwarePayload
        payload = TasteAwarePayload(number)

        return meta.implement(authentication, distribution, destination, payload)

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
        meta = self._community.get_meta_message(u"dispersy-missing-sequence")
        authentication = meta.authentication.implement(self._my_member)
        distribution = meta.distribution.implement(global_time)
        destination = meta.destination.implement(destination_address)
        payload = MissingSequencePayload(missing_member, missing_message_meta, missing_low, missing_high)
        return meta.implement(authentication, distribution, destination, payload)

    def create_dispersy_signature_response_message(self, request_id, signature, global_time, destination_member):
        assert isinstance(request_id, str)
        assert len(request_id) == 20
        assert isinstance(signature, str)
        assert isinstance(global_time, (int, long))
        assert isinstance(destination_member, Member)
        meta = self._community.get_meta_message(u"dispersy-signature-response")                                                
        return meta.implement(meta.authentication.implement(),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(destination_member),
                              SignatureResponsePayload(request_id, signature))
