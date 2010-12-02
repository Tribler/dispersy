from socket import inet_ntoa, inet_aton
from struct import pack, unpack_from
from hashlib import sha1

from Authentication import NoAuthentication, MemberAuthentication, MultiMemberAuthentication
from Bloomfilter import BloomFilter
from Destination import MemberDestination, CommunityDestination, AddressDestination, SimilarityDestination
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution, DirectDistribution, RelayDistribution
from Encoding import encode, decode
from Message import DelayPacket, DelayPacketByMissingMember, DropPacket, Message
from Payload import Permit, Authorize, Revoke
from Payload import MissingSequencePayload
from Payload import SyncPayload
from Payload import SignatureRequestPayload, SignatureResponsePayload
from Payload import RoutingRequestPayload, RoutingResponsePayload
from Payload import IdentityPayload, IdentityRequestPayload
from Payload import SimilarityPayload, SimilarityRequestPayload
from Member import PrivateMember, MasterMember

if __debug__:
    from Print import dprint

class Conversion(object):
    """
    A Conversion object is used to convert incoming packets to a
    different, often more recent, community version.  If also allows
    outgoing messages to be converted to a different, often older,
    community version.
    """ 
    def __init__(self, community, version):
        """
        COMMUNITY instance that this conversion belongs to.
        VERSION is the conversion identifyer (on the wire version).
        """
        if __debug__: from Community import Community
        assert isinstance(community, Community)
        assert isinstance(version, str)
        assert len(version) == 2

        # the dispersy database
        self._dispersy_database = DispersyDatabase.get_instance()

        # the community that this conversion belongs to.
        self._community = community

        # the messages that this instance can handle, and that this
        # instance produces, is identified by _prefix.
        self._prefix = community.cid + version

    @property
    def community(self):
        return self._community

    @property
    def version(self):
        return self._prefix[20:22]

    @property
    def prefix(self):
        return self._prefix

    def decode_message(self, data):
        """
        DATA is a string, where the first 20 bytes indicate the CID,
        the next 2 bytes the on-the-wite VERSION, and the rest forms
        the message payload.
        
        Returns a Message instance.
        """
        assert isinstance(data, str)
        assert len(data) >= 22
        assert data[:22] == self._prefix
        raise NotImplementedError("The subclass must implement decode_message")

    def encode_message(self, message):
        """
        Encode a Message instance into a binary string that starts
        with CID and the on-the-wire VERSION.
        """
        assert isinstance(message, Message)
        raise NotImplementedError("The subclass must implement encode_message")

class DictionaryConversion(Conversion):
    """
    On-The-Wire debug version

    This conversion is for debugging only.  The entire message is made
    into a dictionary, and is encoded using Encoding.py.  This makes
    is easy to create messages and read them without needing to
    convert them from binary first.
    """
    def __init__(self, community, version):
        Conversion.__init__(self, community, version)
        self._distribution_map = {FullSyncDistribution.Implementation:self._encode_full_sync_distribution,
                                  LastSyncDistribution.Implementation:self._encode_last_sync_distribution,
                                  DirectDistribution.Implementation:self._encode_direct_distribution}
        self._destination_map = {MemberDestination.Implementation:self._encode_member_destination,
                                 CommunityDestination.Implementation:self._encode_community_destination,
                                 AddressDestination.Implementation:self._encode_address_destination}
        self._message_map = dict() # message.name : (encode_payload_func, decode_payload_func)
        self.define_meta_message(community.get_meta_message(u"dispersy-missing-sequence"), self._encode_missing_sequence_payload, self._decode_missing_sequence_payload)
        self.define_meta_message(community.get_meta_message(u"dispersy-sync"), self._encode_sync_payload, self._decode_sync_payload)
        self.define_meta_message(community.get_meta_message(u"dispersy-similarity"), self._encode_similarity_payload, self._decode_similarity_payload)
        self.define_meta_message(community.get_meta_message(u"dispersy-similarity-request"), self._encode_similarity_request_payload, self._decode_similarity_request_payload)

    def define_meta_message(self, message, encode_payload_func, decode_payload_func):
        assert isinstance(message, Message)
        assert not message.name in self._message_map
        assert callable(encode_payload_func)
        assert callable(decode_payload_func)
        self._message_map[message.name] = (encode_payload_func, decode_payload_func)

    #
    # Dispersy payload
    #

    def _encode_missing_sequence_payload(self, message):
        assert isinstance(message.payload, MissingSequencePayload)
        payload = message.payload
        return {"message":payload.message.name, "member":payload.member.pem, "missing-low":payload.missing_low, "missing-high":payload.missing_high}

    def _decode_missing_sequence_payload(self, payload):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 4:
            raise DropPacket("Invalid payload length")

        missing_low = self._check_sequence_number(payload.get("missing-low"))
        missing_high = self._check_sequence_number(payload.get("missing-high"))
        if not 0 < missing_low <= missing_high:
            raise DropPacket("Invalid missing low and high values")
        meta_message = self._check_meta_message(payload.get("message"))
        member = self._check_member(payload.get("member"))

        return MissingSequencePayload(member, meta_message, missing_low, missing_high)

    def _encode_sync_payload(self, message):
        assert isinstance(message.payload, SyncPayload)
        return {"global-time":message.payload.global_time, "bloom-filter":str(message.payload.bloom_filter)}

    def _decode_sync_payload(self, payload):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 2:
            raise DropPacket("Invalid payload length")

        global_time = self._check_global_time(payload.get("global-time"))
        bloom_filter = payload.get("bloom-filter")
        if not isinstance(bloom_filter, str):
            raise DropPacket("Invalid bloom-filter type")
        try:
            bloom_filter = BloomFilter(bloom_filter, 0)
        except ValueError:
            raise DropPacket("Invalid bloom-filter value")

        return SyncPayload(global_time, bloom_filter)

    def _encode_similarity_payload(self, message):
        assert isinstance(message.payload, SimilarityPayload)
        return {"cluster":message.payload.cluster, "similarity":str(message.payload.similarity)}

    def _decode_similarity_payload(self, payload):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 2:
            raise DropPacket("Invalid payload length")

        cluster = payload.get("cluster")
        if not isinstance(cluster, (int, long)):
            raise DropPacket("Invalid cluster type")
        if not 0 < cluster < 2^8:
            raise DropPacket("Invalid cluster value")

        similarity = payload.get("similarity")
        if not isinstance(similarity, str):
            raise DropPacket("Invalid similarity type")

        try:
            bloom_filter = BloomFilter(similarity, 0)
        except ValueError:
            raise DropPacket("Invalid similarity")

        return SimilarityPayload(cluster, similarity)

    def _encode_similarity_request_payload(self, message):
        assert isinstance(message.payload, SimilarityRequestPayload)
        return {"cluster":message.payload.cluster, "members":[member.pem for member in message.payload.members]}

    def _decode_similarity_request_payload(self, message):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 2:
            raise DropPacket("Invalid payload length")

        cluster = payload.get("cluster")
        if not isinstance(cluster, (int, long)):
            raise DropPacket("Invalid identifier")
        if not 0 < cluster < 2^8:
            raise DropPacket("Invalid cluster value")

        members = payload.get("members")
        if not isinstance(members, (tuple, list)):
            raise DropPacket("Invalid members type")
        for pem in members:
            if not isinstance(pem, str):
                raise DropPacket("Invalid member type")
        members = [Member.get_instance(pem) for pem in members]

        return SimilarityRequestPayload(cluster, members)

    #
    # Encoding
    #

    def _encode_member_destination(self, container, _):
        container["destination"] = {"debug-type":"member-destination"}

    def _encode_community_destination(self, container, _):
        container["destination"] = {"debug-type":"community-destination"}

    def _encode_address_destination(self, container, _):
        container["destination"] = {"debug-type":"address-destination"}

    def _encode_full_sync_distribution(self, container, message):
        container["distribution"] = {"debug-type":"full-sync", "global-time":message.distribution.global_time, "sequence-number":message.distribution.sequence_number}

    def _encode_last_sync_distribution(self, container, message):
        container["distribution"] = {"debug-type":"last-sync", "global-time":message.distribution.global_time}

    def _encode_direct_distribution(self, container, message):
        container["distribution"] = {"debug-type":"direct-message", "global-time":message.distribution.global_time}

    def encode_message(self, message):
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.signed_by, PrivateMember)
        assert not message.signed_by.private_pem is None

        container = {"signed-by":message.signed_by.pem, "message-name":message.name}
        assert type(message.destination) in self._destination_map
        self._destination_map[type(message.destination)](container, message)
        assert type(message.distribution) in self._distribution_map
        self._distribution_map[type(message.distribution)](container, message)

        if isinstance(message.payload, Permit):
            assert message.name in self._message_map
            payload = self._message_map[message.name][0](message)
            assert encode(payload), "Must be able to encode this payload.  Preferably a dictionary"
            container["payload"] = {"type":u"permit", "message-payload":payload}

        elif isinstance(message.payload, Authorize):
            container["payload"] = {"type":u"authorize", "to":message.payload.to.pem, "payload-type":message.payload.payload.get_static_type()}

        else:
            raise NotImplementedError()

        # Encode and sign
        return message.signed_by.generate_pair(self._prefix + encode(container))

    #
    # Decoding
    #

    @staticmethod
    def _check_global_time(global_time):
        if not isinstance(global_time, (int, long)):
            raise DropPacket("Invalid global time type")
        if global_time <= 0:
            raise DropPacket("Invalid global time value {global_time}".format(global_time=global_time))
        return global_time

    @staticmethod
    def _check_sequence_number(sequence_number):
        if not isinstance(sequence_number, (int, long)):
            raise DropPacket("Invalid sequence number type")
        if sequence_number <= 0:
            raise DropPacket("Invalid sequence number value {sequence_number}".format(sequence_number=sequence_number))
        return sequence_number
    
    @staticmethod
    def _check_payload_type(payload_type):
        if not isinstance(payload_type, unicode):
            raise DropPacket("Invalid type type")
        if not payload_type in (u"permit", u"authorize", u"revoke"):
            raise DropPacket("Invalid type")
        return payload_type

    def _check_meta_message(self, message_name):
        if not isinstance(message_name, unicode):
            raise DropPacket("Invalid meta message type")
        try:
            meta_message = self._community.get_meta_message(message_name)
        except KeyError:
            # the meta message is not known in this community
            raise DropPacket("Invalid meta message")
        return meta_message

    def _check_member(self, public_key):
        if not isinstance(public_key, str):
            raise DropPacket("Invalid to-member type")
        try:
            member = self._community.get_member(public_key)
        except KeyError:
            # the user is not known in this community.  delay
            # message processing for a while
            raise DelayPacket("Unable to find to-member in community")
        return member

    def decode_message(self, data):
        """
        Convert version 00001 DATA into an internal data structure.
        """
        assert isinstance(data, str)
        assert len(data) >= 22
        assert data[:22] == self._prefix

        container = decode(data, 22)
        if not isinstance(container, dict):
            raise DropPacket("Invalid container type")

        # signed_by
        signed_by = self._check_member(container.get("signed-by"))
        if not signed_by.verify_pair(data):
            raise DropPacket("Invalid signature")

        # meta_message
        meta_message = self._check_meta_message(container.get("message-name"))

        # destination
        assert isinstance(meta_message.destination, (MemberDestination, CommunityDestination, AddressDestination))
        if isinstance(meta_message.destination, AddressDestination):
            destination_impl = meta_message.destination.implement(("", 0))
        else:
            destination_impl = meta_message.destination.implement()

        # distribution
        d = container.get("distribution")
        if not isinstance(d, dict):
            raise DropPacket("Invalid distribution type")
        assert isinstance(meta_message.distribution, (FullSyncDistribution, LastSyncDistribution, DirectDistribution))
        if isinstance(meta_message.distribution, FullSyncDistribution):
            global_time = self._check_global_time(d.get("global-time"))
            sequence_number = self._check_sequence_number(d.get("sequence-number"))
            distribution_impl = meta_message.distribution.implement(global_time, sequence_number)
        else:
            global_time = self._check_global_time(d.get("global-time"))
            distribution_impl = meta_message.distribution.implement(global_time)

        # payload
        d = container.get("payload")
        if not isinstance(d, dict):
            raise DropPacket("Invalid permission type")
        t = self._check_payload_type(d.get("type"))
        if t == u"permit":
            assert meta_message.name in self._message_map
            payload = self._message_map[meta_message.name][1][d.get("message-payload")]
            assert isinstance(payload, Permit), type(payload)
        elif t == "authorize":
            payload_type = self._check_payload_type(d.get("payload-type"))
            payload_type = {u"authorize":Authorize, u"revoke":Revoke, u"permit":Permit}[payload_type]
            payload = Authorize(self._check_member(d.get("to")), payload_type)
        else:
            raise NotImplementedError()

        return meta_message.implement(signed_by, distribution_impl, destination_impl, payload)

class BinaryConversion(Conversion):
    """
    On-The-Wire binary version

    This conversion is intended to be as space efficient as possible.
    All data is encoded in a binary form.
    """
    _encode_payload_type_map = {u"permit":"\x00", u"authorize":"\x01", u"revoke":"\x02"}
    _decode_payload_type_map = dict([(value, key) for key, value in _encode_payload_type_map.iteritems()])

    def __init__(self, community, version):
        Conversion.__init__(self, community, version)
        self._encode_distribution_map = {FullSyncDistribution.Implementation:self._encode_full_sync_distribution,
                                         LastSyncDistribution.Implementation:self._encode_last_sync_distribution,
                                         DirectDistribution.Implementation:self._encode_direct_distribution}
        self._decode_distribution_map = {FullSyncDistribution:self._decode_full_sync_distribution,
                                         LastSyncDistribution:self._decode_last_sync_distribution,
                                         DirectDistribution:self._decode_direct_distribution}
        self._encode_message_map = dict() # message.name : (byte, encode_payload_func)
        self._decode_message_map = dict() # byte : (message, decode_payload_func)

        self.define_meta_message(chr(254), community.get_meta_message(u"dispersy-missing-sequence"), self._encode_missing_sequence, self._decode_missing_sequence)
        self.define_meta_message(chr(253), community.get_meta_message(u"dispersy-sync"), self._encode_sync, self._decode_sync)
        self.define_meta_message(chr(252), community.get_meta_message(u"dispersy-signature-request"), self._encode_signature_request, self._decode_signature_request)
        self.define_meta_message(chr(251), community.get_meta_message(u"dispersy-signature-response"), self._encode_signature_response, self._decode_signature_response)
        self.define_meta_message(chr(250), community.get_meta_message(u"dispersy-routing-request"), self._encode_routing_request, self._decode_routing_request)
        self.define_meta_message(chr(249), community.get_meta_message(u"dispersy-routing-response"), self._encode_routing_response, self._decode_routing_response)
        self.define_meta_message(chr(248), community.get_meta_message(u"dispersy-identity"), self._encode_identity, self._decode_identity)
        self.define_meta_message(chr(247), community.get_meta_message(u"dispersy-identity-request"), self._encode_identity_request, self._decode_identity_request)
        self.define_meta_message(chr(246), community.get_meta_message(u"dispersy-similarity"), self._encode_similarity, self._decode_similarity)
        self.define_meta_message(chr(245), community.get_meta_message(u"dispersy-similarity-request"), self._encode_similarity_request, self._decode_similarity_request)

    def define_meta_message(self, byte, message, encode_payload_func, decode_payload_func):
        assert isinstance(byte, str)
        assert len(byte) == 1
        assert isinstance(message, Message)
        assert 0 < ord(byte) < 255
        assert not message.name in self._encode_message_map
        assert not byte in self._decode_message_map, "This byte has already been defined ({0})".format(ord(byte))
        assert callable(encode_payload_func)
        assert callable(decode_payload_func)
        self._encode_message_map[message.name] = (byte, encode_payload_func)
        self._decode_message_map[byte] = (message, decode_payload_func)

    #
    # Dispersy payload
    #

    def _encode_missing_sequence(self, message):
        assert isinstance(message.payload, MissingSequencePayload.Implementation)
        payload = message.payload
        assert payload.message.name in self._encode_message_map, payload.message.name
        message_id, _ = self._encode_message_map[payload.message.name]
        return payload.member.mid, message_id, pack("!LL", payload.missing_low, payload.missing_high)

    def _decode_missing_sequence(self, meta_message, offset, data):
        if len(data) < offset + 29:
            raise DropPacket("Insufficient packet size")

        member_id = data[offset:offset+20]
        offset += 20
        members = self._community.get_members_from_id(member_id)
        if not members:
            raise DelayPacketByMissingMember(self._community, member_id)
        elif len(members) > 1:
            # this is unrecoverable.  a member id without a signature
            # is simply not globally unique.  This can occur when two
            # or more nodes have the same sha1 hash.  Very unlikely.
            raise DropPacket("Unrecoverable: ambiguous member")
        member = members[0]

        missing_meta_message, _ = self._decode_message_map.get(data[offset], (None, None))
        if missing_meta_message is None:
            raise DropPacket("Invalid message")
        offset += 1

        missing_low, missing_high = unpack_from("!LL", data, offset)
        offset += 8

        return offset, meta_message.payload.implement(member, missing_meta_message, missing_low, missing_high)

    def _encode_sync(self, message):
        assert isinstance(message.payload, SyncPayload.Implementation)
        return pack("!L", message.payload.global_time), str(message.payload.bloom_filter)

    def _decode_sync(self, meta_message, offset, data):
        if len(data) < offset + 4:
            raise DropPacket("Insufficient packet size")

        global_time, = unpack_from("!L", data, offset)
        offset += 4

        try:
            bloom_filter = BloomFilter(data, offset)
        except ValueError:
            raise DropPacket("Invalid bloom filter")
        offset += len(bloom_filter)

        return offset, meta_message.payload.implement(global_time, bloom_filter)

    def _encode_signature_request(self, message):
        assert isinstance(message.payload, SignatureRequestPayload.Implementation)
        return self.encode_message(message.payload.message),

    def _decode_signature_request(self, meta_message, offset, data):
        return len(data), meta_message.payload.implement(self._decode_message(data[offset:], False))

    def _encode_signature_response(self, message):
        assert isinstance(message.payload, SignatureResponsePayload.Implementation)
        return message.payload.identifier, message.payload.signature

    def _decode_signature_response(self, meta_message, offset, data):
        return len(data), meta_message.payload.implement(data[offset:offset+20], data[offset+20:])

    def _encode_routing_request(self, message):
        assert isinstance(message.payload, RoutingRequestPayload.Implementation)
        return inet_aton(message.payload.source_address[0]), pack("!H", message.payload.source_address[1]), inet_aton(message.payload.destination_address[0]), pack("!H", message.payload.destination_address[1])

    def _decode_routing_request(self, meta_message, offset, data):
        if len(data) < offset + 12:
            raise DropPacket("Insufficient packet size")

        source_address = (inet_ntoa(data[offset:offset+4]), unpack_from("!H", data, offset+4)[0])
        destination_address = (inet_ntoa(data[offset+6:offset+10]), unpack_from("!H", data, offset+10)[0])

        return offset + 12, meta_message.payload.implement(source_address, destination_address)

    def _encode_routing_response(self, message):
        assert isinstance(message.payload, RoutingResponsePayload.Implementation)
        return inet_aton(message.payload.source_address[0]), pack("!H", message.payload.source_address[1]), inet_aton(message.payload.destination_address[0]), pack("!H", message.payload.destination_address[1])

    def _decode_routing_response(self, meta_message, offset, data):
        if len(data) < offset + 12:
            raise DropPacket("Insufficient packet size")

        source_address = (inet_ntoa(data[offset:offset+4]), unpack_from("!H", data, offset+4)[0])
        destination_address = (inet_ntoa(data[offset+6:offset+10]), unpack_from("!H", data, offset+10)[0])

        return offset + 12, meta_message.payload.implement(source_address, destination_address)

    def _encode_identity(self, message):
        assert isinstance(message.payload, IdentityPayload.Implementation)
        return inet_aton(message.payload.address[0]), pack("!H", message.payload.address[1])

    def _decode_identity(self, meta_message, offset, data):
        if len(data) < offset + 6:
            raise DropPacket("Insufficient packet size")

        address = (inet_ntoa(data[offset:offset+4]), unpack_from("!H", data, offset+4)[0])

        return offset + 6, meta_message.payload.implement(address)

    def _encode_identity_request(self, message):
        assert isinstance(message.payload, IdentityRequestPayload.Implementation)
        return message.payload.mid,

    def _decode_identity_request(self, meta_message, offset, data):
        if len(data) < offset + 20:
            raise DropPacket("Insufficient packet size")

        return offset + 20, meta_message.payload.implement(data[offset:offset+20])

    def _encode_similarity(self, message):
        assert isinstance(message.payload, SimilarityPayload.Implementation)
        return pack("!B", message.payload.cluster), str(message.payload.similarity)

    def _decode_similarity(self, meta_message, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        cluster, = unpack_from("!B", data, offset)
        offset += 1

        try:
            similarity = BloomFilter(data, offset)
        except ValueError:
            raise DropPacket("Invalid similarity")
        offset += len(similarity)

        return offset, meta_message.payload.implement(cluster, similarity)

    def _encode_similarity_request(self, message):
        assert isinstance(message.payload, SimilarityRequestPayload.Implementation)
        return (pack("!B", message.payload.cluster),) + tuple([member.mid for member in message.payload.members])

    def _decode_similarity_request(self, meta_message, offset, data):
        if len(data) < offset + 21:
            raise DropPacket("Insufficient packet size")

        cluster, = unpack_from("!B", data, offset)
        offset += 1

        members = []
        while len(data) < offset + 20:
            members.extend(self._community.get_members_from_id(data[offset:offset+20]))
            offset += 20

        return offset, meta_message.payload.implement(cluster, members)

    #
    # Encoding
    #

    @staticmethod
    def _encode_full_sync_distribution(container, message):
        container.append(pack("!QL", message.distribution.global_time, message.distribution.sequence_number))

    @staticmethod
    def _encode_last_sync_distribution(container, message):
        container.append(pack("!Q", message.distribution.global_time))

    @staticmethod
    def _encode_direct_distribution(container, message):
        container.append(pack("!Q", message.distribution.global_time))

    def encode_message(self, message):
        assert isinstance(message, Message.Implementation), message

        assert message.name in self._encode_message_map, message.name
        message_id, encode_payload_func = self._encode_message_map[message.name]

        # Community prefix, message-id
        container = [self._prefix, message_id]

        # Authentication
        if isinstance(message.authentication, NoAuthentication.Implementation):
            pass
        elif isinstance(message.authentication, MemberAuthentication.Implementation):
            if message.authentication.encoding == "sha1":
                container.append(message.authentication.member.mid)
            elif message.authentication.encoding == "pem":
                container.extend((pack("!H", len(message.authentication.member.pem)), message.authentication.member.pem))
            else:
                raise NotImplementedError(message.authentication.encoding)
        elif isinstance(message.authentication, MultiMemberAuthentication.Implementation):
            container.extend([member.mid for member in message.authentication.members])
        else:
            raise NotImplementedError(type(message.authentication))

        # Destination does not hold any space in the message

        # Distribution
        assert type(message.distribution) in self._encode_distribution_map
        self._encode_distribution_map[type(message.distribution)](container, message)

        # Payload
        if isinstance(message.payload, Permit.Implementation):
            container.append(self._encode_payload_type_map[u"permit"])
            tup = encode_payload_func(message)
            assert isinstance(tup, tuple), (type(tup), encode_payload_func)
            assert not filter(lambda x: not isinstance(x, str), tup)
            container.extend(tup)

        elif isinstance(message.payload, Authorize.Implementation):
            public_key = message.payload.to.pem
            container.extend((self._encode_payload_type_map[message.payload.payload.get_static_type()], pack("H", len(public_key)), public_key))

        else:
            raise NotImplementedError(message.payload)

        # Sign
        if isinstance(message.authentication, NoAuthentication.Implementation):
            message.packet = "".join(container)

        elif isinstance(message.authentication, MemberAuthentication.Implementation):
            assert isinstance(message.authentication.member, PrivateMember)
            data = "".join(container)
            message.packet = data + message.authentication.member.sign(data)

        elif isinstance(message.authentication, MultiMemberAuthentication.Implementation):
            data = "".join(container)
            signatures = []
            for signature, member in message.authentication.signed_members:
                if signature:
                    signatures.append(signature)
                elif isinstance(member, PrivateMember):
                    signatures.append(member.sign(data))
                else:
                    signatures.append("\x00" * member.signature_length)
            message.packet = data + "".join(signatures)

        else:
            raise NotImplementedError(type(message.authentication))

        # dprint(message.packet.encode("HEX"))
        return message.packet

    #
    # Decoding
    #

    @staticmethod
    def _decode_full_sync_distribution(offset, data, meta_message):
        global_time, sequence_number = unpack_from("!QL", data, offset)
        return offset + 12, meta_message.distribution.implement(global_time, sequence_number)
 
    @staticmethod
    def _decode_last_sync_distribution(offset, data, meta_message):
        global_time, = unpack_from("!Q", data, offset)
        return offset + 8, meta_message.distribution.implement(global_time)

    @staticmethod
    def _decode_direct_distribution(offset, data, meta_message):
        global_time, = unpack_from("!Q", data, offset)
        return offset + 8, meta_message.distribution.implement(global_time)

    def _decode_authentication(self, authentication, offset, data):
        if isinstance(authentication, NoAuthentication):
            return offset, authentication.implement(), len(data)

        elif isinstance(authentication, MemberAuthentication):
            if authentication.encoding == "sha1":
                member_id = data[offset:offset+20]
                members = self._community.get_members_from_id(member_id)
                if not members:
                    raise DelayPacketByMissingMember(self._community, member_id)
                offset += 20

                for member in members:
                    first_signature_offset = len(data) - member.signature_length
                    if member.verify(data, data[first_signature_offset:], length=first_signature_offset):
                        return offset, authentication.implement(member, is_signed=True), first_signature_offset

                raise DelayPacketByMissingMember(self._community, member_id)
            
            elif authentication.encoding == "pem":
                pem_length, = unpack_from("!H", data, offset)
                offset += 2
                member = self._community.get_member(data[offset:offset+pem_length])
                offset += pem_length
                first_signature_offset = len(data) - member.signature_length
                if member.verify(data, data[first_signature_offset:], length=first_signature_offset):
                    return offset, authentication.implement(member, is_signed=True), first_signature_offset
                else:
                    raise DropPacket("Invalid signature")

            else:
                raise NotImplementedError(authentication.encoding)

        elif isinstance(authentication, MultiMemberAuthentication):
            def iter_options(members_ids):
                """
                members_ids = [[m1_a, m1_b], [m2_a], [m3_a, m3_b]]
                --> m1_a, m2_a, m3_a
                --> m1_a, m2_a, m3_b
                --> m1_b, m2_a, m3_a
                --> m1_b, m2_a, m3_b
                """
                if members_ids:
                    for member_id in members_ids[0]:
                        for others in iter_options(members_ids[1:]):
                            yield [member_id] + others
                else:
                    yield []

            members_ids = []
            for _ in range(authentication.count):
                member_id = data[offset:offset+20]
                members = self._community.get_members_from_id(member_id)
                if not members:
                    raise DelayPacketByMissingMember(self._community, member_id)
                offset += 20
                members_ids.append(members)

            for members in iter_options(members_ids):
                # try this member combination
                first_signature_offset = len(data) - sum([member.signature_length for member in members])
                signature_offset = first_signature_offset
                signatures = [""] * authentication.count
                valid_or_null = True
                for index, member in zip(range(authentication.count), members):
                    signature = data[signature_offset:signature_offset+member.signature_length]
                    # dprint("INDEX: ", index)
                    # dprint(signature.encode('HEX'))
                    if not signature == "\x00" * member.signature_length:
                        if member.verify(data, data[signature_offset:signature_offset+member.signature_length], length=first_signature_offset):
                            signatures[index] = signature
                        else:
                            valid_or_null = False
                            break
                    signature_offset += member.signature_length

                # found a valid combination
                if valid_or_null:
                    return offset, authentication.implement(members, signatures=signatures), first_signature_offset
            raise DelayPacketByMissingMember(self._community, member_id)

        raise NotImplementedError()

    def _decode_similarity_destination(self, meta_message, authentication_impl):
        if __debug__:
            from Authentication import Authentication
        assert isinstance(meta_message, Message)
        assert isinstance(authentication_impl, Authentication.Implementation)

        try:
            my_similarity, = self._dispersy_database.execute(u"SELECT similarity FROM similarity WHERE community = ? AND user = ? AND cluster = ?",
                                                             (self._community.database_id,
                                                              self._community._my_member.database_id,
                                                              meta_message.destination.cluster)).next()
        except StopIteration:
            raise DropPacket("We don't know our own similarity... should not happen")
        my_similarity = BloomFilter(str(my_similarity), 0)

        try:
            sender_similarity, = self._dispersy_database.execute(u"SELECT similarity FROM similarity WHERE community = ? AND user = ? AND cluster = ?",
                                                                 (self._community.database_id,
                                                                  authentication_impl.member.database_id,
                                                                  meta_message.destination.cluster)).next()
        except StopIteration:
            raise DelayPacketBySimilarity(self._community, authentication_impl.member, meta_message.destination)
        sender_similarity = BloomFilter(str(sender_similarity), 0)

        return meta_message.destination.implement(my_similarity.bic_occurrence(sender_similarity))

    def _decode_message(self, data, verify_all_signatures):
        """
        Decode a binary string into a Message structure, with some
        Dispersy specific parameters.

        When VERIFY_ALL_SIGNATURES is True, all signatures must be
        valid.  When VERIFY_ALL_SIGNATURES is False, signatures may be
        \x00 bytes.  Message.authentication.signed_members returns
        information on which members had a signature present.
        Signatures that are set and fail will NOT be accepted.
        """
        assert isinstance(data, str)
        assert isinstance(verify_all_signatures, bool)
        assert len(data) >= 22
        assert data[:22] == self._prefix

        if len(data) < 100:
            DropPacket("Packet is to small to decode")

        offset = 22

        # meta_message
        meta_message, decode_payload_func = self._decode_message_map.get(data[offset], (None, None))
        if meta_message is None:
            raise DropPacket("Invalid message byte")
        offset += 1

        # authentication
        offset, authentication_impl, first_signature_offset = self._decode_authentication(meta_message.authentication, offset, data)
        if verify_all_signatures and not authentication_impl.is_signed:
            raise DropPacket("Signature consists of \x00 bytes")

        # destination
        assert isinstance(meta_message.destination, (MemberDestination, CommunityDestination, AddressDestination, SimilarityDestination))
        if isinstance(meta_message.destination, AddressDestination):
            destination_impl = meta_message.destination.implement(("", 0))
        elif isinstance(meta_message.destination, MemberDestination):
            destination_impl = meta_message.destination.implement(self._community.my_member)
        elif isinstance(meta_message.destination, SimilarityDestination):
            destination_impl = self._decode_similarity_destination(meta_message, authentication_impl)
        else:
            destination_impl = meta_message.destination.implement()

        # distribution
        assert type(meta_message.distribution) in self._decode_distribution_map, type(meta_message.distribution)
        offset, distribution_impl = self._decode_distribution_map[type(meta_message.distribution)](offset, data, meta_message)

        # payload
        payload_type = self._decode_payload_type_map.get(data[offset])
        if payload_type is None:
            raise DropPacket("Invalid payload type")
        offset += 1
        if payload_type == u"permit":
            try:
                offset, payload = decode_payload_func(meta_message, offset, data[:first_signature_offset])
            except:
                dprint(decode_payload_func)
                raise
            assert isinstance(offset, (int, long))
            assert isinstance(payload, Permit.Implementation), type(payload)

        elif payload_type == u"authorize":
            authorized_payload = self._decode_payload_type_map.get(data[offset])
            if authorized_payload is None:
                raise DropPacket("Invalid payload type (2)")
            offset += 1

            public_key_length, = unpack_from("H", data, offset)
            offset += 2
            try:
                member = self._community.get_member(data[offset:offset+public_key_length])
            except KeyError:
                # todo: delay + retrieve user public key
                raise DelayPacket("Unable to find member in community")
            offset += public_key_length

            payload = Authorized(member, authorized_payload)

        else:
            raise NotImplementedError()

        message_impl =  meta_message.implement(authentication_impl, distribution_impl, destination_impl, payload)
        message_impl.packet = data
        return message_impl

    def decode_message(self, data):
        """
        Decode a binary string into a Message structure.
        """
        return self._decode_message(data, True)

class DefaultConversion(BinaryConversion):
    """
    This conversion class is initially used to encode some Dispersy
    specific messages during the creation of a new Community
    (authorizing the initial member).  Afterwards it is usually
    replaced by a Community specific conversion that also supplies
    payload conversion for the Community specific messages.
    """
    def __init__(self, community):
        super(DefaultConversion, self).__init__(community, "\x00\x00")
