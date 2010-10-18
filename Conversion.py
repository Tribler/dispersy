from struct import pack, unpack_from
from hashlib import sha1

from Bloomfilter import BloomFilter
from Destination import MemberDestination, CommunityDestination, AddressDestination
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution, DirectDistribution, RelayDistribution
from Encoding import encode, decode
from Message import DelayPacket, DropPacket
from Message import Message
from Payload import Permit, Authorize, Revoke, MissingSequencePayload, SyncPayload

if __debug__:
    from Print import dprint

class ConversionBase(object):
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

class DictionaryConversion(ConversionBase):
    """
    On-The-Wire debug version

    This conversion is for debugging only.  The entire message is made
    into a dictionary, and is encoded using Encoding.py.  This makes
    is easy to create messages and read them without needing to
    convert them from binary first.
    """
    def __init__(self, community, version):
        ConversionBase.__init__(self, community, version)
        self._distribution_map = {FullSyncDistribution.Implementation:self._encode_full_sync_distribution,
                                  LastSyncDistribution.Implementation:self._encode_last_sync_distribution,
                                  DirectDistribution.Implementation:self._encode_direct_distribution}
        self._destination_map = {MemberDestination.Implementation:self._encode_member_destination,
                                 CommunityDestination.Implementation:self._encode_community_destination,
                                 AddressDestination.Implementation:self._encode_address_destination}
        self._message_map = dict() # message.name : (encode_payload_func, decode_payload_func)
        self.define_meta_message(community.get_meta_message(u"dispersy-missing-sequence"), self._encode_missing_sequence_payload, self._decode_missing_sequence_payload)
        self.define_meta_message(community.get_meta_message(u"dispersy-sync"), self._encode_sync_payload, self._decode_sync_payload)

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
        if __debug__:
            from Member import PrivateMemberBase
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.signed_by, PrivateMemberBase)
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

class BinaryConversion(ConversionBase):
    """
    On-The-Wire binary version

    This conversion is intended to be as space efficient as possible.
    All data is encoded in a binary form.
    """
    _encode_payload_type_map = {u"permit":"\x00", u"authorize":"\x01", u"revoke":"\x02"}
    _decode_payload_type_map = dict([(value, key) for key, value in _encode_payload_type_map.iteritems()])

    def __init__(self, community, version):
        ConversionBase.__init__(self, community, version)
        self._encode_distribution_map = {FullSyncDistribution.Implementation:self._encode_full_sync_distribution,
                                         LastSyncDistribution.Implementation:self._encode_last_sync_distribution,
                                         DirectDistribution.Implementation:self._encode_direct_distribution}
        self._decode_distribution_map = {FullSyncDistribution:self._decode_full_sync_distribution,
                                         LastSyncDistribution:self._decode_last_sync_distribution,
                                         DirectDistribution:self._decode_direct_distribution}
        self._encode_message_map = dict() # message.name : (byte, encode_payload_func)
        self._decode_message_map = dict() # byte : (message, decode_payload_func)
        self.define_meta_message(chr(254), community.get_meta_message(u"dispersy-missing-sequence"), self._encode_missing_sequence_payload, self._decode_missing_sequence_payload)
        self.define_meta_message(chr(253), community.get_meta_message(u"dispersy-sync"), self._encode_sync_payload, self._decode_sync_payload)

    def define_meta_message(self, byte, message, encode_payload_func, decode_payload_func):
        assert isinstance(byte, str)
        assert len(byte) == 1
        assert isinstance(message, Message)
        assert 0 < ord(byte) < 255
        assert not message.name in self._encode_message_map
        assert not byte in self._decode_message_map
        assert callable(encode_payload_func)
        assert callable(decode_payload_func)
        self._encode_message_map[message.name] = (byte, encode_payload_func)
        self._decode_message_map[byte] = (message, decode_payload_func)

    #
    # Dispersy payload
    #

    def _encode_missing_sequence_payload(self, message):
        assert isinstance(message.payload, MissingSequencePayload)
        payload = message.payload
        assert payload.message.name in self._encode_message_map, payload.message.name
        message_id, _ = self._encode_message_map[payload.message.name]
        return payload.member.mid, message_id, pack("!LL", payload.missing_low, payload.missing_high)

    def _decode_missing_sequence_payload(self, offset, data):
        if len(data) < offset + 29:
            raise DropPacket("Insufficient packet size")

        member_id = data[offset:offset+20]
        offset += 20
        members = self._community.get_members_from_id(member_id)
        if not members:
            raise DelayPacketByMissingMember(member_id)
        elif len(members) > 1:
            # this is unrecoverable.  a member id without a signature
            # is simply not globally unique.  This can occur when two
            # or more nodes have the same sha1 hash.  Very unlikely.
            raise DropPacket("Unrecoverable: ambiguous member")
        member = members[0]

        meta_message, _ = self._decode_message_map.get(data[offset], (None, None))
        if meta_message is None:
            raise DropPacket("Invalid message")
        offset += 1
        
        missing_low, missing_high = unpack_from("!LL", data, offset)
        offset += 8

        return offset, MissingSequencePayload(member, meta_message, missing_low, missing_high)

    def _encode_sync_payload(self, message):
        assert isinstance(message.payload, SyncPayload)
        return pack("!L", message.payload.global_time), str(message.payload.bloom_filter)

    def _decode_sync_payload(self, offset, data):
        if len(data) < offset + 4:
            raise DropPacket("Insufficient packet size")

        global_time, = unpack_from("!L", data, offset)
        offset += 4

        try:
            bloom_filter = BloomFilter(data, offset)
        except ValueError:
            raise DropPacket("Invalid bloom filter")
        offset += len(bloom_filter)

        return offset, SyncPayload(global_time, bloom_filter)

    #
    # Encoding
    #

    @staticmethod
    def _encode_full_sync_distribution(container, message):
        container.append(pack("!LL", message.distribution.global_time, message.distribution.sequence_number))

    @staticmethod
    def _encode_last_sync_distribution(container, message):
        container.append(pack("!L", message.distribution.global_time))

    @staticmethod
    def _encode_direct_distribution(container, message):
        container.append(pack("!L", message.distribution.global_time))

    def encode_message(self, message):
        if __debug__:
            from Member import PrivateMemberBase
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.signed_by, PrivateMemberBase)
        assert not message.signed_by.private_pem is None

        assert message.name in self._encode_message_map
        message_id, encode_payload_func = self._encode_message_map[message.name]

        # Signed by and the message name
        container = [self._prefix, message.signed_by.mid, message_id]
        # Destination does not hold any space in the message
        # Distribution
        assert type(message.distribution) in self._encode_distribution_map
        self._encode_distribution_map[type(message.distribution)](container, message)
        # Payload
        container.append(self._encode_payload_type_map[u"permit"])
        if isinstance(message.payload, Permit):
            if __debug__:
                tup = encode_payload_func(message)
                assert isinstance(tup, tuple)
                assert not filter(lambda x: not isinstance(x, str), tup)
                container.extend(tup)
            else:
                container.extend(encode_payload_func(message))

        elif isinstance(message.payload, Authorize):
            public_key = message.payload.to.pem
            container.extend((self._encode_payload_type_map[message.payload.payload.get_static_type()], pack("H", len(public_key)), public_key))

        else:
            raise NotImplementedError()

        # Sign
        return message.signed_by.generate_pair("".join(container))

    #
    # Decoding
    #

    @staticmethod
    def _decode_full_sync_distribution(offset, data, meta_message):
        global_time, sequence_number = unpack_from("!LL", data, offset)
        return offset + 8, meta_message.distribution.implement(global_time, sequence_number)

    @staticmethod
    def _decode_last_sync_distribution(offset, data, meta_message):
        global_time, = unpack_from("!L", data, offset)
        return offset + 4, meta_message.distribution.implement(global_time)

    @staticmethod
    def _decode_direct_distribution(offset, data, meta_message):
        global_time, = unpack_from("!L", data, offset)
        return offset + 4, meta_message.distribution.implement(global_time)

    def decode_message(self, data):
        assert isinstance(data, str)
        assert len(data) >= 22
        assert data[:22] == self._prefix

        if len(data) < 100:
            DropPacket("Packet is to small to decode")

        offset = 22

        # signed by
        member_id = data[offset:offset+20]
        offset += 20
        try:
            members = self._community.get_members_from_id(member_id)
        except KeyError:
            raise DelayPacketByMissingMember(member_id)
        for signed_by in members:
            if signed_by.verify_pair(data):
                break
        else:
            raise DelayPacketByMissingMember(member_id)

        # meta_message
        meta_message, decode_payload_func = self._decode_message_map.get(data[offset], (None, None))
        if meta_message is None:
            raise DropPacket("Invalid message byte")
        offset += 1

        # destination
        assert isinstance(meta_message.destination, (MemberDestination, CommunityDestination, AddressDestination))
        if isinstance(meta_message.destination, AddressDestination):
            destination_impl = meta_message.destination.implement(("", 0))
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
            offset, payload = decode_payload_func(offset, data)
            assert isinstance(offset, (int, long))
            assert isinstance(payload, Permit), type(payload)
            
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
        
        return meta_message.implement(signed_by, distribution_impl, destination_impl, payload)

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
