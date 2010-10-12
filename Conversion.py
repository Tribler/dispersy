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
    def __init__(self, community, vid):
        """
        COMMUNITY instance that this conversion belongs to.
        VID is the conversion identifyer (on the wire version).
        """
        if __debug__: from Community import Community
        assert isinstance(community, Community)
        assert isinstance(vid, str)
        assert len(vid) == 5

        # the dispersy database
        self._dispersy_database = DispersyDatabase.get_instance()

        # the community that this conversion belongs to.
        self._community = community

        # the messages that this instance can handle, and that this
        # instance produces, is identified by _prefix.
        self._prefix = community.cid + vid

    @property
    def community(self):
        return self._community

    @property
    def vid(self):
        return self._prefix[20:25]

    @property
    def prefix(self):
        return self._prefix

    def decode_message(self, data):
        """
        DATA is a string, where the first 20 bytes indicate the CID,
        the next 5 byres the VID, and the rest forms a CID and VID
        dependent message payload.
        
        Returns a Message instance.
        """
        assert isinstance(data, str)
        assert len(data) >= 25
        assert data[:25] == self._prefix
        raise NotImplementedError()

    def encode_message(self, message):
        """
        Encode a Message instance into a binary string.
        """
        assert isinstance(message, Message)
        raise NotImplementedError()

class Conversion00001(ConversionBase):
    """
    On-The-Wire version 00001.

    USER-DESTINATION + DIRECT-MESSAGE
    =================================
    20 byte CID (community identifier)
     5 byte VID (on-the-wire protocol version)
    {
       signed_by: "public key, in PEM format"
       destination: {}
       distribution: {}
       payload: {}
    }
    20 byte signature of entire message (including CID and VID)
    """
    def __init__(self, community):
        ConversionBase.__init__(self, community, "00001")

        self._encode_destination_map = {MemberDestination.Implementation:self._encode_member_destination,
                                        CommunityDestination.Implementation:self._encode_community_destination,
                                        AddressDestination.Implementation:self._encode_address_destination}

        self._encode_distribution_map = {FullSyncDistribution.Implementation:self._encode_full_sync_distribution,
                                         LastSyncDistribution.Implementation:self._encode_last_sync_distribution,
                                         DirectDistribution.Implementation:self._encode_direct_distribution}

        self._decode_payload_map = {u"dispersy-missing-sequence":self._decode_missing_sequence_payload,
                                    u"dispersy-sync":self._decode_sync_payload}

        self._encode_payload_map = {u"dispersy-missing-sequence":self._encode_missing_sequence_payload,
                                    u"dispersy-sync":self._encode_sync_payload}

    @staticmethod
    def _decode_not_implemented(*args):
        if __debug__: dprint(args, level="warning")
        raise DropPacket("Unknown payload")

    @staticmethod
    def _encode_not_implemented(*args):
        raise NotImplementedError(*args)

    def _decode_missing_sequence_payload(self, _, payload):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 4:
            raise DropPacket("Invalid payload length")

        missing_low = self._decode_sequence_number(payload, "missing-low")
        missing_high = self._decode_sequence_number(payload, "missing-high")
        if not 0 < missing_low <= missing_high:
            raise DropPacket("Invalid missing low and high values")
        meta_message = self._decode_meta_message(payload, "message")
        member = self._decode_member(payload, "member")

        return MissingSequencePayload(member, meta_message, missing_low, missing_high)

    def _encode_missing_sequence_payload(self, message):
        assert isinstance(message.payload, MissingSequencePayload)
        payload = message.payload
        return {"message":payload.message.name, "member":payload.member.pem, "missing-low":payload.missing_low, "missing-high":payload.missing_high}

    def _decode_sync_payload(self, _, payload):
        if not isinstance(payload, dict):
            raise DropPacket("Invalid payload type")
        if not len(payload) == 2:
            raise DropPacket("Invalid payload length")

        global_time = payload.get("global-time")
        if not isinstance(global_time, (int, long)):
            raise DropPacket("Invalid global-time type")
        if not global_time > 0:
            raise DropPacket("Invalid global-time value")

        bloom_filter = payload.get("bloom-filter")
        if not isinstance(bloom_filter, str):
            raise DropPacket("Invalid bloom-filter type")

        return SyncPayload(global_time, BloomFilter(bloom_filter))

    def _encode_sync_payload(self, message):
        assert isinstance(message.payload, SyncPayload)
        return {"global-time":message.payload.global_time, "bloom-filter":str(message.payload.bloom_filter)}

    @staticmethod
    def _decode_global_time(container, index):
        global_time = container.get(index)
        if not isinstance(global_time, (int, long)):
            raise DropPacket("Invalid global time type")
        if global_time <= 0:
            raise DropPacket("Invalid global time value {global_time}".format(global_time=global_time))
        return global_time

    @staticmethod
    def _decode_sequence_number(container, index):
        sequence_number = container.get(index)
        if not isinstance(sequence_number, (int, long)):
            raise DropPacket("Invalid sequence number type")
        if sequence_number <= 0:
            raise DropPacket("Invalid sequence number value {sequence_number}".format(sequence_number=sequence_number))
        return sequence_number
    
    def _decode_meta_message(self, container, index):
        message_name = container.get(index)
        if not isinstance(message_name, unicode):
            raise DropPacket("Invalid meta message type")
        try:
            meta_message = self._community.get_meta_message(message_name)
        except KeyError:
            # the meta message is not known in this community
            raise DropPacket("Invalid meta message")
        return meta_message

    def _decode_type(self, container, index):
        type_ = container.get(index)
        if not isinstance(type_, str):
            raise DropPacket("Invalid type type")
        if not type_ in (u"permit", u"authorize", u"revoke"):
            raise DropPacket("Invalid type")
        return type_

    def _decode_member(self, container, index):
        public_key = container.get(index)
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
        assert len(data) >= 25
        assert data[:25] == self._prefix

        signature = data[-20:]
        container = decode(data, 25)
        if not isinstance(container, dict):
            raise DropPacket("Invalid container type")

        #
        # member (signer of the message)
        #
        public_key = container.get("signed-by")
        if not isinstance(public_key, str):
            raise DropPacket("Invalid public key type")
        try:
            signed_by = self._community.get_member(public_key)
        except KeyError:
            # todo: delay + retrieve user public key
            raise DelayPacket("Unable to find member in community")

        if not signed_by.verify_pair(data):
            raise DropPacket("Invalid signature")

        #
        # message
        #
        t = container.get("message-name")
        if not isinstance(t, unicode):
            raise DropPacket("Invalid message name type")
        try:
            meta_message = self._community.get_meta_message(t)
        except KeyError:
            raise DropPacket("Invalid message name")

        d = container.get("payload")
        if not isinstance(d, dict):
            raise DropPacket("Invalid permission type")
        t = self._decode_type(d, "type")
        if t == u"permit":
            payload = self._decode_payload_map.get(meta_message.name, self._decode_not_implemented)(d, d.get("payload"))
            assert isinstance(payload, Permit)
        elif t == "authorize":
            payload = Authorize(self._decode_member(d, "to"), self._decode_type(d, "payload-type"))
        else:
            raise NotImplementedError()

        #
        # destination
        #
        if isinstance(meta_message.destination, MemberDestination):
            destination = meta_message.destination.implement()

        elif isinstance(meta_message.destination, CommunityDestination):
            destination = meta_message.destination.implement()

        elif isinstance(meta_message.destination, AddressDestination):
            destination = meta_message.destination.implement(("", 0))

        else:
            raise DropPacket("Invalid destination")

        #
        # distribution
        #
        d = container.get("distribution")
        if not isinstance(d, dict):
            raise DropPacket("Invalid distribution type")
        if isinstance(meta_message.distribution, FullSyncDistribution):
            global_time = self._decode_global_time(d, "global-time")
            sequence_number = self._decode_sequence_number(d, "sequence-number")
            distribution = meta_message.distribution.implement(global_time, sequence_number)

        elif isinstance(meta_message.distribution, LastSyncDistribution):
            global_time = self._decode_global_time(d, "global-time")
            distribution = meta_message.distribution.implement(global_time)

        elif isinstance(meta_message.distribution, DirectDistribution):
            global_time = self._decode_global_time(d, "global-time")
            distribution = meta_message.distribution.implement(global_time)
            
        else:
            raise NotImplementedError()

        return meta_message.implement(signed_by, distribution, destination, payload)

    def _encode_member_destination(self, container, _):
        container["destination"] = {"debug-type":"member-destination"}

    def _encode_community_destination(self, container, _):
        container["destination"] = {"debug-type":"community-destination"}

    def _encode_address_destination(self, container, _):
        container["destination"] = {"debug-type":"address-destination"}

    def _encode_full_sync_distribution(self, container, message):
        container["distribution"] = {"global-time":message.distribution.global_time, "sequence-number":message.distribution.sequence_number}
        container["distribution"]["debug-type"] = "full-sync"

    def _encode_last_sync_distribution(self, container, message):
        container["distribution"] = {"global-time":message.distribution.global_time}
        container["distribution"]["debug-type"] = "last-sync"

    def _encode_direct_distribution(self, container, message):
        container["distribution"] = {"global-time":message.distribution.global_time}
        container["distribution"]["debug-type"] = "direct-message"

    def _encode_permit_payload(self, container, message):
        payload = self._encode_payload_map.get(message.name, self._encode_not_implemented)(message)
        assert isinstance(payload, dict)
        container["payload"] = {"type":"permit", "payload":payload}

    def _encode_authorize_payload(self, container, message):
        container["payload"] = {"type":"authorize", "to":message.payload.to.pem, "payload":message.payload.payload.get_static_type()}

    def encode_message(self, message):
        if __debug__:
            from Member import PrivateMemberBase
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.signed_by, PrivateMemberBase)
        assert not message.signed_by.private_pem is None

        # stuff message in a container
        container = {"signed-by":message.signed_by.pem, "message-name":message.name}
        self._encode_destination_map.get(type(message.destination), self._encode_not_implemented)(container, message)
        self._encode_distribution_map.get(type(message.distribution), self._encode_not_implemented)(container, message)

        if isinstance(message.payload, Permit):
            self._encode_permit_payload(container, message)
        elif isinstance(message.payload, Authorize):
            self._encode_authorize_payload(container, message)
        else:
            raise NotImplementedError()

        # encode and sign message
        return message.signed_by.generate_pair(self._prefix + encode(container))

class DefaultConversion(Conversion00001):
    """
    Conversion subclasses the current ConversionXXXXX class.
    """
    pass
