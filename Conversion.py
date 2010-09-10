from hashlib import sha1

from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Encoding import encode, decode
from Message import DelayPacket, DropPacket
from Message import Message
from Message import FullSyncDistribution, LastSyncDistribution, MinimalSyncDistribution, DirectDistribution, RelayDistribution
from Message import UserDestination, MemberDestination, CommunityDestination, PrivilegedDestination
from DispersyDatabase import DispersyDatabase

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

    def get_community(self):
        return self._community

    def get_vid(self):
        return self._prefix[20:25]

    def get_prefix(self):
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
        raise NotImplemented

    def encode_message(self, message):
        """
        Encode a Message instance into a binary string.
        """
        assert isinstance(message, Message)
        raise NotImplemented

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
       permission: {}
    }
    20 byte signature of entire message (including CID and VID)
    """
    def __init__(self, community):
        ConversionBase.__init__(self, community, "00001")

        self._encode_destination_map = {UserDestination:self._encode_user_destination,
                                        CommunityDestination:self._encode_community_destination}

        self._encode_distribution_map = {FullSyncDistribution:self._encode_full_sync_distribution,
                                         LastSyncDistribution:self._encode_last_sync_distribution,
                                         DirectDistribution:self._encode_direct_distribution}

        self._encode_permission_map = {PermitPermission:self._encode_permit_permission,
                                       AuthorizePermission:self._encode_authorize_permission}

    @staticmethod
    def _decode_global_time(container, index):
        global_time = container.get(index)
        if not isinstance(global_time, (int, long)):
            raise DropPacket("Invalid global time type")
        if global_time <= 0:
            raise DropPacket("Invalid global time value")
        return global_time

    @staticmethod
    def _decode_sequence_number(container, index):
        sequence_number = container.get(index)
        if not isinstance(sequence_number, (int, long)):
            raise DropPacket("Invalid sequence number type")
        if sequence_number <= 0:
            raise DropPacket("Invalid sequence number value")
        return sequence_number
    
    def _decode_privilege(self, container, index):
        privilege = container.get(index)
        if not isinstance(privilege, unicode):
            raise DropPacket("Invalid privilege type")
        try:
            privilege = self._community.get_privilege(privilege)
        except KeyError:
            # the privilege is not known in this community.  delay
            # message processing for a while
            raise DropPacket("Invalid privilege")
        return privilege

    @staticmethod
    def _decode_permission(container, index):
        permission = container.get(index)
        if not isinstance(permission, unicode):
            raise DropPacket("Invalid authorized permission type")
        if permission == u"permit":
            permission = PermitPermission
        elif permission == u"authorize":
            permission = AuthorizePermission
        elif permission == u"revoke":
            permission = RevokePermission
        else:
            raise DropPacket("Invalid permission")
        return permission

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

    def _decode_container(self, container, index):
        tup = container.get(index)
        if isinstance(tup, tuple):
            return tup
        else:
            DropPacket("Invalid container type")

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
        if not len(container) == 4:
            raise DropPacket("Invalid container length")

        #
        # member (signer of the message)
        #
        public_key = container.get("signed_by")
        if not isinstance(public_key, str):
            raise DropPacket("Invalid public key type")
        try:
            member = self._community.get_member(public_key)
        except KeyError:
            # todo: delay + retrieve user public key
            raise DelayPacket("Unable to find member in community")

        if not member.verify_pair(data):
            raise DropPacket("Invalid signature")

        #
        # permission
        #
        d = container.get("permission")
        if not isinstance(d, dict):
            raise DropPacket("Invalid permission type")
        t = d.get("type")
        if t == "permit":
            permission = PermitPermission(self._decode_privilege(d, "privilege_name"), self._decode_container(d, "container"))

        elif t == "authorize":
            permission = AuthorizePermission(self._decode_privilege(d, "privilege_name", self._decode_member(d, "to"), self._decode_permission(d, "permission_name")))

        else:
            raise NotImplementedError()

        #
        # destination
        #
        d = container.get("destination")
        if not isinstance(d, dict):
            raise DropPacket("Invalid destination type")
        t = d.get("type")
        if t == "user-destination":
            destination = UserDestination()

        elif t == "community-destination":
            destination = CommunityDestination()

        else:
            raise DropPacket("Invalid destination")

        #
        # distribution
        #
        d = container.get("distribution")
        if not isinstance(d, dict):
            raise DropPacket("Invalid distribution type")
        t = d.get("type")
        if t == "full-sync":
            global_time = self._decode_global_time(d, "global_time")
            sequence_number = self._decode_sequence_number(d, "sequence_number")
            try:
                self._dispersy_database.execute(u"SELECT 1 FROM sync_full WHERE user = ? and community = ? and global = ? and sequence = ?",
                                                (member.database_id, self._community.database_id, global_time, sequence_number)).next()
                raise DropPacket("Duplicate packet")
            except StopIteration:
                pass
            distribution = FullSyncDistribution(global_time, sequence_number)

        if t == "last-sync":
            global_time = self._decode_global_time(d, "global_time")
            try:
                self._dispersy_database.execute(u"SELECT 1 FROM sync_last WHERE user = ? and community = ? and global > ? and privilege = ?",
                                                (member.database_id, self._community.database_id, global_time, permission.privilege.name)).next()
                raise DropPacket("Duplicate or older packet")
            except StopIteration:
                pass
            distribution = LastSyncDistribution(global_time)

        elif container[index] == u"direct-message":
            global_time = self._decode_global_time(d, "global_time")

            # todo
            raise NotImplementedError()
            
        else:
            raise NotImplementedError()

        return Message(self._community, member, distribution, destination, permission)

    def _encode_not_implemented(self, _, obj):
        raise NotImplementedError(type(obj))

    def _encode_user_destination(self, container, _):
        container["destination"] = {"type":"user-destination"}

    def _encode_community_destination(self, container, _):
        container["destination"] = {"type":"community-destination"}

    def _encode_full_sync_distribution(self, container, distribution):
        container["distribution"] = {"type":"full-sync", "global_time":distribution.global_time, "sequence_number":distribution.sequence_number}

    def _encode_last_sync_distribution(self, container, distribution):
        container["distribution"] = {"type":"last-sync", "global_time":distribution.global_time}

    def _encode_direct_distribution(self, container, distribution):
        container["distribution"] = {"type":"direct-message", "global_time":distribution.global_time}

    def _encode_permit_permission(self, container, permission):
        container["permission"] = {"type":"permit", "privilege_name":permission.privilege.name, "container":permission.payload}

    def _encode_authorize_permission(self, container, permission):
        container["permission"] = {"type":"authorize", "privilege_name":permission.privilege.name, "permission_name":permission.permission.name, "to":permission.to.pem}

    def encode_message(self, message):
        if __debug__:
            from Member import PrivateMemberBase
        assert isinstance(message, Message)
        assert isinstance(message.signed_by, PrivateMemberBase)
        assert not message.signed_by.private_pem is None

        # stuff message in a container
        container = {"signed_by":message.signed_by.pem}
        self._encode_destination_map.get(type(message.destination), self._encode_not_implemented)(container, message.destination)
        self._encode_distribution_map.get(type(message.distribution), self._encode_not_implemented)(container, message.distribution)
        self._encode_permission_map.get(type(message.permission), self._encode_not_implemented)(container, message.permission)

        # encode and sign message
        return message.signed_by.generate_pair(self._prefix + encode(container))
    
class Conversion(Conversion00001, ConversionBase):
    """
    Conversion subclasses the current ConversionXXXXX class.
    """
    pass
