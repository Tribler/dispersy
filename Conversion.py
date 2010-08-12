from hashlib import sha1

from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Encoding import encode, decode
from Message import DelayPacket, DropPacket
from Message import SyncMessage, DirectMessage
from Message import FullSyncDistribution, LastSyncDistribution, MinimalSyncDistribution, DirectDistribution, RelayDistribution
from Message import UserDestination, MemberDestination, CommunityDestination, PrivilegedDestination
from DispersyDatabase import DispersyDatabase
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
        self._prefix = community.get_cid() + vid

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
    [
       signer public key, in PEM format
       'user-destination'
       'direct-message'
       global time
       payload
    ]
    20 byte signature of entire message (including CID and VID)

    COMMUNITY-DESTINATION + FULL-SYNC
    =================================
    20 byte CID (community identifier)
     5 byte VID (on-the-wire protocol version)
    [
       signer public key, in PEM format
       'community-destination'
       'full-sync'
       global time
       sequence number
       permission ('permit', 'authorize', or 'revoke')
       payload
    ]
    20 byte signature of entire message (including CID and VID)
    """
    def __init__(self, community):
        ConversionBase.__init__(self, community, "00001")

    def _check_dupplicate(self, statements, sequenceofbindings):
        try:
            self._dispersy_database.execute(statements, sequenceofbindings).next()
            raise DropPacket("Duplicate packet")
        except StopIteration:
            pass
        
    @staticmethod
    def _decode_global_time(container, index):
        global_time = container[index]
        if not isinstance(global_time, (int, long)):
            raise DropPacket("Invalid global time type")
        if global_time <= 0:
            raise DropPacket("Invalid global time value")
        return index+1, global_time

    @staticmethod
    def _decode_sequence_number(container, index):
        sequence_number = container[index]
        if not isinstance(sequence_number, (int, long)):
            raise DropPacket("Invalid sequence number type")
        if sequence_number <= 0:
            raise DropPacket("Invalid sequence number value")
        return index+1, sequence_number
    
    def _decode_privilege(self, container, index):
        privilege = container[index]
        if not isinstance(privilege, unicode):
            raise DropPacket("Invalid privilege type")
        try:
            privilege = self._community.get_privilege(privilege)
        except KeyError:
            # the privilege is not known in this community.  delay
            # message processing for a while
            raise DropPacket("Invalid privilege")
        return index+1, privilege

    @staticmethod
    def _decode_permission(container, index):
        permission = container[index]
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
        return index+1, permission

    def _decode_member(self, container, index):
        public_key = container[index]
        if not isinstance(public_key, str):
            raise DropPacket("Invalid to-member type")
        try:
            member = self._community.get_member(public_key)
        except KeyError:
            # the user is not known in this community.  delay
            # message processing for a while
            raise DelayPacket("Unable to find to-member in community")
        return index+1, member

    def decode_message(self, data):
        """
        Convert version 00001 DATA into an internal data structure.
        """
        assert isinstance(data, str)
        assert len(data) >= 25
        assert data[:25] == self._prefix

        signature = data[-20:]
        container = decode(data, 25)
        if not isinstance(container, tuple):
            raise DropPacket("Invalid container type")
        if not len(container) >= 6:
            raise DropPacket("Invalid container length")

        #
        # member (signer of the message)
        #
        index = 0
        public_key = container[index]
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
        # destination
        #
        index += 1
        if container[index] == u"user-destination":
            destination = UserDestination()

        elif container[index] == u"community-destination":
            destination = CommunityDestination()

        else:
            raise DropPacket("Invalid destination")

        #
        # distribution
        #
        index += 1
        if container[index] == u"full-sync":
            index, global_time = self._decode_global_time(container, index+1)
            index, sequence_number = self._decode_sequence_number(container, index)
            self._check_dupplicate(u"SELECT 1 FROM sync_full WHERE user = ? and community = ? and global = ? and sequence = ?",
                                   (member.get_database_id(), self._community.get_database_id(), global_time, sequence_number))
            distribution = FullSyncDistribution(global_time, sequence_number)

            if container[index] == u"authorize":
                index, privilege = self._decode_privilege(container, index+1)
                index, authorized_permission = self._decode_permission(container, index)
                index, to_member = self._decode_member(container, index)
                permission = AuthorizePermission(privilege, to_member, authorized_permission)

            elif container[index] == u"permit":
                index, privilege = self._decode_privilege(container, index+1)
                permission = PermitPermission(privilege, container[index:])

            else:
                raise NotImplementedError()

            message = SyncMessage(self._community, member, distribution, destination, permission)

        if container[index] == u"last-sync":
            index, global_time = self._decode_global_time(container, index+1)
            self._check_dupplicate(u"SELECT 1 FROM sync_last WHERE user = ? and community = ? and global = ?",
                                   (member.get_database_id(), self._community.get_database_id(), global_time))
            distribution = LastSyncDistribution(global_time)

            if container[index] == u"permit":
                index, privilege = self._decode_privilege(container, index+1)
                permission = PermitPermission(privilege, container[index:])

            else:
                raise NotImplementedError()

            message = SyncMessage(self._community, member, distribution, destination, permission)

        elif container[index] == u"direct-message":
            index, global_time = self._decode_global_time(container, index+1)

            # todo
            raise NotImplementedError()
            
        else:
            raise NotImplementedError()

        return message

    def encode_message(self, message):
        assert isinstance(message, (SyncMessage, DirectMessage))

        container = [message.signed_by.get_pem()]

        #
        # destination
        #
        if isinstance(message.destination, UserDestination):
            container.append(u"user-destination")
        elif isinstance(message.destination, CommunityDestination):
            container.append(u"community-destination")
        else:
            raise NotImplementedError()

        #
        # gossip message
        #
        if isinstance(message, SyncMessage):
            if isinstance(message.distribution, FullSyncDistribution):
                container.extend((u"full-sync", message.distribution.global_time, message.distribution.sequence_number))

            elif isinstance(message.distribution, LastSyncDistribution):
                container.extend((u"last-sync", message.distribution.global_time))

            else:
                raise NotImplementedError()

            if isinstance(message.permission, AuthorizePermission):
                container.extend((u"authorize", message.permission.get_privilege().get_name(), message.permission.get_permission().get_name(), message.permission.get_to().get_pem()))

            elif isinstance(message.permission, PermitPermission):
                container.extend((u"permit", message.permission.get_privilege().get_name()))
                container.extend(message.permission.get_container())

            else:
                raise NotImplementedError()

        #
        # direct message
        #
        elif isinstance(message, DirectMessage):
            if isinstance(message.distribution, DirectDistribution):
                container.extend((u"direct-message", message.distribution.global_time))
            else:
                raise NotImplementedError()

            container.append(message.identifier)
            container.extend(message.payload)

        #
        # encode and sign message
        #
        return message.signed_by.generate_pair(self._prefix + encode(container))
    
class Conversion(Conversion00001, ConversionBase):
    """
    Conversion subclasses the current ConversionXXXXX class.
    """
    pass
