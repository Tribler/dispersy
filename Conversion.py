from hashlib import sha1

from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Encoding import encode, decode
from Message import DelayPacket, DropPacket
from Message import SyncMessage, DirectMessage
from Message import FullSyncDistribution, MinimalSyncDistribution, DirectDistribution, RelayDistribution
from Message import UserDestination, MemberDestination, CommunityDestination, PrivilegedDestination

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
        if not isinstance(public_key, buffer):
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
            # global_time
            index += 1
            global_time = container[index]
            if not isinstance(global_time, (int, long)):
                raise DropPacket("Invalid global time type")
            if global_time <= 0:
                raise DropPacket("Invalid global time value")

            # sequence_number
            index += 1
            sequence_number = container[index]
            if not isinstance(sequence_number, (int, long)):
                raise DropPacket("Invalid sequence number type")
            if sequence_number <= 0:
                raise DropPacket("Invalid sequence number value")

            distribution = FullSyncDistribution(global_time, sequence_number)

            index += 1
            if container[index] == u"authorize":
                # privilege
                index += 1
                privilege = container[index]
                if not isinstance(privilege, unicode):
                    raise DropPacket("Invalid privilege type")
                try:
                    privilege = self._community.get_privilege(privilege)
                except KeyError:
                    # the privilege is not known in this community.  delay
                    # message processing for a while
                    raise DropPacket("Invalid privilege")

                # authorized_permission
                index += 1
                authorized_permission = container[index]
                if not isinstance(authorized_permission, unicode):
                    raise DropPacket("Invalid authorized permission type")
                if authorized_permission == u"permit":
                    authorized_permission = PermitPermission
                elif authorized_permission == u"authorize":
                    authorized_permission = AuthorizePermission
                elif authorized_permission == u"revoke":
                    authorized_permission = RevokePermission
                else:
                    raise DropPacket("Invalid permission")

                # to_member
                index += 1
                public_key = container[index]
                if not isinstance(public_key, buffer):
                    raise DropPacket("Invalid to-member type")
                try:
                    to_member = self._community.get_member(public_key)
                except KeyError:
                    # the user is not known in this community.  delay
                    # message processing for a while
                    raise DelayPacket("Unable to find to-member in community")

                # message payload
                permission = AuthorizePermission(privilege, to_member, authorized_permission)

            elif container[index] == u"permit":
                # privilege
                index += 1
                privilege = container[index]
                if not isinstance(privilege, unicode):
                    raise DropPacket("Invalid target privilege type")
                try:
                    privilege = self._community.get_privilege(privilege)
                except KeyError:
                    # the privilege is not known in this community.  delay
                    # message processing for a while
                    raise DropPacket("Invalid target privilege")

                # message payload
                index += 1
                permission = PermitPermission(privilege, container[index:])

            else:
                raise NotImplemented()

            message = SyncMessage(self._community, member, distribution, destination, permission)

        elif container[index] == u"direct-message":
            # global_time
            index += 1
            global_time = container[index]
            if not isinstance(global_time, (int, long)):
                raise DropPacket("Invalid global time type")
            if global_time <= 0:
                raise DropPacket("Invalid global time value")

            # todo
            raise NotImplemented()
            
        else:
            raise NotImplemented()

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
            raise NotImplemented()

        #
        # gossip message
        #
        if isinstance(message, SyncMessage):
            if isinstance(message.distribution, FullSyncDistribution):
                container.extend((u"full-sync", message.distribution.global_time, message.distribution.sequence_number))
            else:
                raise NotImplemented()

            if isinstance(message.permission, AuthorizePermission):
                container.extend((u"authorize", message.permission.get_privilege().get_name(), message.permission.get_permission().get_name(), message.permission.get_to().get_pem()))

            elif isinstance(message.permission, PermitPermission):
                container.extend((u"permit", message.permission.get_privilege().get_name()))
                container.extend(message.permission.get_container())

            else:
                raise NotImplemented()

        #
        # direct message
        #
        elif isinstance(message, DirectMessage):
            if isinstance(message.distribution, DirectDistribution):
                container.extend((u"direct-message", message.distribution.global_time))
            else:
                raise NotImplemented()

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
