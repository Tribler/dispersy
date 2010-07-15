from hashlib import sha1

from Timeline import Timeline
from Privilege import PublicPrivilege
from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Conversion import Conversion
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Member import MasterMember, MyMember, Member
from Message import SyncMessage, DirectMessage, FullSyncDistribution, DirectDistribution, CommunityDestination, UserDestination, DelayMessageByProof
from Encoding import encode

class Community(object):
    """
    The Community module manages the participation and the reconstruction
    of the current state of a distributed community.
    """
    @staticmethod
    def create_community(cls, privileges, my_member):
        """
        Create a new CLS community with PRIVILEGES owned by MY_MEMBER.

        CLS is a Community subclass.  A new instance of this is returned.
        PRIVILEGES is a list with Privileges that will be created.
        MY_MEMBER is a Member that will be granted all Permissions for PRIVILEGES.
        """
        if __debug__:
            from Privilege import PrivilegeBase
        assert isinstance(privileges, (tuple, list))
        assert not filter(lambda x: not isinstance(x, PrivilegeBase), privileges)
        assert isinstance(my_member, MyMember)

        # master key and community id
        rsa = rsa_generate_key(512)
        public_pem = rsa_to_public_pem(rsa)
        private_pem = rsa_to_private_pem(rsa)
        cid = buffer(sha1(public_pem).digest())
        master_member = MasterMember(private_pem)

        database = DispersyDatabase.get_instance()
        database.execute(u"INSERT INTO community(cid, pem) VALUES(?, ?)", (cid, private_pem))

        # new community instance
        community = cls(cid, my_member)
        dispersy = Dispersy.get_instance()
        dispersy.add_community(community)

        permission_pairs = []
        for privilege in privileges:
            if not isinstance(privilege, PublicPrivilege):
                for permission in (AuthorizePermission, RevokePermission, PermitPermission):
                    permission_pairs.append((privilege, permission))
        if permission_pairs:
            community.authorize(my_member, permission_pairs, True)

        return community

    def __init__(self, cid, my_member):
        """
        CID is the community identifier.
        MY_MEMBER is the person participating in the community.
        """
        assert isinstance(cid, buffer)
        assert len(cid) == 20
        assert isinstance(my_member, MyMember)

        # community identifier
        self._cid = cid

        # the person participating in the community
        self._my_member = my_member

        # dictionary containing available conversions.  currently only
        # contains one conversion (the default 00001)
        default_conversion = Conversion(self)
        self._conversions = {None:default_conversion, default_conversion.get_prefix():default_conversion}

        # dispersy
        self._dispersy = Dispersy.get_instance()
        
        # community database id and master key
        self._dispersy_database = DispersyDatabase.get_instance()
        try:
            id_, pem = self._dispersy_database.execute(u"SELECT id, pem FROM community WHERE cid == ? LIMIT 1", (self._cid,)).next()
        except StopIteration:
            # community not found in database
            raise ValueError
        self._database_id = id_
        self._master_member = MasterMember(pem)

        # dictionary with all community members
        # todo: load from database
        self._members = {self._master_member.get_pem():self._master_member,
                         self._my_member.get_pem():self._my_member}

        # initial timeline containing all known privileges
        self._timeline = Timeline(self)

    def get_cid(self):
        return self._cid

    def get_database_id(self):
        return self._database_id

    def get_member(self, public_key):
        """
        Returns a Member instance associated with PUBLIC_KEY.
        """
        assert isinstance(public_key, buffer)
        if not public_key in self._members:
            self._members[public_key] = Member(public_key)
        return self._members[public_key]

    def get_master_member(self):
        """
        Returns the community MasterMember instance.
        """
        return self._master_member

    def get_my_member(self):
        """
        Returns our own MyMember instance.
        """
        return self._my_member
        
    def get_conversion(self, prefix=None):
        # todo: add parameter to specify the conversion version
        return self._conversions[prefix]

    def authorize(self, member, permission_pairs, sign_with_master=False):
        """
        Grant MEMBER the PERMISSION_PAIRS.

        MEMBER is the Member who will obtain the new permissions.
        PERMISSIONS_PAIRS is a list containing (Privilege, Permission) tuples.
         where Privilege is the Privilege that the Member will obtain and
         where Permission is the Permission for that Privilege that the Member will obtain.
        SIGN_WITH_MASTER when True the MasterMember is used to sign the authorize message.
        """
        if __debug__:
            from Privilege import PrivilegeBase
            from Permission import PermissionBase
        assert isinstance(member, Member)
        assert isinstance(permission_pairs, (tuple, list))
        assert not filter(lambda x: not (isinstance(x, tuple) and len(x) == 2 and isinstance(x[0], PrivilegeBase) and issubclass(x[1], PermissionBase)), permission_pairs)
        assert isinstance(sign_with_master, bool)

        if sign_with_master:
            signer = self.get_master_member()
        else:
            signer = self.get_my_member()

        messages = []
        global_time = self._timeline.claim_global_time()
        for privilege, permission in permission_pairs:
            messages.append(SyncMessage(self, signer, FullSyncDistribution(global_time, signer.claim_sequence_number()), CommunityDestination(), AuthorizePermission(privilege, member, permission)))

        # update locally
        for message in messages:
            assert self._timeline.check(message.signed_by, message.permission, message.distribution.global_time)
            self.on_dispersy_message(message)

        # distribute messages so others can update their timeline
        self._dispersy.queue_outgoing_messages(messages)

    def permit(self, permission, sign_with_master=False):
        assert isinstance(permission, PermitPermission)

        if sign_with_master:
            signer = self.get_master_member()
        else:
            signer = self.get_my_member()

        global_time = self._timeline.claim_global_time()
        message = SyncMessage(self, signer, FullSyncDistribution(global_time, signer.claim_sequence_number()), CommunityDestination(), permission)

        # update locally
        assert self._timeline.check(message.signed_by, message.permission, message.distribution.global_time)
        self.on_message(message)

        # distribute messages
        self._dispersy.queue_outgoing_messages([message])

    def on_incoming_dispersy_message(self, address, packet, message):
        """
        A Dispersy message was received from an external source.
        """
        assert isinstance(address, tuple)
        assert isinstance(message, SyncMessage)
        assert isinstance(message.permission, (AuthorizePermission, RevokePermission))
        if self._timeline.check(message.signed_by, message.permission, message.distribution.global_time):
            return self.on_dispersy_message(message)

        else:
            raise DelayMessageByProof()

    def on_dispersy_message(self, message):
        """
        A Dispersy message was received, it was either locally
        generated or received from an external source.
        """
        assert isinstance(message, SyncMessage)
        # update our timeline
        self._timeline.update(message.signed_by, message.permission, message.distribution.global_time)
        # we should distribute the message as defined by the
        # distribution policy
        self._dispersy.queue_outgoing_messages([message])

    def on_incoming_message(self, address, packet, message):
        """
        A message was received from an external source.
        """
        if __debug__:
            from Message import MessageBase
        assert isinstance(address, tuple)
        assert isinstance(message, MessageBase)
        if self._timeline.check(message.signed_by, message.permission, message.distribution.global_time):
            return self.on_message(message)

        else:
            raise DelayMessageByProof()

    def on_message(self, message):
        """
        A message was received, it was either locally generated or
        received from an external source.

        Must be implemented in community specific code.
        """
        if __debug__:
            from Message import MessageBase
        assert isinstance(message, MessageBase)
        raise NotImplemented()
        
    def get_privilege(self, name):
        """
        Must be implemented in community specific code.
        """
        assert isinstance(name, unicode)
        raise NotImplemented()

