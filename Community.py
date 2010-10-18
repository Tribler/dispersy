from hashlib import sha1

from Bloomfilter import BloomFilter
from Conversion import DefaultConversion
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Encoding import encode
from Member import MasterMember, MyMember, Member
from Message import Message, DelayMessageByProof
from Payload import Permit, Authorize, Revoke
from Resolution import PublicResolution
from Timeline import Timeline

if __debug__:
    from Print import dprint

class Community(object):
    """
    The Community module manages the participation and the reconstruction
    of the current state of a distributed community.
    """
    @classmethod
    def create_community(cls, my_member, *args, **kargs):
        """
        Create a new CLS community owned by MY_MEMBER.

        CLS is a Community subclass.  A new instance of this is returned.
        MY_MEMBER is a Member that will be granted Permit, Authorize, and Revoke for all messages.
        *ARGS are passed along to __init__
        **KARGS are passed along to __init__
        """
        assert isinstance(my_member, MyMember)

        # master key and community id
        rsa = rsa_generate_key(1024 * 2)
        public_pem = rsa_to_public_pem(rsa)
        private_pem = rsa_to_private_pem(rsa)
        cid = sha1(public_pem).digest()

        database = DispersyDatabase.get_instance()
        with database as execute:
            execute(u"INSERT INTO community(user, cid, master_pem) VALUES(?, ?, ?)", (my_member.database_id, buffer(cid), buffer(public_pem)))
            database_id = database.last_insert_rowid
            execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(cid), buffer(public_pem)))
            execute(u"INSERT INTO key(public_pem, private_pem) VALUES(?, ?)", (buffer(public_pem), buffer(private_pem)))
            execute(u"INSERT INTO routing(community, host, port, incoming_time, outgoing_time) SELECT ?, host, port, incoming_time, outgoing_time FROM routing WHERE community = 0", (database_id,))

        # new community instance
        community = cls(cid, *args, **kargs)

        # authorize MY_MEMBER for each message
        permission_pairs = []
        for message in community.get_meta_messages():
            if not isinstance(message.resolution, PublicResolution):
                for allowed in (Authorize, Revoke, Permit):
                    permission_pairs.append((message, allowed))
        if permission_pairs:
            community.authorize(my_member, permission_pairs, True)

        return community

    @staticmethod
    def join_community(cls, master_pem, my_member, *args, **kargs):
        """
        Joins a discovered community.  Returns a Community subclass
        instance.
        """
        assert isinstance(master_pem, str)
        assert isinstance(my_member, MyMember)
        cid = sha1(master_pem).digest()
        database = DispersyDatabase.get_instance()
        database.execute(u"INSERT INTO community(user, cid, master_pem) VALUES(?, ?, ?)",
                         (my_member.database_id, buffer(cid), master_pem))

        # new community instance
        return cls(cid, *args, **kargs)

    @staticmethod
    def load_communities():
        """
        Load existing communities.  Returns a list with zero or more
        Community subclass instances.
        """
        raise NotImplementedError()

    def __init__(self, cid):
        """
        CID is the community identifier.
        """
        assert isinstance(cid, str)
        assert len(cid) == 20

        # community identifier
        self._cid = cid

        # incoming message map
        self._incoming_payload_type_map = {u"permit":self.on_message,
                                           u"authorize":self.on_authorize_message,
                                           u"revoke":self.on_revoke_message}

        # dispersy
        self._dispersy = Dispersy.get_instance()
        self._dispersy_database = DispersyDatabase.get_instance()

        try:
            community_id, master_pem, user_pem = self._dispersy_database.execute(u"""
            SELECT community.id, community.master_pem, user.pem
            FROM community
            LEFT JOIN user ON community.user = user.id
            WHERE cid == ?
            LIMIT 1""", (buffer(self._cid),)).next()

            # the database returns <buffer> types, we use the binary
            # <str> type internally
            master_pem = str(master_pem)
            user_pem = str(user_pem)
           
        except StopIteration:
            raise ValueError(u"Community not found in database")
        self._database_id = community_id
        self._my_member = MyMember.get_instance(user_pem)
        self._master_member = MasterMember.get_instance(master_pem)

        # define all available messages
        self._meta_messages = {}
        for meta_message in self._dispersy.get_meta_messages(self):
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message
        for meta_message in self.get_meta_messages():
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message

        # the list with bloom filters.  the list will grow as the
        # global time increases.  The 1st bloom filter will contain
        # all stored messages from global time 1 to stepping.  The 2nd
        # from stepping to 2*stepping, etc.
        self._bloom_filter_stepping = 100
        self._bloom_filters = [BloomFilter(100, 0.01)]
        # todo: if we are only using LastSyncDistribution then it is
        # possible that only the last elements of the _bloom_filters
        # are used.  We should make this into a dictionary and keep it
        # clean once a bloomfilter becomes obsolete.

        # dictionary containing available conversions.  currently only
        # contains one conversion.
        self._conversions = {}
        self.add_conversion(DefaultConversion(self), True)

        # initial timeline.  the timeline will keep track of member
        # permissions
        self._timeline = Timeline(self)

        # tell dispersy that there is a new community
        self._dispersy.add_community(self)

    def get_bloom_filter(self, global_time):
        """
        Returns the bloom-filter associated to global-time
        """
        index = global_time / self._bloom_filter_stepping
        while len(self._bloom_filters) <= index:
            self._bloom_filters.append(BloomFilter(100, 0.01))
        return self._bloom_filters[index]

    def get_current_bloom_filter(self):
        """
        Returns (global-time, bloom-filter)
        """
        index = len(self._bloom_filters) - 1
        return index * self._bloom_filter_stepping + 1, self._bloom_filters[index]

    @property
    def cid(self):
        return self._cid

    @property
    def database_id(self):
        return self._database_id

    @property
    def master_member(self):
        """
        Returns the community MasterMember instance.
        """
        return self._master_member

    @property
    def my_member(self):
        """
        Returns our own MyMember instance.
        """
        return self._my_member
        
    def get_member(self, public_key):
        """
        Returns a Member instance associated with PUBLIC_KEY.

        Since we have the PUBLIC_KEY, we can create this user when it
        didn't already exist.  Hence, this method always succeeds.
        """
        assert isinstance(public_key, str)
        return Member.get_instance(public_key)

    def get_members_from_id(self, mid):
        """
        Returns one or more Member instances associated with MID.  MID
        is the sha1 hash of a member public key.

        Since we may not have the public key associated to MID, this
        method may return an empty list.  In such a case it is
        sometimes possoble to DelayPacketByMissingMember to obtain the
        public key.
        """
        assert isinstance(mid, str)
        assert len(mid) == 20
        return [Member.get_instance(str(pem)) for pem, in self._dispersy_database.execute(u"SELECT pem FROM user WHERE mid = ?", (buffer(mid),))]

    def get_conversion(self, prefix=None):
        assert prefix is None or isinstance(prefix, str)
        assert prefix is None or len(prefix) == 22
        return self._conversions[prefix]

    def add_conversion(self, conversion, default=False):
        if __debug__:
            from Conversion import ConversionBase
        assert isinstance(conversion, ConversionBase)
        assert isinstance(default, bool)
        assert not conversion.prefix in self._conversions
        if default:
            self._conversions[None] = conversion
        self._conversions[conversion.prefix] = conversion

    def authorize(self, member, permission_pairs, sign_with_master=False, update_locally=True, store_and_forward=True):
        """
        Grant MEMBER the PERMISSION_PAIRS.


        MEMBER is the Member who will obtain the new permissions.
        PERMISSIONS_PAIRS is a list containing (Message, Payload)
         tuples.  where Message is the meta message for which Member
         may send Payload
        SIGN_WITH_MASTER when True the MasterMember is used to sign
         the authorize message.
        """
        assert isinstance(member, Member)
        assert isinstance(permission_pairs, (tuple, list))
        assert not filter(lambda x: not isinstance(x, tuple), permission_pairs)
        assert not filter(lambda x: not len(x) == 2, permission_pairs)
        assert not filter(lambda x: not isinstance(x[0], Message), permission_pairs)
        assert not filter(lambda x: not issubclass(x[1], (Authorize, Revoke, Permit)), permission_pairs)
        assert isinstance(sign_with_master, bool)
        assert isinstance(update_locally, bool)
        assert isinstance(store_and_forward, bool)

        if sign_with_master:
            signed_by = self.master_member
        else:
            signed_by = self.my_member

        messages = []
        distribution = FullSyncDistribution()
        destination = CommunityDestination()
        for message, allowed in permission_pairs:
            distribution_impl = distribution.implement(self._timeline.claim_global_time(), signed_by.claim_sequence_number())
            destination_impl = destination.implement()
            payload = Authorize(member, allowed)
            messages.append(message.implement(signed_by, distribution_impl, destination_impl, payload))

        if update_locally:
            for message_impl in messages:
                assert self._timeline.check(message_impl)
                self.on_authorize_message(None, message_impl)

        if store_and_forward:
            self._dispersy.store_and_forward(messages)

        return messages

    def permit(self, message, payload, distribution=(), destination=(), sign_with_master=False, update_locally=True, store_and_forward=True):
        assert isinstance(message, Message)
        assert isinstance(payload, Permit)
        assert isinstance(distribution, tuple)
        assert len(distribution) == 0, "Should not contain any values, this parameter is ignored for now"
        assert isinstance(destination, tuple)
        assert isinstance(sign_with_master, bool)
        assert isinstance(update_locally, bool)
        assert isinstance(store_and_forward, bool)

        if sign_with_master:
            signed_by = self.master_member
        else:
            signed_by = self.my_member

        distribution = message.distribution
        if isinstance(distribution, FullSyncDistribution):
            distribution_impl = distribution.implement(self._timeline.claim_global_time(), signed_by.claim_sequence_number())
        elif isinstance(distribution, LastSyncDistribution):
            distribution_impl = distribution.implement(self._timeline.claim_global_time())
        elif isinstance(distribution, DirectDistribution):
            distribution_impl = distribution.implement(self._timeline.global_time)
        else:
            raise ValueError("Unknown distribution")

        destination_impl = message.destination.implement(*destination)
        message_impl = message.implement(signed_by, distribution_impl, destination_impl, payload)

        if update_locally:
            assert self._timeline.check(message_impl)
            self.on_message(None, message_impl)

        if store_and_forward:
            self._dispersy.store_and_forward([message_impl])

        return message_impl

    def on_incoming_message(self, address, message):
        """
        A message was received from an external source.
        """
        assert isinstance(address, tuple)
        assert isinstance(message, Message.Implementation)
        if self._timeline.check(message):
            self._incoming_payload_type_map[message.payload.type](address, message)

        else:
            raise DelayMessageByProof()

    def on_authorize_message(self, address, message):
        """
        A authorize message was received, it was either locally
        generated or received from an external source.
        """
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        self._timeline.update(message)

    def on_revoke_message(self, address, message):
        """
        A revoke message was received, it was either locally generated
        or received from an external source.
        """
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        self._timeline.update(message)

    def on_message(self, address, message):
        """
        A message was received, it was either locally generated or
        received from an external source.

        Must be implemented in community specific code.
        """
        if __debug__:
            from Message import Message
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        raise NotImplementedError()

    def get_meta_message(self, name):
        """
        Returns the Message associated to NAME.  Or a KeyError if it
        does not exist.
        """
        assert isinstance(name, unicode)
        return self._meta_messages[name]

    def get_meta_messages(self):
        """
        Returns all the Message instances available in this Community.
        """
        return self._meta_messages.itervalues()

    def get_meta_messages(self):
        """
        Returns the PrivilegeBase subclasses available in this
        Community.
        """
        raise NotImplementedError()
