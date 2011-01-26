"""
The Community module provides the Community baseclass that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from hashlib import sha1

from authentication import NoAuthentication, MemberAuthentication, MultiMemberAuthentication
from bloomfilter import BloomFilter
from conversion import DefaultConversion
from crypto import ec_generate_key, ec_to_public_pem, ec_to_private_pem
from decorator import documentation
from destination import CommunityDestination, AddressDestination
from dispersy import Dispersy
from dispersydatabase import DispersyDatabase
from distribution import FullSyncDistribution, LastSyncDistribution, DirectDistribution
from encoding import encode
from member import Private, MasterMember, MyMember, Member
from message import Message, DropMessage
from payload import Permit, Authorize, Revoke, SimilarityPayload
from resolution import PublicResolution
from timeline import Timeline

if __debug__:
    from dprint import dprint

class Community(object):
    @classmethod
    def create_community(cls, my_member, *args, **kargs):
        """
        Create a new community owned by my_member.

        Each unique community, that exists out in the world, is identified by a public/private key
        pair.  When the create_community method is called such a key pair is generated.

        Furthermore, my_member will be granted permission to use all the messages that the community
        provides.

        @param my_member: The Member that will be granted Permit, Authorize, and Revoke for all
         messages.
        @type my_member: Member

        @param args: optional argumets that are passed to the community constructor.
        @type args: tuple

        @param kargs: optional keyword arguments that are passed to the community constructor.
        @type args: dictionary

        @return: The created community instance.
        @rtype: Community
        """
        assert isinstance(my_member, MyMember), my_member

        # master key and community id
        ec = ec_generate_key("high")
        public_pem = ec_to_public_pem(ec)
        private_pem = ec_to_private_pem(ec)
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
        for message in community.initiate_meta_messages():
            if not isinstance(message.resolution, PublicResolution):
                for allowed in (Authorize, Revoke, Permit):
                    permission_pairs.append((message, allowed))
        if permission_pairs:
            community.authorize(my_member, permission_pairs, True)

        # send out my initial dispersy-identity
        community.create_identity()

        return community

    @classmethod
    def join_community(cls, master_pem, my_member, *args, **kargs):
        """
        Join an existing community.

        Once you have discovered an existing community, i.e. you have obtained the public master pem
        from a community, you can join this community.

        Joining a community does not mean that you obtain permissions in that community, those will
        need to be granted by another member who is allowed to do so.  However, it will let you
        receive, send, and disseminate messages that do not require any permission to use.

        @param master_pem: The public pem of the master member of the community that is to be
         joined.
        @type master_pem: string

        @param my_member: The Member that will be granted Permit, Authorize, and Revoke for all
         messages.
        @type my_member: Member

        @param args: optional argumets that are passed to the
        community constructor.
        @type args: tuple

        @param kargs: optional keyword arguments that are passed to
        the community constructor.
        @type args: dictionary

        @return: The created community instance.
        @rtype: Community

        @todo: we should probably change MASTER_PEM to require a master member instance, or the cid
         that we want to join.
        """
        assert isinstance(master_pem, str)
        assert isinstance(my_member, MyMember)
        cid = sha1(master_pem).digest()
        database = DispersyDatabase.get_instance()
        database.execute(u"INSERT INTO community(user, cid, master_pem) VALUES(?, ?, ?)",
                         (my_member.database_id, buffer(cid), buffer(master_pem)))

        # new community instance
        community = cls(cid, *args, **kargs)

        # send out my initial dispersy-identity
        community.create_identity()

        return community

    @staticmethod
    def load_communities():
        """
        Load all joined or created communities of this type.

        Typically the load_communities is called when the main application is launched.  This will
        ensure that all communities are loaded and attached to Dispersy.

        @return: A list with zero or more Community instances.
        @rtype: list
        """
        raise NotImplementedError()

    def __init__(self, cid):
        """
        Initialize a community.

        Generally a new community is created using create_community.  Or an existing community is
        loaded using load_communities.  These two methods prepare and call this __init__ method.

        @param cid: The community identifier, i.e. the sha1 digest over the public PEM of the
         community master member.
        @type cid: string
        """
        assert isinstance(cid, str)
        assert len(cid) == 20

        # community identifier
        self._cid = cid

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

            # the database returns <buffer> types, we use the binary <str> type internally
            master_pem = str(master_pem)
            user_pem = str(user_pem)

        except StopIteration:
            raise ValueError(u"Community not found in database")
        self._database_id = community_id
        self._my_member = MyMember.get_instance(user_pem)
        self._master_member = MasterMember.get_instance(master_pem)

        # define all available messages
        self._meta_messages = {}
        for meta_message in self._dispersy.initiate_meta_messages(self):
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message
        for meta_message in self.initiate_meta_messages():
            assert meta_message.name not in self._meta_messages
            self._meta_messages[meta_message.name] = meta_message

        # the list with bloom filters.  the list will grow as the global time increases.  The 1st
        # bloom filter will contain all stored messages from global time 1 to stepping.  The 2nd
        # from stepping to 2*stepping, etc.
        self._bloom_filter_stepping = 1000
        self._bloom_filters = [BloomFilter(10, 512)] # 10, 512 -> 640 bytes
        # todo: if we are only using LastSyncDistribution then it is possible that only the last
        # elements of the _bloom_filters are used.  We should make this into a dictionary and keep
        # it clean once a bloomfilter becomes obsolete.

        # dictionary containing available conversions.  currently only contains one conversion.
        self._conversions = {}
        self.add_conversion(DefaultConversion(self), True)

        # initial timeline.  the timeline will keep track of member permissions
        self._timeline = Timeline(self)

        # tell dispersy that there is a new community
        self._dispersy.add_community(self)

    @property
    def dispersy_sync_interval(self):
        """
        The interval between sending dispersy-sync messages.
        @rtype float
        """
        return 20.0

    @property
    def dispersy_sync_member_count(self):
        """
        The number of members that are selected each time a dispersy-sync message is send.
        @rtype int
        """
        return 10

    @property
    def dispersy_sync_response_limit(self):
        """
        The maximum number of packets and the maximum number of bytes to send back per received
        dispersy-sync message.
        @rtype (int, int)
        """
        return (50, 5 * 1025)

    @property
    def dispersy_missing_sequence_response_limit(self):
        """
        The maximum number of packets and the maximum number of bytes to send back per received
        dispersy-missing-sequence message.
        @rtype (int, int)
        """
        return (100, 10 * 1025)

    @property
    def cid(self):
        """
        The 20 byte sha1 digest of the public master key, in other words: the community identifier.
        @rtype: string
        """
        return self._cid

    @property
    def database_id(self):
        """
        The number used to identify this community in the local Dispersy database.
        @rtype: int or long
        """
        return self._database_id

    @property
    def master_member(self):
        """
        The community MasterMember instance.
        @rtype: MasterMember
        """
        return self._master_member

    @property
    def my_member(self):
        """
        Our own MyMember instance that is used to sign the messages that we create.
        @rtype: MyMember
        """
        return self._my_member

    @property
    def dispersy(self):
        """
        The Dispersy instance.
        @rtype: Dispersy
        """
        return self._dispersy

    def get_bloom_filter(self, global_time):
        """
        Returns the bloom filter associated to global-time.

        @param global_time: The global time indicating the time range.
        @type global_time: int or long

        @return: The bloom filter where messages in global_time are stored.
        @rtype: BloomFilter

        @todo: this name should be more distinct... this bloom filter is specifically used by the
         SyncDistribution policy.
        """
        index = global_time / self._bloom_filter_stepping
        while len(self._bloom_filters) <= index:
            self._bloom_filters.append(BloomFilter(100, 0.01))
        return self._bloom_filters[index]

    def get_current_bloom_filter(self):
        """
        Returns the global time and bloom filter associated to the current time frame.

        @return: The global-time and bloom filter associated to the current time frame.
        @rtype: (int or long, BloomFilter) tuple

        @todo: this name should be more distinct... this bloom filter is specifically used by the
         SyncDistribution policy.
        """
        index = len(self._bloom_filters) - 1
        return index * self._bloom_filter_stepping + 1, self._bloom_filters[index]

    def get_member(self, public_key):
        """
        Returns a Member instance associated with public_key.

        since we have the public_key, we can create this user when it didn't already exist.  Hence,
        this method always succeeds.

        @param public_key: The public key, i.e. PEM of the public key, of the member we want to
         obtain.
        @type public_key: string

        @return: The Member instance associated with public_key.
        @rtype: Member

        @note: This returns -any- Member, it may not be a member that is part of this community.

        @todo: Since this method returns Members that are not specifically bound to any community,
         this method should be moved to Dispersy
        """
        assert isinstance(public_key, str)
        return Member.get_instance(public_key)

    def get_members_from_id(self, mid):
        """
        Returns zero or more Member instances associated with mid, where mid is the sha1 digest of a
        member public key.

        As we are using only 20 bytes to represent the actual member public key, this method may
        return multiple possible Member instances.  In this case, other ways must be used to figure
        out the correct Member instance.  For instance: if a signature or encryption is available,
        all Member instances could be used, but only one can succeed in verifying or decrypting.

        Since we may not have the public key associated to MID, this method may return an empty
        list.  In such a case it is sometimes possible to DelayPacketByMissingMember to obtain the
        public key.

        @param mid: The 20 byte sha1 digest indicating a member.
        @type mid: string

        @return: A list containing zero or more Member instances.
        @rtype: [Member]

        @note: This returns -any- Member, it may not be a member that is part of this community.

        @todo: Since this method returns Members that are not specifically bound to any community,
         this method should be moved to Dispersy
        """
        assert isinstance(mid, str)
        assert len(mid) == 20
        return [Member.get_instance(str(pem)) for pem, in self._dispersy_database.execute(u"SELECT pem FROM user WHERE mid = ?", (buffer(mid),))]

    def get_conversion(self, prefix=None):
        """
        returns the conversion associated with prefix.

        prefix is an optional 22 byte sting.  Where the first 20 bytes are the community id and the
        last 2 bytes are the conversion version.

        When no prefix is given, i.e. prefix is None, then the default Conversion is returned.
        Conversions are assigned to a community using add_conversion().

        @param prefix: Optional prefix indicating a conversion.
        @type prefix: string

        @return A Conversion instance indicated by prefix or the default one.
        @rtype: Conversion
        """
        assert prefix is None or isinstance(prefix, str)
        assert prefix is None or len(prefix) == 22
        return self._conversions[prefix]

    def add_conversion(self, conversion, default=False):
        """
        Add a Conversion to the Community.

        A conversion instance converts between the internal Message structure and the on-the-wire
        message.

        When default is True the conversion is set to be the default conversion.  The default
        conversion is used (by default) when a message is implemented and no prefix is given.

        @param conversion: The new conversion instance.
        @type conversion: Conversion

        @param default: Indicating if this is to become the default conversion.
        @type default: bool
        """
        if __debug__:
            from conversion import Conversion
        assert isinstance(conversion, Conversion)
        assert isinstance(default, bool)
        assert not conversion.prefix in self._conversions
        if default:
            self._conversions[None] = conversion
        self._conversions[conversion.prefix] = conversion

    def authorize(self, member, permission_pairs, sign_with_master=False, update_locally=True, store_and_forward=True):
        """
        Grant one or more permissions to someone.

        This method will generate one or more messages that grant a member one or more permissions.
        Each permission pair will result in one message.

        By default, self.my_member is doing the authorization.  This means, that self.my_member must
        have the authorize permission for each of the permissions that she is authorizing.

        >>> # Authorize Bob to use Permit payload for 'some-message'
        >>> from Payload import Permit
        >>> bob = Member.get_instance(pem_bob)
        >>> msg = self.get_meta_message(u"some-message")
        >>> self.authorize(bob, [(msg, Permit)])

        @param member: This Member will obtain the new permissions.
        @type member: Member

        @param permissions_pairs: The permissions that are granted.  Must be a list or tuple
         containing (Message, Payload) tuples.  Where Message is the meta message for which Member
         may send Payload.
        @type permissions_pairs: [(Message, Payload)]

        @param sign_with_master: When True self.master_member is used to sign the authorize message.
         Otherwise self.my_member is used.
        @type sign_with_master: bool

        @param update_locally: When True the self.on_authorize_message is called with each created
         message.  This parameter should (almost always) be True, its inclusion is mostly to allow
         certain debugging scenarios.
        @type update_locally: bool

        @param store_and_forward: When True the created messages are stored (as defined by the
         message distribution policy) in the local Dispersy database and the messages are forewarded
         to other peers (as defined by the message destination policy).  This parameter should
         (almost always) be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store_and_forward: bool
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
            signed_by = self._master_member
        else:
            signed_by = self._my_member

        messages = []
        distribution = FullSyncDistribution()
        destination = CommunityDestination()
        for message, allowed in permission_pairs:
            distribution_impl = distribution.implement(self._timeline.claim_global_time())
            destination_impl = destination.implement()
            payload = Authorize(member, allowed)
            messages.append(message.implement(signed_by, distribution_impl, destination_impl, payload))

        if __debug__:
            # this method may NOT be called when we do not have the appropriate permissions
            for message_impl in messages:
                assert self._timeline.check(message_impl)

        if update_locally:
            for message_impl in messages:
                self.on_authorize_message(None, message_impl)

        if store_and_forward:
            self._dispersy.store_and_forward(messages)

        return messages

    def revoke(self, member, permission_pairs, sign_with_master=False, update_locally=True, store_and_forward=True):
        """
        Revoke one or more permissions from someone.

        This method will generate one or more messages that will revoke one or more permissions from
        a member.  Each permission pair will result in one message.

        Note that, by default, self.my_member is doing the revocation.  This means, that
        self.my_member must have the revoke permission for each of the permissions that she is
        revoking.

        >>> # Revoke the Permit payload for 'some-message' from Bob
        >>> from Payload import Permit
        >>> bob = Member.get_instance(pem_bob)
        >>> msg = self.get_meta_message(u"some-message")
        >>> self.revoke(bob, [(msg, Permit)])

        @param member: This Member will no longer have the permissions.
        @type member: Member

        @param permissions_pairs: The permissions that are revoked.  Must be a list or tuple
         containing (Message, Payload) tuples.  Where Message is the meta message for which Member
         may send Payload.
        @type permissions_pairs: [(Message, Payload)]

        @param sign_with_master: When True self.master_member is used to sign the revoke message.
         Otherwise self.my_member is used.
        @type sign_with_master: bool

        @param update_locally: When True the self.on_revoke_message is called with each created
         message.  This parameter should (almost always) be True, its inclusion is mostly to allow
         certain debugging scenarios.
        @type update_locally: bool

        @param store_and_forward: When True the created messages are stored (as defined by the
         message distribution policy) in the local Dispersy database and the messages are forewarded
         to other peers (as defined by the message destination policy).  This parameter should
         (almost always) be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store_and_forward: bool
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
            signed_by = self._master_member
        else:
            signed_by = self._my_member

        messages = []
        distribution = FullSyncDistribution()
        destination = CommunityDestination()
        for message, revoked in permission_pairs:
            distribution_impl = distribution.implement(self._timeline.claim_global_time())
            destination_impl = destination.implement()
            payload = Revoke(member, revoked)
            messages.append(message.implement(signed_by, distribution_impl, destination_impl, payload))

        if __debug__:
            # this method may NOT be called when we do not have the appropriate permissions
            for message_impl in messages:
                assert self._timeline.check(message_impl)

        if update_locally:
            for message_impl in messages:
                self.on_revoke_message(None, message_impl)

        if store_and_forward:
            self._dispersy.store_and_forward(messages)

        return messages

    @documentation(Dispersy.create_identity)
    def create_identity(self, store_and_forward=True):
        return self._dispersy.create_identity(self, store_and_forward)

    @documentation(Dispersy.create_signature_request)
    def create_signature_request(self, message, response_func, response_args=(), timeout=10.0, store_and_forward=True):
        return self._dispersy.create_signature_request(self, message, response_func, response_args, timeout, store_and_forward)

    @documentation(Dispersy.create_similarity)
    def create_similarity(self, message, keywords, update_locally=True, store_and_forward=True):
        return self._dispersy.create_similarity(self, message, keywords, update_locally, store_and_forward)

    def on_authorize_message(self, address, message):
        """
        Process an authorize message.

        This method is called to process an unknown authorize message.  This message is either
        received from an external source or locally generated.

        When the message is locally generated the address will be set to ('', -1).

        @param address: The address from where we received this message.
        @type address: (string, int)

        @param message: The received message.
        @type message: Message.Implementation
        @raise DropMessage: When unable to verify that this message is valid.
        @todo: We should raise a DelayMessageByProof to ensure that we request the proof for this
         message immediately.
        """
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(message, Message.Implementation)
        if self._timeline.check(message):
            self._timeline.update(message)
        else:
            raise DropMessage("TODO: implement delay by proof")

    def on_revoke_message(self, address, message):
        """
        Process a revoke message.

        This method is called to process an unknown revoke message.  This message is either received
        from an external source or locally generated.

        When the message is locally generated the address will be set to ('', -1).

        @param address: The address from where we received this message.
        @type address: (string, int)

        @param message: The received message.
        @type message: Message.Implementation
        @raise DropMessage: When unable to verify that this message is valid.
        @todo: We should raise a DelayMessageByProof to ensure that we request the proof for this
         message immediately.
        """
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(message, Message.Implementation)
        if self._timeline.check(message):
            self._timeline.update(message)
        else:
            raise DropMessage("TODO: implement delay by proof")

    def on_message(self, address, message):
        """
        Process a permit (regular) message.

        This method is called to process an unknown permit message.  This message is either received
        from an external source or locally generated.

        When the message is locally generated the address will be set to ('', -1).

        This is an abstract method that must be implemented in community specific code.

        @param address: The address from where we received this message.
        @type address: (string, int)

        @param message: The received message.
        @type message: Message.Implementation
        @raise DropMessage: When unable to verify that this message is valid.
        @todo: We should raise a DelayMessageByProof to ensure that we request the proof for this
         message immediately.
        """
        if __debug__:
            from message import Message
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        raise NotImplementedError()

    def get_meta_message(self, name):
        """
        Returns the meta message by its name.

        @param name: The name of the message.
        @type name: unicode

        @return: The meta message.
        @rtype: Message

        @raise KeyError: When there is no meta message by that name.
        """
        assert isinstance(name, unicode)
        return self._meta_messages[name]

    def get_meta_messages(self):
        """
        Returns all meta messages.

        @return: The meta messages.
        @rtype: [Message]
        """
        return self._meta_messages.values()

    def initiate_meta_messages(self):
        """
        Create the meta messages for one community instance.

        This method is called once for each community when it is created.  The resulting meta
        messages can be obtained by either get_meta_message(name) or get_meta_messages().

        To distinct the meta messages that the community provides from those that Dispersy provides,
        none of the messages may have a name that starts with 'dispersy-'.

        @return: The new meta messages.
        @rtype: [Message]
        """
        raise NotImplementedError()
