"""
The Community module manages the participation and the reconstruction
of the current state of a distributed community.
"""

from hashlib import sha1

from Authentication import NoAuthentication, MemberAuthentication, MultiMemberAuthentication
from Bloomfilter import BloomFilter
from Conversion import DefaultConversion
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Encoding import encode
from Member import Private, MasterMember, MyMember, Member
from Message import Message, DropMessage
from Payload import Permit, Authorize, Revoke, SimilarityPayload
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

        CLS is a Community subclass.  A new instance of this is
        returned.
        
        MY_MEMBER is a Member that will be granted Permit, Authorize,
        and Revoke for all messages.
        
        *ARGS are passed along to cls.__init__(...).
        
        **KARGS are passed along to cls.__init__(...).

        Returns the created community.
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

        # send out my initial dispersy-identity
        community.create_identity()

        return community

    @classmethod
    def join_community(cls, master_pem, my_member, *args, **kargs):
        """
        Joins an existing community.  Returns a Community subclass
        instance.
        
        TODO: we should probably change MASTER_PEM to require a master
        member instance, or the cid that we want to join.
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
        Load existing communities.  Returns a list with zero or more
        Community subclass instances.  The returned instances must
        include the communities of type CLS.

        Typically the load_communities is called when the main
        application is launched.  This will ensure that all
        communities are loaded and attacked to Dispersy.
        """
        raise NotImplementedError()

    def __init__(self, cid):
        """
        Creates a new Community instance identified by CID.

        Generally a new community is created using create_community.
        Or an existing community is loaded using load_communities.
        These two methods prepare and call this __init__ method.

        CID is the community identifier.
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
        self._bloom_filter_stepping = 1000
        self._bloom_filters = [BloomFilter(10, 512)] # 10, 512 -> 640 bytes
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
        Returns the bloom-filter associated to global-time.

        TODO: this name should be more distinct... this bloom filter
        is specifically used by the SyncDistribution policy.
        """
        index = global_time / self._bloom_filter_stepping
        while len(self._bloom_filters) <= index:
            self._bloom_filters.append(BloomFilter(100, 0.01))
        return self._bloom_filters[index]

    def get_current_bloom_filter(self):
        """
        Returns (global-time, bloom-filter)

        TODO: this name should be more distinct... this bloom filter
        is specifically used by the SyncDistribution policy.
        """
        index = len(self._bloom_filters) - 1
        return index * self._bloom_filter_stepping + 1, self._bloom_filters[index]

    @property
    def cid(self):
        """
        The 20 byte sha1 digest of the public master key, in other
        words: the community identifier.
        """
        return self._cid

    @property
    def database_id(self):
        """
        The number used to identify this community in the local
        Dispersy database.
        """
        return self._database_id

    @property
    def master_member(self):
        """
        The community MasterMember instance.  
        """
        return self._master_member

    @property
    def my_member(self):
        """
        Our own MyMember instance that is used to sign the messages
        that we create.
        """
        return self._my_member
        
    def get_member(self, public_key):
        """
        Returns a Member instance associated with PUBLIC_KEY.

        Since we have the PUBLIC_KEY, we can create this user when it
        didn't already exist.  Hence, this method always succeeds.

        This method may be removed in the future, as it does nothing
        more than the folling:

        >>> Member.get_instance(public_key)
        """
        assert isinstance(public_key, str)
        return Member.get_instance(public_key)

    def get_members_from_id(self, mid):
        """
        Returns zero or more Member instances associated with MID,
        where MID is the sha1 digest of a member public key.

        MID must be a 20 byte sting.  As we are using only 20 bytes to
        represent the actual member public key, this method may return
        multiple possible Member instances.  In this case, other ways
        must be used to figure out the correct Member instance.  For
        instance: if a signature or encryption is available, all
        Member instances could be used, but only one can succeed in
        verifying or decrypting.

        Since we may not have the public key associated to MID, this
        method may return an empty list.  In such a case it is
        sometimes possible to DelayPacketByMissingMember to obtain the
        public key.
        """
        assert isinstance(mid, str)
        assert len(mid) == 20
        return [Member.get_instance(str(pem)) for pem, in self._dispersy_database.execute(u"SELECT pem FROM user WHERE mid = ?", (buffer(mid),))]

    def get_conversion(self, prefix=None):
        """
        Returns the Conversion associated with PREFIX.

        PREFIX is an optional 22 byte sting.  Where the first 20 bytes
        are the community id and the last 2 bytes are the conversion
        version.
        
        When no PREFIX is given, i.e. PREFIX is None, then the default
        Conversion is returned.  Conversions are assigned to a
        community using add_conversion().
        """
        assert prefix is None or isinstance(prefix, str)
        assert prefix is None or len(prefix) == 22
        return self._conversions[prefix]

    def add_conversion(self, conversion, default=False):
        """
        Assigns a Conversion to the Community.

        CONVERSION is a Conversion instance.  A conversion instance
        converts between the internal Message structure and the
        on-the-wire message.

        DEFAULT is an optional boolean.  When True the conversion is
        set to be the default conversion.  The default conversion is
        used (by default) when a new message (self.authorize(),
        self.revoke(), self.permit()) is created.
        """
        if __debug__:
            from Conversion import Conversion
        assert isinstance(conversion, Conversion)
        assert isinstance(default, bool)
        assert not conversion.prefix in self._conversions
        if default:
            self._conversions[None] = conversion
        self._conversions[conversion.prefix] = conversion

    def authorize(self, member, permission_pairs, sign_with_master=False, update_locally=True, store_and_forward=True):
        """
        Gives MEMBER the permissions defined in PERMISSION_PAIRS.

        MEMBER must be a Member instance.  This Member will obtain the
        new permissions.  By default, self.my_member is used to
        perform this authorization.

        PERMISSIONS_PAIRS must be a list or tuple containing (Message,
        Payload) tuples.  Where Message is the meta message for which
        Member may send Payload. 

        SIGN_WITH_MASTER must be a boolean.  When True
        self.master_member is used to sign the authorize message.
        Otherwise self.my_member is used.

        UPDATE_LOCALLY must be a boolean.  When True the
        self.on_authorize_message is called with each created message.
        This parameter should (almost always) be True, its inclusion
        is mostly to allow certain debugging scenarios.

        STORE_AND_FORWARD must be a boolean.  When True the created
        messages are stored (as defined by the message distribution
        policy) in the local Dispersy database and the messages are
        forewarded to other peers (as defined by the message
        destination policy).  This parameter should (almost always) be
        True, its inclusion is mostly to allow certain debugging
        scenarios.

        Note that, by default, self.my_member is doing the
        authorization.  This means, that self.my_member must have the
        authorize permission for each of the permissions that he is
        authorizing.

        >>> # Authorize Bob to use Permit payload for 'some-message'
        >>> from Payload import Permit
        >>> bob = Member.get_instance(pem_bob)
        >>> msg = self.get_meta_messages(u"some-message")
        >>> self.authorize(bob, [msg, Permit])
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
            distribution_impl = distribution.implement(self._timeline.claim_global_time(), signed_by.claim_sequence_number())
            destination_impl = destination.implement()
            payload = Authorize(member, allowed)
            messages.append(message.implement(signed_by, distribution_impl, destination_impl, payload))

        if __debug__:
            # this method may NOT be called when we do not have the
            # appropriate permissions
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
        Removes the permissions defined in PERMISSION_PAIRS from
        MEMBER.

        MEMBER must be a Member instance.  This Member will no longer
        have the permissions.  By default, self.my_member is used to
        perform this revocation.

        PERMISSIONS_PAIRS must be a list or tuple containing (Message,
        Payload) tuples.  Where Message is the meta message for which
        Member may send Payload. 

        SIGN_WITH_MASTER must be a boolean.  When True
        self.master_member is used to sign the revoke message.
        Otherwise self.my_member is used.

        UPDATE_LOCALLY must be a boolean.  When True the
        self.on_revoke_message is called with each created message.
        This parameter should (almost always) be True, its inclusion
        is mostly to allow certain debugging scenarios.

        STORE_AND_FORWARD must be a boolean.  When True the created
        messages are stored (as defined by the message distribution
        policy) in the local Dispersy database and the messages are
        forewarded to other peers (as defined by the message
        destination policy).  This parameter should (almost always) be
        True, its inclusion is mostly to allow certain debugging
        scenarios.

        Note that, by default, self.my_member is doing the
        authorization.  This means, that self.my_member must have the
        revoke permission for each of the permissions that he is
        revoking.

        >>> # Revoke the Permit payload for 'some-message' from Bob
        >>> from Payload import Permit
        >>> bob = Member.get_instance(pem_bob)
        >>> msg = self.get_meta_messages(u"some-message")
        >>> self.revoke(bob, [msg, Permit])
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
            distribution_impl = distribution.implement(self._timeline.claim_global_time(), signed_by.claim_sequence_number())
            destination_impl = destination.implement()
            payload = Revoke(member, revoked)
            messages.append(message.implement(signed_by, distribution_impl, destination_impl, payload))

        if __debug__:
            # this method may NOT be called when we do not have the
            # appropriate permissions
            for message_impl in messages:
                assert self._timeline.check(message_impl)

        if update_locally:
            for message_impl in messages:
                self.on_authorize_message(None, message_impl)

        if store_and_forward:
            self._dispersy.store_and_forward(messages)

        return messages

    def create_identity(self, store_and_forward=True):
        return self._dispersy.create_identity(self, store_and_forward)

    def create_signature_request(self, message, response_func, timeout=10.0, store_and_forward=True):
        """
        Send a dispersy-signature-request to all members in MESSAGE to
        ask them to add their signature to MESSAGE.
        """
        assert isinstance(message, Message.Implementation)
        assert isinstance(message.authentication, MultiMemberAuthentication.Implementation)
        assert hasattr(response_func, "__call__")
        assert isinstance(timeout, float)
        assert isinstance(store_and_forward, bool)

        # the members that need to sign
        members = [member for signature, member in message.authentication.signed_members if not (signature or isinstance(member, Private))]

        # the dispersy-signature-request message that will hold the
        # message that should obtain more signatures
        meta = self.get_meta_message(u"dispersy-signature-request")
        request = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(self._timeline.global_time),
                                 meta.destination.implement(*members),
                                 message)

        if store_and_forward:
            self._dispersy.store_and_forward([request])

        # set callback and timeout
        # self._dispersy.await_response(request, self.on_signature_response, timeout, response_func)
        footprint = self.get_meta_message(u"dispersy-signature-response").generate_footprint()
        self._dispersy.await_message(footprint, self.on_signature_response, (request, response_func), timeout, len(members))

        return request

    def on_signature_response(self, address, response, request, response_func):
        # check for timeout
        if response is None:
            response_func(address, response, request)

        else:
            # the multi signed message
            submsg = request.payload

            first_signature_offset = len(submsg.packet) - sum([member.signature_length for member in submsg.authentication.members])
            body = submsg.packet[:first_signature_offset]

            for signature, member in submsg.authentication.signed_members:
                if not signature and member.verify(body, response.payload.signature):
                    submsg.authentication.set_signature(member, response.payload.signature)
                    response_func(address, response, request)

                    # assuming this signature only matches one member,
                    # we can break
                    break

    def create_similarity(self, message, keywords, update_locally=True, store_and_forward=True):
        return self._dispersy.create_similarity(self, message, keywords, update_locally, store_and_forward)

    def on_authorize_message(self, address, message):
        """
        A authorize message was received, it was either locally
        generated or received from an external source.
        """
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        if self._timeline.check(message):
            self._timeline.update(message)
        else:
            raise DropMessage("TODO: implement delay by proof")

    def on_revoke_message(self, address, message):
        """
        A revoke message was received, it was either locally generated
        or received from an external source.
        """
        assert isinstance(address, (type(None), tuple))
        assert isinstance(message, Message.Implementation)
        if self._timeline.check(message):
            self._timeline.update(message)
        else:
            raise DropMessage("TODO: implement delay by proof")

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
