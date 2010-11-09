"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from hashlib import sha1

from Authentication import NoAuthentication
from Bloomfilter import BloomFilter
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination, MemberDestination
from DispersyDatabase import DispersyDatabase
from Distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Member import MyMember, PrivateMember, MasterMember
from Message import Message, DelayPacket, DropPacket, DelayMessage, DelayMessageBySequence, DropMessage
from Payload import MissingSequencePayload, SyncPayload
from Resolution import PublicResolution
from Singleton import Singleton

if __debug__:
    from Print import dprint

class DummySocket(object):
    def send(address, data):
        pass

class ExpectedResponse(object):
    def __init__(self, request, response_func):
        self._request = request
        self._response_func = response_func

    @property
    def request(self):
        return self._request

    @property
    def response_func(self):
        return self._response_func

class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self, rawserver, working_directory):
        # the raw server
        self._rawserver = rawserver
        self._rawserver.add_task(self._periodically_disperse, 1.0)

        # where we store all data
        self._working_directory = working_directory

        # our data storage
        self._database = DispersyDatabase.get_instance(working_directory)

        try:
            public_pem = str(self._database.execute(u"SELECT value FROM option WHERE key == 'my_public_pem' LIMIT 1").next()[0])
            private_pem = None
        except StopIteration:
            # one of the keys was not found in the database, we need
            # to generate a new one
            rsa = rsa_generate_key(512)
            public_pem = rsa_to_public_pem(rsa)
            private_pem = rsa_to_private_pem(rsa)
            self._database.execute(u"INSERT INTO option VALUES('my_public_pem', ?)", (buffer(public_pem),))
            
        # this is yourself
        self._my_member = MyMember.get_instance(public_pem, private_pem)

        # all available communities.  cid:Community pairs.
        self._communities = {}

        # outgoing communication
        self._socket = DummySocket()

        # waiting for responses
        self._expected_responses = {} # request-id:ExpectedResponse pairs

        # all available communities.  cid:Community pairs.  messages
        # that are delayed (because previous messages were missing)
        self._delayed = {}
        self._check_delayed_map = {FullSyncDistribution.Implementation:self._check_delayed_full_sync_distribution,
                                   LastSyncDistribution.Implementation:self._check_delayed_last_sync_distribution,
                                   DirectDistribution.Implementation:self._check_delayed_direct_distribution}

        self._incoming_distribution_map = {FullSyncDistribution.Implementation:self._check_incoming_full_sync_distribution,
                                           LastSyncDistribution.Implementation:self._check_incoming_last_sync_distribution,
                                           DirectDistribution.Implementation:self._check_incoming_direct_distribution}

    @property
    def working_directory(self):
        return self._working_directory

    @property
    def socket(self):
        return self._socket

    @socket.setter
    def socket(self, socket):
        self._socket = socket

    @property
    def my_member(self):
        return self._my_member

    @property
    def database(self):
        """
        Returns the Dispersy database.

        This is the same as: DispersyDatabase.get_instance([working_directory])
        """
        return self._database

    def add_community(self, community):
        if __debug__:
            from Community import Community
        assert isinstance(community, Community)
        assert not community.cid in self._communities
        self._communities[community.cid] = community

        # update the community bloom filter
        with self._database as execute:
            for global_time, packet in execute(u"SELECT global, packet FROM sync_full WHERE community = ? ORDER BY global", (community.database_id,)):
                packet = str(packet)
                community.get_bloom_filter(global_time).add(packet)

            for global_time, packet in execute(u"SELECT global, packet FROM sync_last WHERE community = ? ORDER BY global", (community.database_id,)):
                packet = str(packet)
                community.get_bloom_filter(global_time).add(packet)

    def get_community(self, cid):
        assert isinstance(cid, str)
        return self._communities[cid]

    def _delay_packet(self, address, packet, delay):
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(delay, DelayPacket)
        dprint(delay)

    def _delay_message(self, address, message, delay):
        if __debug__:
            from Message import Message
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(message, Message.Implementation)
        assert isinstance(delay, DelayMessage)
        if isinstance(delay, DelayMessageBySequence):
            key = "message:{0.name} community:{0.community.database_id} user:{0.authentication.member.database_id} sequence:{1.missing_high}".format(message, delay)
            if not key in self._delayed:
                self._delayed[key] = (address, message)
                message.community.permit(message.community.get_meta_message(u"dispersy-missing-sequence"), MissingSequencePayload(message.authentication.member, message.meta, delay.missing_low, delay.missing_high), destination=(address,), update_locally=False)
                
        else:
            raise NotImplementedError(delay)

    def _check_delayed_full_sync_distribution(self, message):
        key = "message:{0.name} community:{0.community.database_id} user:{0.authentication.member.database_id} sequence:{0.distribution.sequence_number}".format(message)
        if __debug__:
            if key in self._delayed:
                dprint(key)
        return self._delayed.pop(key, None)

    def _check_delayed_last_sync_distribution(self, message):
        pass

    def _check_delayed_direct_distribution(self, message):
        pass

    def _check_delayed_OTHER_distribution(self, message):
        raise NotImplementedError(message.distribution)

    def _check_incoming_full_sync_distribution(self, message):
        try:
            sequence, = self._database.execute(u"""
SELECT sequence
FROM sync_full
WHERE user = ? AND community = ?
ORDER BY sequence DESC
LIMIT 1""",
                                              (message.authentication.member.database_id,
                                               message.community.database_id)).next()
        except StopIteration:
            sequence = 0
            
        # (1) we already have this message (drop)
        if sequence >= message.distribution.sequence_number:
            raise DropMessage("duplicate message")

        # (3) we have the previous message (process)
        elif sequence + 1 == message.distribution.sequence_number:
            return

        # (2) we do not have the previous message (delay and request)
        else:
            raise DelayMessageBySequence(sequence+1, message.distribution.sequence_number-1)

        assert False

    def _check_incoming_last_sync_distribution(self, message):
        try:
            self._database.execute(u"""
SELECT 1
FROM sync_last
WHERE user = ? AND global > ?
LIMIT 1""",
                                   (message.authentication.member.database_id,
                                    message.distribution.global_time)).next()
        except StopIteration:
            return
        raise DropMessage("duplicate or older message")

    def _check_incoming_direct_distribution(self, message):
        return

    def _check_incoming_OTHER_distribution(self, message):
        raise NotImplementedError(message.distribution)

    def on_incoming_packets(self, packets):
        """
        Incoming PACKETS were received.

        PACKETS is a list containing one or more (ADDRESS, DATA) pairs
        where ADDRESS is a (HOST, PORT) tuple and DATA is a string.
        """
        assert isinstance(packets, (tuple, list))
        assert len(packets) > 0
        assert not filter(lambda x: not len(x) == 2, packets)

        for address, packet in packets:
            assert isinstance(address, tuple)
            assert isinstance(address[0], str)
            assert isinstance(address[1], int)
            assert isinstance(packet, str)

            #
            # Find associated community
            #
            try:
                community = self.get_community(packet[:20])
            except KeyError:
                dprint("drop a ", len(packet), " byte packet (received packet for unknown community) from ", address[0], ":", address[1])
                continue

            #
            # Find associated conversion
            #
            try:
                conversion = community.get_conversion(packet[:22])
            except KeyError:
                dprint("drop a ", len(packet), " byte packet (received packet for unknown conversion) from ", address[0], ":", address[1])
                continue

            try:
                #
                # Converty binary date to internal Message
                #
                message = conversion.decode_message(packet)

                # #
                # # Perhaps this is a message send by us?
                # #
                # if message.authentication.member == message.community.my_member:
                #     # todo: perform a identity check.  if it proves to
                #     # be us, then we can remove this address from
                #     # routing
                #     dprint("drop a ", len(packet), " byte packet (send by ourselves) from ", address[0], ":", address[1])
                #     dprint("TODO: perform an identity check", level="warning")
                #     self._database.execute(u"DELETE FROM routing WHERE community = ? AND host = ? AND port = ?",
                #                            (message.community.database_id, unicode(address[0]), address[1]))
                #     continue

                # Update routing table.  We know that some peer (not
                # necessarily message.authentication.member) exists at
                # this address.
                #
                self._database.execute(u"UPDATE routing SET incoming_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                                       (message.community.database_id, unicode(address[0]), address[1]))
                if self._database.changes == 0:
                    self._database.execute(u"INSERT INTO routing(community, host, port, incoming_time, outgoing_time) VALUES(?, ?, ?, DATETIME(), '2010-01-01 00:00:00')",
                                           (message.community.database_id, unicode(address[0]), address[1]))

                while True:
                    #
                    # Filter messages based on distribution (usually
                    # duplicate or old messages)
                    #
                    self._incoming_distribution_map.get(type(message.distribution), self._check_incoming_OTHER_distribution)(message)

                    #
                    # Allow community code to handle the message
                    #
                    if __debug__: dprint("incoming ", message.payload.type, "^", message.name, " (", len(message.packet), " bytes)")
                    community.on_incoming_message(address, message)

                    #
                    # Sync messages need to be stored (so they can be
                    # synced later)
                    #
                    if isinstance(message.distribution, SyncDistribution.Implementation):
                        self._sync_store(message)

                    #
                    # This message may 'trigger' a previously delayed message
                    #
                    tup = self._check_delayed_map.get(type(message.distribution), self._check_delayed_OTHER_distribution)(message)
                    if tup:
                        address, message = tup
                    else:
                        break

            except DropPacket as exception:
                dprint("drop a ", len(packet), " byte packet (", exception, ") from ", address[0], ":", address[1], exception=True)
                continue

            except DelayPacket as delay:
                self._delay_packet(address, packet, delay)
                continue

            except DropMessage as exception:
                dprint("drop a ", len(message.packet), " byte message (", exception, ") from ", address[0], ":", address[1], exception=True)
                continue
            
            except DelayMessage as delay:
                self._delay_message(address, message, delay)
                continue

    def _sync_store(self, message):
        assert isinstance(message.distribution, SyncDistribution.Implementation)
        distribution = message.distribution

        # sync bloomfilter
        message.community.get_bloom_filter(message.distribution.global_time).add(message.packet)

        # sync database
        if isinstance(distribution, FullSyncDistribution.Implementation):
            self._database.execute(u"INSERT INTO sync_full(community, user, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                   (message.community.database_id,
                                    message.authentication.member.database_id,
                                    distribution.global_time,
                                    distribution.sequence_number,
                                    buffer(message.packet)))

        elif isinstance(distribution, LastSyncDistribution.Implementation):
            self._database.execute(u"INSERT OR REPLACE INTO sync_last(community, user, global, packet) VALUES(?, ?, ?, ?)",
                                   (message.community.database_id,
                                    message.authentication.member.database_id,
                                    distribution.global_time,
                                    buffer(message.packet)))
        
        else:
            raise NotImplementedError(distribution)

    def store_and_forward(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes.
        """
        if __debug__:
            from Message import Message
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert not filter(lambda x: not isinstance(x, Message.Implementation), messages)

        for message in messages:
            if not message.packet:
                message.packet = message.community.get_conversion().encode_message(message)

            # Store
            if isinstance(message.distribution, SyncDistribution.Implementation):
                self._sync_store(message)

            # Forward
            if isinstance(message.destination, CommunityDestination.Implementation):
                # todo: we can remove the returning diff and age from
                # the query since it is not used (especially in the
                # 2nd query)

                # the theory behind the address selection is:
                # a) we want to keep contact with those who are
                #    online, hence we send messages to those that
                #    have a small diff.
                # b) we want to get connections to those that have
                #    been away for some time, hence we send
                #    messages to those that have a high age.
                sql = u"""
                SELECT ABS(STRFTIME('%s', outgoing_time) - STRFTIME('%s', incoming_time)) AS diff, STRFTIME('%s', DATETIME()) - STRFTIME('%s', outgoing_time) AS age, host, port
                FROM routing
                WHERE community = ? AND (diff < 30 OR age > 300)
                ORDER BY diff ASC, age DESC
                LIMIT 10"""

                addresses = list(self._database.execute(sql, (message.community.database_id,)))
                if not addresses:
                    # we need to fallback to something... just
                    # pick some addresses.
                    sql = u"""
                    SELECT ABS(STRFTIME('%s', outgoing_time) - STRFTIME('%s', incoming_time)) AS diff, STRFTIME('%s', DATETIME()) - STRFTIME('%s', outgoing_time) AS age, host, port
                    FROM routing
                    WHERE community = ?
                    ORDER BY diff ASC, age DESC
                    LIMIT 10"""
                    addresses = list(self._database.execute(sql, (message.community.database_id,)))

                for diff, age, host, port in addresses:
                    assert isinstance(host, unicode)
                    self._send((str(host), port), message)
                    # if __debug__: dprint(message.payload.type, "^", message.name, " to ", host, ":", port, " [len:", len(message.packet), "; diff:", diff, "; age:", age, "]")
                    # self._socket.send((host, port), message.packet)
                    # execute(u"UPDATE routing SET outgoing_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                    #                        (message.community.database_id, host, port))
                    # assert self._database.changes

            elif isinstance(message.destination, AddressDestination.Implementation):
                for address in message.destination.addresses:
                    self._send(address, message)
                    # if __debug__: dprint(message.payload.type, "^", message.name, " (", len(message.packet), " bytes) to ", address[0], ":", address[1])
                    # self._socket.send(address, message.packet)
                    # execute(u"UPDATE routing SET outgoing_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                    #         (message.community.database_id, unicode(address[0]), address[1]))

            elif isinstance(message.destination, MemberDestination.Implementation):
                for member in message.destination.members:
                    address = member.discovery.address
                    if address:
                        self._send(address, message)
                        # if __debug__: dprint(message.payload.type, "^", message.name, " (", len(message.packet), " bytes) to ", address[0], ":", address[1])
                        # self._socket.send(address, message.packet)
                        # execute(u"UPDATE routing SET outgoing_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                        #         (message.community.database_id, unicode(address[0]), address[1]))
                    elif __debug__:
                        dprint("No address available for this member", level="warning")

            else:
                raise NotImplementedError(message.destination)

    def _send(self, address, message):
        assert isinstance(address, tuple)
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        if __debug__: dprint(message.payload.type, "^", message.name, " (", len(message.packet), " bytes) to ", address[0], ":", address[1])
        self._socket.send(address, message.packet)
        with self._database as execute:
            execute(u"UPDATE routing SET outgoing_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                    (message.community.database_id, unicode(address[0]), address[1]))

    def await_response(self, request, response_func, timeout=10.0):
        assert isinstance(request, Message.Implementation)
        assert request.packet
        assert hasattr(response_func, "__call__")
        assert isinstance(timeout, float)
        assert timeout > 0.0

        def on_timeout():
            expected_response = self._expected_responses.pop(request_id, None)
            if expected_response:
                expected_response.response_func(("", -1), expected_response.request, None)

        request_id = sha1(request.packet).digest()
        assert not request_id in self._expected_responses
        self._expected_responses[request_id] = ExpectedResponse(request, response_func)
        self._rawserver.add_task(on_timeout, timeout)

    def on_response(self, address, message):
        # todo: we should expect multiple people to send a response
        # back (based on the destination policy from the request)
        expected_response = self._expected_responses.pop(message.payload.request_id)
        if expected_response:
            expected_response.response_func(address, expected_response.request, message.payload.response)

    def get_meta_messages(self, community):
        """
        Returns the Message instances available to Dispersy.

        Each Message has a name prefixed with dispersy, and each
        Community should support these Messages in order for Dispersy
        to function properly.
        """
        if __debug__:
            def check_meta_message(name):
                try:
                    community.get_meta_message(name)
                    assert False, name
                except KeyError:
                    pass
            # the community may not already have these messages
            # map(check_meta_message, [u"dispersy-handshake-request", u"disperty-handshake-reply", u"dispersy-sync", u"dispersy-missing-sequence", u"dispersy-double-signature"])
            map(check_meta_message, [u"dispersy-sync",
                                     u"dispersy-missing-sequence",
                                     u"dispersy-signature-request",
                                     u"dispersy-response"])

        # return [Message(community, u"dispersy-handshake-request", MemberAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
        #         Message(community, u"dispersy-handshake-reply", MemberAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
        return [Message(community, u"dispersy-sync", NoAuthentication(), PublicResolution(), DirectDistribution(), CommunityDestination()),
                Message(community, u"dispersy-missing-sequence", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
                Message(community, u"dispersy-signature-request", NoAuthentication(), PublicResolution(), DirectDistribution(), MemberDestination()),
                Message(community, u"dispersy-response", NoAuthentication(), PublicResolution(), DirectDistribution(), MemberDestination())]

    def get_message_handlers(self, community):
        """
        Returns the handler methods for the privileges available to
        Dispersy.
        """
        # return [(community.get_meta_message(u"dispersy-handshake-request"), self.on_handshake_request),
        #         (community.get_meta_message(u"dispersy-handshake-reply"), self.on_handshake_reply),
        return [(community.get_meta_message(u"dispersy-sync"), self.on_sync_message),
                (community.get_meta_message(u"dispersy-missing-sequence"), self.on_missing_sequence),
                (community.get_meta_message(u"dispersy-signature-request"), self.on_signature_request),
                (community.get_meta_message(u"dispersy-response"), self.on_response)]

    # def on_handshake_request(self, address, message):
    #     dprint(message)

    # def on_handshake_reply(self, address, message):
    #     dprint(message)

    def on_sync_message(self, address, message):
        """
        We received a dispersy-sync message.

        The message contains a bloom-filter that needs to be checked.
        If we find any messages that are not in the bloom-filter, we
        will send those to the sender.

        Todo: we need to optimise this much much more, currently it
        just sends back data.  So if multiple nodes receive this
        dispersy-sync message they will probably all send the same
        messages back.  So we need to make things smarter!
        """
        if __debug__:
            from Message import Message
            assert isinstance(message, Message.Implementation)

        bloom_filter = message.payload.bloom_filter
        with self._database as execute:
            for packet, in execute(u"SELECT packet FROM sync_full WHERE community = ? AND global >= ? ORDER BY global LIMIT 100", (message.community.database_id, message.payload.global_time)):
                packet = str(packet)
                if not packet in bloom_filter:
                    if __debug__: dprint("Syncing ", len(packet), " bytes from sync_full to " , address[0], ":", address[1])
                    self._socket.send(address, packet)

            for packet, in execute(u"SELECT packet FROM sync_last WHERE community = ? AND global >= ? ORDER BY global LIMIT 100", (message.community.database_id, message.payload.global_time)):
                packet = str(packet)
                if not packet in bloom_filter:
                    if __debug__: dprint("Syncing ", len(packet), " bytes from sync_last to " , address[0], ":", address[1])
                    self._socket.send(address, packet)

    def on_missing_sequence(self, address, message):
        """
        We received a dispersy-missing-sequence message.

        The message contains a user and a range of sequence numbers.
        We will send the messages in this range back to the sender.

        Todo: we need to optimise this to include a bandwidth
        throttle.  Otherwise a node can easilly force us to send
        arbitrary large amounts of data.
        """
        if __debug__:
            from Message import Message
        assert isinstance(message, Message)

        payload = message.payload
        for packet, in self._database.execute(u"SELECT packet FROM sync_full WHERE community = ? and sequence >= ? AND sequence <= ? ORDER BY sequence LIMIT 100",
                                              (payload.message.community.database_id, payload.missing_low, payload.missing_high)):
            if __debug__: dprint("Syncing ", len(packet), " bytes from sync_full to " , address[0], ":", address[1])
            self._socket.send(address, packet)

    def on_signature_request(self, address, message):
        """
        We received a dispersy-signature-request message.

        This message contains another message (message.payload).
        Someone requested us to add our signature to this submessage.
        The message may, or may not, have already been signed by some
        of the other members.  Furthermore, we can choose for
        ourselves if we want to sign this message or not.
        """
        if __debug__:
            from Message import Message
            from Authentication import MultiMemberAuthentication
        assert isinstance(message, Message.Implementation), type(message)
        assert isinstance(message.payload, Message.Implementation), type(message.payload)
        assert isinstance(message.payload.authentication, MultiMemberAuthentication.Implementation)

        # submsg contains the message that should receive multiple
        # signatures
        submsg = message.payload

        has_private_member = False
        for is_signed, member in submsg.authentication.signed_members:
            # Security: do NOT allow to accidentally sign with
            # MasterMember.
            if isinstance(member, MasterMember):
                raise DropMessage("You may never ask for a MasterMember signature")

            # is this signature missing, and could we provide it
            if not is_signed and isinstance(member, PrivateMember):
                has_private_member = True
                break

        if (# we must be one of the members that needs to sign
            has_private_member and \
            # the message must be valid
            submsg.community._timeline.check(submsg) and \
            # the community must allow this signature
            submsg.authentication.allow_signature_func(submsg)): 

            if __debug__:
                has_added_signature = False
                origional_packet_length = len(payload.packet)

            # adds one or more signature to the packet
            first_signature_offset = len(payload.packet) - sum([member.signature_length for member in submsg.members])
            signature_offset = first_signature_offset
            for member in submsg.members:
                if isinstance(member, PrivateMember):
                    payload.packet = payload.packet[:signature_offset] + \
                                     member.sign(payload.packet, 0, first_signature_offset) + \
                                     payload.packet[signature_offset+member.signature_length:]
                    if __debug__:
                        has_added_signature = True
                signature_offset += member.signature_length

            if __debug__:
                assert has_added_signature
                assert origional_packet_length == len(payload.packet)

            # if all signatures are set: update_locally
            # todo:
            if True:
                self.on_message(address, payload)

            # apparently we are going to propagate this message
            # todo:
            self.store_and_forward([payload])

        else:
            raise DropMessage("Nothing to sign")

    def _periodically_disperse(self):
        """
        Periodically disperse the latest bloom filters for each
        community.
        """
        #
        # Advertise the packages that we sync.  This means sending
        # a 'sync' message containing one or more bloom filters.
        #
        for community in self._communities.itervalues():
            global_time, bloom_filter = community.get_current_bloom_filter()
            community.permit(community.get_meta_message(u"dispersy-sync"), SyncPayload(global_time, bloom_filter), update_locally=False)

        self._rawserver.add_task(self._periodically_disperse, 1.0)
