"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from hashlib import sha1
from lencoder import log

from Authentication import NoAuthentication, MemberAuthentication, MultiMemberAuthentication
from Bloomfilter import BloomFilter
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from Destination import CommunityDestination, AddressDestination, MemberDestination, SimilarityDestination
from DispersyDatabase import DispersyDatabase
from Distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Member import MyMember, PrivateMember, MasterMember
from Message import Message
from Message import DropPacket, DelayPacket, DelayPacketByMissingMember, DelayPacketBySimilarity
from Message import DropMessage, DelayMessage, DelayMessageBySequence, DelayMessageBySimilarity
from Payload import MissingSequencePayload
from Payload import SyncPayload
from Payload import SignatureResponsePayload
from Payload import ResponsePayload, RoutingResponsePayload
from Payload import IdentityPayload, IdentityRequestPayload
from Payload import SimilarityRequestPayload
from Resolution import PublicResolution
from Singleton import Singleton

if __debug__:
    from Print import dprint

class DummySocket(object):
    def send(address, data):
        pass

class ExpectedResponse(object):
    def __init__(self, request, response_func, args):
        assert isinstance(request, Message.Implementation)
        assert isinstance(request.payload, Message.Implementation)
        assert isinstance(request.payload.authentication, MultiMemberAuthentication.Implementation)
        self._request = request
        self._response_func = response_func
        self._args = args

        if isinstance(request.destination, AddressDestination.Implementation):
            self._responses_remaining = len(request.destination.addresses)

        elif isinstance(request.destination, MemberDestination.Implementation):
            self._responses_remaining = len(request.destination.members)

        else:
            raise NotImplementedError(type(request.destination))

    @property
    def request(self):
        return self._request

    @property
    def response_func(self):
        return self._response_func

    @property
    def args(self):
        return self._args

    @property
    def responses_remaining(self):
        return self._responses_remaining

    def on_response(self, response):
        assert isinstance(response, Message.Implementation)
        self._responses_remaining -= 1

class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self, rawserver, working_directory):
        # the raw server
        self._rawserver = rawserver
        self._rawserver.add_task(self._periodically_disperse, 3.0)
        self._rawserver.add_task(self._periodically_stats, 1.0)

        # where we store all data
        self._working_directory = working_directory

        # our data storage
        self._database = DispersyDatabase.get_instance(working_directory)
        
        # our external address
        try:
            ip, = self._database.execute(u"SELECT value FROM option WHERE key = 'my_external_ip' LIMIT 1").next()
            port, = self._database.execute(u"SELECT value FROM option WHERE key = 'my_external_port' LIMIT 1").next()
            self._my_external_address = (str(ip), port)
        except StopIteration:
            self._my_external_address = ("", -1)

        try:
            public_pem, = self._database.execute(u"SELECT value FROM option WHERE key == 'my_public_pem' LIMIT 1").next()
            public_pem = str(public_pem)
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

        # statistics...
        self._total_send = 0
        self._total_received = 0

    @property
    def working_directory(self):
        return self._working_directory

    @property
    def socket(self):
        return self._socket

    @socket.setter
    def socket(self, socket):
        self._socket = socket
        if self._my_external_address == ("", -1):
            self._my_external_address = socket.get_address()

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
            for global_time, packet in execute(u"SELECT global_time, packet FROM sync WHERE community = ? ORDER BY global_time", (community.database_id,)):
                community.get_bloom_filter(global_time).add(str(packet))

            for global_time, packet in execute(u"SELECT global_time, packet FROM sync WHERE community = ? ORDER BY global_time", (community.database_id,)):
                community.get_bloom_filter(global_time).add(str(packet))

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
        if isinstance(delay, DelayPacketByMissingMember):
            key = "message:dispersy-identity community:{0.community.cid} member:{0.missing_member_id}".format(delay)
            if not key in self._delayed:
                self._delayed[key] = (address, packet)
                meta = delay.community.get_meta_message(u"dispersy-identity-request")
                message = meta.implement(meta.authentication.implement(),
                                         meta.distribution.implement(meta.community._timeline.global_time),
                                         meta.destination.implement(address),
                                         IdentityRequestPayload(delay.missing_member_id))
                self._send([address], [message.community.get_conversion().encode_message(message)])

        elif isinstance(delay, DelayPacketBySimilarity):
            key = "message:dispersy-similarity community:{0.community.database_id} member:{0.member.database_id} cluster:{0.cluster}".format(delay)
            if not key in self._delayed:
                self._delayed[key] = (address, message)
                meta = message.community.get_meta_message(u"dispersy-similarity-request")
                request = meta.implement(meta.authentication.implement(),
                                         meta.distribution.implement(message.community._timeline.global_time),
                                         meta.destination.implement(address),
                                         SimilarityRequestPayload(delay.cluster, [delay.member]))
                self._send([address], [meta.community.get_conversion().encode_message(request)])

        else:
            raise NotImplementedError(type(delay))

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
            key = "message:{0.name} community:{0.community.database_id} member:{0.authentication.member.database_id} sequence:{1.missing_high}".format(message, delay)
            if not key in self._delayed:
                self._delayed[key] = (address, message)
                meta = message.community.get_meta_message(u"dispersy-missing-sequence")
                request = meta.implement(meta.authentication.implement(),
                                         meta.distribution.implement(meta.community._timeline.global_time),
                                         meta.destination.implement(address),
                                         MissingSequencePayload(message.authentication.member, message.meta, delay.missing_low, delay.missing_high))
                self._send([address], [meta.community.get_conversion().encode_message(request)])

        elif isinstance(delay, DelayMessageBySimilarity):
            cluster = message.community.get_meta_message(u"dispersy-similarity").distribution.cluster
            key = "message:dispersy-similarity community:{0.community.database_id} member:{1.member.database_id} distribution_cluster:{2}".format(message, delay, cluster)
            if not key in self._delayed:
                self._delayed[key] = (address, message)
                meta = message.community.get_meta_message(u"dispersy-similarity-request")
                request = meta.implement(meta.authentication.implement(),
                                         meta.distribution.implement(message.community._timeline.global_time),
                                         meta.destination.implement(delay.member.address),
                                         SimilarityRequestPayload(delay.cluster, [delay.member]))
                self._send([address], [meta.community.get_conversion().encode_message(request)])
        else:
            raise NotImplementedError(delay)

    def _check_delayed_full_sync_distribution(self, message):
        key = "message:{0.name} community:{0.community.database_id} member:{0.authentication.member.database_id} sequence:{0.distribution.sequence_number}".format(message)
        if key in self._delayed:
            return self._delayed.pop(key)

        key = "message:{0.name} community:{0.community.database_id} member:{0.authentication.member.database_id}".format(message)
        if key in self._delayed:
            return self._delayed.pop(key)

        return None

    def _check_delayed_last_sync_distribution(self, message):
        dprint(message)
        dprint(self._delayed.keys())

        key = "message:{0.name} community:{0.community.database_id} member:{0.authentication.member.database_id}".format(message)
        if key in self._delayed:
            return self._delayed.pop(key)

        if isinstance(message.distribution, LastSyncDistribution.Implementation):
            key = "message:{0.name} community:{0.community.database_id} member:{0.authentication.member.database_id} distribution_cluster:{0.distribution.cluster}".format(message)
            dprint(key)
            if key in self._delayed:
                return self._delayed.pop(key)

        return None

    def _check_delayed_direct_distribution(self, message):
        pass

    def _check_delayed_OTHER_distribution(self, message):
        raise NotImplementedError(message.distribution)

    def _check_incoming_full_sync_distribution(self, message):
        try:
            sequence, = self._database.execute(u"""SELECT distribution_sequence
                                                   FROM sync
                                                   WHERE community = ? AND user = ? AND distribution_sequence > 0
                                                   ORDER BY distribution_sequence DESC
                                                   LIMIT 1""",
                                               (message.community.database_id,
                                                message.authentication.member.database_id)).next()
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
        times = [x for x, in self._database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ? LIMIT ?",
                                                    (message.community.database_id,
                                                     message.authentication.member.database_id,
                                                     message.distribution.cluster,
                                                     message.distribution.history_size))]

        if message.distribution.global_time in times:
            raise DropMessage("duplicate message")

        if len(times) >= message.distribution.history_size and min(times) > message.distribution.global_time:
            raise DropMessage("older message")

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

            if __debug__: dprint(address[0], ":", address[1], ": ", len(packet), " bytes were received")
            self._total_received += len(packet)

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
                    if __debug__: dprint("incoming ", message.payload.type, "^", message.name, " (", len(message.packet), " bytes) from ", address[0], ":", address[1])
                    if message.payload.type == u"permit":
                        community.on_message(address, message)
                    elif message.payload.type == u"authorize":
                        community.on_authorize_message(address, message)
                    elif message.payload.type == u"revoke":
                        community.on_revoke_message(address, message)

                    #
                    # Sync messages need to be stored (so they can be
                    # synced later)
                    #
                    if isinstance(message.distribution, SyncDistribution.Implementation):
                        self._sync_store(message)

                    log("dispersy.log", "handled", address=address, packet=packet, message=message.name)

                    #
                    # This message may 'trigger' a previously delayed message
                    #
                    tup = self._check_delayed_map.get(type(message.distribution), self._check_delayed_OTHER_distribution)(message)
                    if tup:
                        if isinstance(tup[1], str):
                            address = tup[0]
                            message = conversion.decode_message(tup[1])

                        else:
                            address, message = tup

                        assert isinstance(address, tuple)
                        assert isinstance(message, Message.Implementation)
                    else:
                        break

            except DropPacket as exception:
                dprint(address[0], ":", address[1], ": drop a ", len(packet), " byte packet (", exception, ")", exception=True)
                log("dispersy.log", "drop-packet", address=address, packet=packet, exception=str(exception))
 
            except DelayPacket as delay:
                if __debug__: dprint(address[0], ":", address[1], ": delay a ", len(packet), " byte packet (", delay, ")")
                self._delay_packet(address, packet, delay)
 
            except DropMessage as exception:
                dprint(address[0], ":", address[1], ": drop a ", len(message.packet), " byte message (", exception, ")", exception=True)
                log("dispersy.log", "drop-message", address=address, message=message.name, packet=message.packet, exception=str(exception))
             
            except DelayMessage as delay:
                if __debug__: dprint(address[0], ":", address[1], ": delay a ", len(message.packet), " byte message (", delay, ")")
                self._delay_message(address, message, delay)
 
    def _sync_store(self, message):
        assert isinstance(message.distribution, SyncDistribution.Implementation)

        # we do not store a message when it uses SimilarityDestination
        # and it its not similar
        if isinstance(message.destination, SimilarityDestination.Implementation) and not message.destination.is_similar:
            dprint("Not storing message.  xor:", message.destination.xor_occurrence, "  threshold:", message.destination.threshold)
            return

        # sync bloomfilter
        message.community.get_bloom_filter(message.distribution.global_time).add(message.packet)

        with self._database as execute:

            # delete packet if there are to many stored
            if isinstance(message.distribution, LastSyncDistribution.Implementation):
                try:
                    id_, = execute(u"SELECT id FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ? ORDER BY global_time DESC LIMIT 1 OFFSET ?",
                                   (message.community.database_id,
                                    message.authentication.member.database_id,
                                    message.distribution.cluster,
                                    message.distribution.history_size - 1)).next()
                except StopIteration:
                    pass
                else:
                    execute(u"DELETE FROM sync WHERE id = ?", (id_,))

            # add packet to database
            execute(u"INSERT INTO sync(community, user, global_time, distribution_sequence, distribution_cluster, destination_cluster, packet) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (message.community.database_id,
                     message.authentication.member.database_id,
                     message.distribution.global_time,
                     isinstance(message.distribution, FullSyncDistribution.Implementation) and message.distribution.sequence_number or 0,
                     isinstance(message.distribution, LastSyncDistribution.Implementation) and message.distribution.cluster or 0,
                                    isinstance(message.destination, SimilarityDestination.Implementation) and message.destination.cluster or 0,
                     buffer(message.packet)))

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
            dprint(message)

            # Store
            if isinstance(message.distribution, SyncDistribution.Implementation):
                self._sync_store(message)

            # Forward
            if isinstance(message.destination, (CommunityDestination.Implementation, SimilarityDestination.Implementation)):
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
                sql = u"""SELECT ABS(STRFTIME('%s', outgoing_time) - STRFTIME('%s', incoming_time)) AS diff, STRFTIME('%s', DATETIME()) - STRFTIME('%s', outgoing_time) AS age, host, port
                          FROM routing
                          WHERE community = ? AND (diff < 30 OR age > 300)
                          ORDER BY diff ASC, age DESC
                          LIMIT 2"""
                addresses = set([(str(host), port) for _, _, host, port in self._database.execute(sql, (message.community.database_id,))])
                has_recent = bool(addresses)

                # we need to fallback to something... just pick
                # some addresses within this community.
                sql = u"""SELECT ABS(STRFTIME('%s', outgoing_time) - STRFTIME('%s', incoming_time)) AS diff, STRFTIME('%s', DATETIME()) - STRFTIME('%s', outgoing_time) AS age, host, port
                          FROM routing
                          WHERE community = ?
                          ORDER BY diff ASC, age DESC
                          LIMIT 3"""
                addresses.update([(str(host), port) for _, _, host, port in self._database.execute(sql, (message.community.database_id,))])

                if not has_recent:
                    # we need to fallback to something else... just
                    # pick some addresses.
                    sql = u"""SELECT host, port
                              FROM routing
                              WHERE community = 0
                              LIMIT 2"""
                    addresses.update([(str(host), port) for host, port in self._database.execute(sql)])
                
                if __debug__:
                    addresses = [(host, port) for host, port in addresses if not (host == "130.161.158.222" and port == self._my_external_address[1])]
                
                self._send(addresses, [message.packet])

            elif isinstance(message.destination, AddressDestination.Implementation):
                self._send(message.destination.addresses, [message.packet])

            elif isinstance(message.destination, MemberDestination.Implementation):
                self._send([member.address for member in message.destination.members], [message.packet])

            else:
                raise NotImplementedError(message.destination)

    def _send(self, addresses, packets):
        self._total_send += len(addresses) * sum([len(packet) for packet in packets])
        
        with self._database as execute:
            for address in addresses:
                assert isinstance(address, tuple)
                assert isinstance(address[0], str)
                assert isinstance(address[1], int)
                for packet in packets:
                    assert isinstance(packet, str)
                    if __debug__: dprint(len(packet), " bytes to ", address[0], ":", address[1])
                    self._socket.send(address, packet)
                execute(u"UPDATE routing SET outgoing_time = DATETIME() WHERE host = ? AND port = ?", (unicode(address[0]), address[1]))

    def await_response(self, request, response_func, timeout=10.0, *args):
        assert isinstance(request, Message.Implementation)
        assert request.packet
        assert hasattr(response_func, "__call__")
        assert isinstance(timeout, float)
        assert timeout > 0.0

        def on_timeout():
            expected_response = self._expected_responses.pop(request_id, None)
            if expected_response:
                expected_response.response_func(("", -1), expected_response.request, None, *expected_response.args)

        request_id = sha1(request.packet).digest()
        assert not request_id in self._expected_responses
        self._expected_responses[request_id] = ExpectedResponse(request, response_func, args)
        self._rawserver.add_task(on_timeout, timeout)

    def get_meta_messages(self, community):
        """
        Returns the Message instances available to Dispersy.

        Each Message has a name prefixed with dispersy, and each
        Community should support these Messages in order for Dispersy
        to function properly.
        """
        return [Message(community, u"dispersy-routing-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
                Message(community, u"dispersy-routing-response", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
                Message(community, u"dispersy-identity", MemberAuthentication(encoding="pem"), PublicResolution(), LastSyncDistribution(cluster=254, history_size=1), CommunityDestination()),
                Message(community, u"dispersy-identity-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
                Message(community, u"dispersy-sync", MemberAuthentication(), PublicResolution(), DirectDistribution(), CommunityDestination()),
                Message(community, u"dispersy-missing-sequence", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination()),
                Message(community, u"dispersy-signature-request", NoAuthentication(), PublicResolution(), DirectDistribution(), MemberDestination()),
                Message(community, u"dispersy-signature-response", NoAuthentication(), PublicResolution(), DirectDistribution(), MemberDestination()),
                Message(community, u"dispersy-similarity", MemberAuthentication(), PublicResolution(), LastSyncDistribution(cluster=253, history_size=1), CommunityDestination()),
                Message(community, u"dispersy-similarity-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination())]

    def get_message_handlers(self, community):
        """
        Returns the handler methods for the privileges available to
        Dispersy.
        """
        return [(community.get_meta_message(u"dispersy-routing-request"), self.on_routing_request),
                (community.get_meta_message(u"dispersy-routing-response"), self.on_general_response),
                (community.get_meta_message(u"dispersy-identity"), self.on_identity),
                (community.get_meta_message(u"dispersy-identity-request"), self.on_identity_request),
                (community.get_meta_message(u"dispersy-sync"), self.on_sync_message),
                (community.get_meta_message(u"dispersy-missing-sequence"), self.on_missing_sequence),
                (community.get_meta_message(u"dispersy-signature-request"), self.on_signature_request),
                (community.get_meta_message(u"dispersy-signature-response"), self.on_general_response),
                (community.get_meta_message(u"dispersy-similarity"), self.on_similarity_message),
                (community.get_meta_message(u"dispersy-similarity-request"), self.on_similarity_request)]

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
        assert message.name == u"dispersy-sync"
        if __debug__: dprint(message)

        # 5 kb per sync (or max N packets, see limit in query)
        limit = self._total_send + 1024 * 5 

        similarity_cache = {}
        bloom_filter = message.payload.bloom_filter

        def get_similarity(cluster):
            try:
                similarity, = self._database.execute(u"SELECT similarity FROM similarity WHERE community = ? AND user = ? AND cluster = ?",
                                                     (message.community.database_id, message.authentication.member.database_id, cluster)).next()
            except StopIteration:
                # this message should never have been stored in the
                # database without a similarity.  Thus the Database is
                # corrupted.
                raise DelayMessageBySimilarity(message.authentication.member, cluster)

            for msg in message.community.get_meta_messages():
                if isinstance(msg.destination, SimilarityDestination) and msg.destination.cluster == cluster:
                    threshold = msg.destination.threshold
                    break
            else:
                raise NotImplementedError("No messages are defined that use this cluster")

            return BloomFilter(str(similarity), 0), threshold

        sql = u"""SELECT sync.packet, sync.destination_cluster, similarity.similarity
                  FROM sync
                  LEFT OUTER JOIN similarity ON sync.community = similarity.community AND sync.user = similarity.user AND sync.destination_cluster = similarity.cluster
                  WHERE sync.community = ? AND sync.global_time >= ?
                  ORDER BY sync.global_time LIMIT 50"""
        for packet, similarity_cluster, packet_similarity in self._database.execute(sql, (message.community.database_id, message.payload.global_time)):
            packet = str(packet)
            if not packet in bloom_filter:
                # check if the packet uses the SimilarityDestination policy
                if similarity_cluster:
                    similarity, threshold = similarity_cache.get(similarity_cluster, (None, None))
                    if similarity is None:
                        similarity, threshold = get_similarity(similarity_cluster)
                        similarity_cache[similarity_cluster] = (similarity, threshold)

                    if similarity.xor_occurrence(BloomFilter(str(packet_similarity), 0)) >= threshold:
                        dprint("do not send this packet: not similar")
                        # do not send this packet: not similar
                        continue

                if __debug__: dprint("Syncing ", len(packet), " bytes from sync_full to " , address[0], ":", address[1])
                self._socket.send(address, packet)

                self._total_send += len(packet)
                if self._total_send > limit:
                    break

    def on_routing_request(self, address, message):
        """
        We received a dispersy-routing-request message.

        This message contains the external address that the sender
        believes it has (message.payload.source_address), and our
        external address (message.payload.destination_address).

        We should send a dispersy-routing-response message back.
        Allowing us to inform them of their external address.
        """
        if __debug__:
            from Message import Message
        assert message.name == u"dispersy-routing-request"
        assert isinstance(message, Message.Implementation)
        if __debug__: dprint(message)
        # dprint("Our external address may be: ", message.payload.destination_address)
        # self._database.execute(u"UPDATE user SET user = ? WHERE community = ? AND host = ? AND port = ?",
        #                        (message.authentication.member.database_id, message.community.database_id, unicode(address[0]), address[1]))

        # send response
        meta = message.community.get_meta_message(u"dispersy-routing-response")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(meta.community._timeline.global_time),
                                 meta.destination.implement(address),
                                 RoutingResponsePayload(self._my_external_address, address))
        self.store_and_forward([message])

    def create_identity(self, community, store_and_forward=True):
        """
        Create an identity message.

        At least one identity message should be created for each
        community that the member is part of.  Generally one is
        created when either a community is joined (for the first time)
        or when a community is created.

        This message contains an address where the sender should be
        available (message.payload.address) and the public PEM.
        """
        meta = community.get_meta_message(u"dispersy-identity")
        message = meta.implement(meta.authentication.implement(community.my_member),
                                 meta.distribution.implement(community._timeline.global_time),
                                 meta.destination.implement(),
                                 IdentityPayload(self._my_external_address))
        if store_and_forward:
            self.store_and_forward([message])
        return message

    def on_identity(self, address, message):
        """
        We received a dispersy-identity message.

        This message contains an address where the sender should be
        available (message.payload.address) and the public PEM.
        """
        assert message.name == u"dispersy-identity"
        if __debug__: dprint(message)
        host, port = message.payload.address
        with self._database as execute:
            execute(u"INSERT OR IGNORE INTO routing(community, host, port, incoming_time, outgoing_time) VALUES(?, ?, ?, DATETIME(), '2010-01-01 00:00:00')", (message.community.database_id, unicode(host), port))
            execute(u"UPDATE user SET host = ?, port = ? WHERE id = ?", (unicode(host), port, message.authentication.member.database_id))
            execute(u"UPDATE identity SET packet = ? WHERE user = ? AND community = ?", (buffer(message.packet), message.authentication.member.database_id, message.community.database_id))
            if self._database.changes == 0:
                execute(u"INSERT INTO identity(user, community, packet) VALUES(?, ?, ?)", (message.authentication.member.database_id, message.community.database_id, buffer(message.packet)))
        message.authentication.member.update()

    def create_identity_request(self, community, mid, address, store_and_forward=True):
        """
        Create a message requesting a dispersy-identity message.
        """
        meta = community.get_meta_message(u"dispersy-identity-request")
        message = meta.implement(meta.authentication.implement(),
                                 meta.distribution.implement(),
                                 meta.destination.implement(address),
                                 IdentityRequestPayload(mid))
        if store_and_forward:
            self.store_and_forward(message)
        return message

    def on_identity_request(self, address, message):
        """
        We received a dispersy-identity-request message.

        The message contains the mid of a member.  The sender would
        like to obtain one or more associated dispersy-identity
        messages.
        """
        assert message.name == u"dispersy-identity-request"
        if __debug__: dprint(message)
        sql = u"""SELECT identity.packet
                  FROM identity
                  JOIN user ON user.id = identity.user
                  WHERE identity.community = ? AND user.mid = ?
                  LIMIT 10"""
        self._send([address], [str(packet) for packet, in self._database.execute(sql, (message.community.database_id, buffer(message.payload.mid)))])

    def create_similarity(self, community, message, keywords, update_locally=True, store_and_forward=True):
        """
        Create similarity for message using a list of keywords
        """
        assert isinstance(message, unicode)
        assert isinstance(keywords, (tuple, list))
        assert not filter(lambda x: not isinstance(x, str), keywords)
        assert isinstance(update_locally, bool)
        assert isinstance(store_and_forward, bool)
        
        similarity_owner = community.get_meta_message(message)
        meta = community.get_meta_message(u"dispersy-similarity")

        # BloomFilter created with 1 slice and defined number of bits
        similarity = BloomFilter(1, similarity_owner.destination.size)
        map(similarity.add, keywords)

        # store into db
        self._database.execute(u"INSERT OR REPLACE INTO my_similarity(community, user, cluster, similarity) VALUES(?, ?, ?, ?)",
                               (community.database_id,
                                community.my_member.database_id,
                                similarity_owner.destination.cluster,
                                buffer(str(similarity))))
        
        similarity = self.regulate_similarity(similarity_owner.destination)

        # implement the message
        message = meta.implement(meta.authentication.implement(community.my_member),
                                 meta.distribution.implement(community._timeline.claim_global_time()),
                                 meta.destination.implement(),
                                 SimilarityPayload(similarity_owner.destination.identifier, similarity))
        
        if update_locally:
            assert community._timeline.check(message)
            community.on_message(("", -1), message)

        if store_and_forward:
            self.store_and_forward([message])

        return message

    def on_similarity_message(self, address, message):
        """
        We received a dispersy-similarity message.

        The message contains a bloom-filter with only one slice that
        represents the sphere of influence of the creator of the
        message.

        We store this bloomfilter in our database and later use it in
        the SimilarityDestination to forward messages accordingly.
        """
        if __debug__:
            from Message import Message
        assert isinstance(message, Message.Implementation)

        self._database.execute(u"INSERT OR REPLACE INTO similarity(community, user, cluster, similarity, packet) VALUES(?, ?, ?, ?, ?)",
                               (message.community.database_id,
                                message.authentication.member.database_id,
                                message.payload.cluster,
                                buffer(str(message.payload.similarity)),
                                buffer(message.packet)))

    def regulate_similarity(self, community, similarity_destination):
        """
        Regulate the BloomFilter similarity by randomly inserting
        extra bits until the number of bits is at least the
        minumum amound of bits as defined in similarity_destination

        Receives a meta SimilarityDestination
        """
        # assert here
        if __debug__:
            from Destination import SimilarityDestination
        assert isinstance(similarity_destination, SimilarityDestination)
        
        minimum_bits = similarity_destination.minimum_bits
        maximum_bits = similarity_destination.maximum_bits

        # fetch my_similarity from db
        try:
            my_similarity, = self._database.execute(u"SELECT similarity FROM my_similarity WHERE community == ? AND user == ? AND cluster == ? LIMIT 1",
                                                    (community.database_id, community.my_member.database_id, similarity_destination.cluster)).next()
        except StopIteration:
            raise ValueError(u"Similarity not found in database")

        # the database returns <buffer> types, we use the binary
        # <str> type internally
        similarity = BloomFilter(str(my_similarity), 0)

        # todo: make this into a bloomfilter method 
        # count the 1's
        set_bits = 0
        for c in similarity._bytes.tostring():
            s = "{0:08d}".format(int(bin(ord(c))[2:]))
            for bit in s:
                if bit == '1':
                    set_bits += 1

        if set_bits > maximum_bits:
            raise ValueError("To many bits set in the similarity")

        # todo: make this into a bloomfilter method (the setting of specific bits)
        # add new bits
        new_bits = 0
        check = 0b1
        while new_bits < minimum_bits - set_bits:
            for b in range(len(similarity._bytes)):
                if not similarity._bytes[b] & check:
                    similarity._bytes[b] |= check
                    new_bits += 1
            check <<= 1

        return similarity

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
            self._total_send += len(packet)
            self._socket.send(address, packet)

    def on_signature_request(self, address, message):
        """
        We received a dispersy-signature-request message.

        This message contains another message (message.payload).
        Someone requested us to add our signature to this submessage.
        The message may, or may not, have already been signed by some
        of the other members.  Furthermore, we can choose for
        ourselves if we want to sign this message or not.

        When the message is allowed to be signed, a
        dispersy-signature-response message is send to the creator of
        the message (the first one in the authentication list).
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

            # send response
            meta = message.community.get_meta_message(u"dispersy-signature-response")
            message = meta.implement(meta.authentication.implement(),
                                     meta.distribution.implement(),
                                     meta.destination_address(message.authentication.member,),
                                     message)
            self.store_and_forward(message)

        else:
            raise DropMessage("Nothing to sign")

    def on_similarity_request(self, address, message):
        """
        We received a dispersy-similarity-request message.

        Construct a dispersy-similarity message with the similarity of
        the community, user and cluster as described in the
        message.payload
        """
        for member in message.payload.members:
            try:
                packet, = self._database.execute(u"SELECT packet FROM similarity WHERE community = ? AND user = ? AND cluster = ?",
                                                 (message.community.database.id, member.database_id, message.payload.cluster)).next()
            except StopIteration:
                continue

            self._send([address], [packet])
                
    def on_general_response(self, address, message):
        expected_response = self._expected_responses.pop(message.payload.request_id)
        if expected_response:
            # check if we expect more responses
            expected_response.on_response(message)
            if expected_response.responses_remaining:
                self._expected_responses[message.payload.request_id] = expected_response

            # handle the incoming response
            expected_response.response_func(address, expected_response.request, message.payload, *expected_response.args)

    def _periodically_disperse(self):
        """
        Periodically disperse the latest bloom filters for each
        community.
        """
        #
        # Advertise the packages that we sync.  This means sending
        # a 'sync' message containing one or more bloom filters.
        #
        messages = []
        for community in self._communities.itervalues():
            global_time, bloom_filter = community.get_current_bloom_filter()
            meta = community.get_meta_message(u"dispersy-sync")
            messages.append(meta.implement(meta.authentication.implement(community._my_member),
                                           meta.distribution.implement(community._timeline.global_time),
                                           meta.destination.implement(),
                                           SyncPayload(global_time, bloom_filter)))
        self.store_and_forward(messages)
        self._rawserver.add_task(self._periodically_disperse, 10.0)

    def _periodically_stats(self):
        log("dispersy.log", "statistics", total_send=self._total_send, total_received=self._total_received)
        self._rawserver.add_task(self._periodically_stats, 1.0)
        
