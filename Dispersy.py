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
from re import compile as re_compile

from Authentication import NoAuthentication, MemberAuthentication, MultiMemberAuthentication
from Bloomfilter import BloomFilter
from Crypto import ec_generate_key, ec_to_public_pem, ec_to_private_pem
from Destination import CommunityDestination, AddressDestination, MemberDestination, SimilarityDestination
from DispersyDatabase import DispersyDatabase
from Distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Member import PrivateMember, MasterMember
from Message import Message
from Message import DropPacket, DelayPacket, DelayPacketByMissingMember, DelayPacketBySimilarity
from Message import DropMessage, DelayMessage, DelayMessageBySequence, DelayMessageBySimilarity
from Payload import MissingSequencePayload
from Payload import SyncPayload
from Payload import SignatureRequestPayload, SignatureResponsePayload
from Payload import RoutingRequestPayload, RoutingResponsePayload
from Payload import IdentityPayload, IdentityRequestPayload
from Payload import SimilarityRequestPayload, SimilarityPayload
from Resolution import PublicResolution
from Singleton import Singleton

if __debug__:
    from Print import dprint

class DummySocket(object):
    def send(address, data):
        pass

class Trigger(object):
    def on_message(self, address, message):
        """
        Called with a received message.

        Must return True to keep the trigger available.  Hence,
        returning False will remove the trigger.
        """
        raise NotImplementedError()

    def on_timeout(self):
        raise NotImplementedError()

class TriggerCallback(Trigger):
    def __init__(self, pattern, response_func, response_args, max_responses):
        """
        Receiving a message matching PATTERN triggers a call to
        RESPONSE_FUNC.

        PATTERN is a python regular expression string.

        RESPONSE_FUNC is called when PATTERN matches the incoming
        message footprint.  The first argument is the sender address,
        the second argument is the incoming message, following this
        are optional values from RESPONSE_ARGS.

        RESPONSE_ARGS is an optional tuple containing arguments passed
        to RESPONSE_ARGS.

        MAX_RESPONSES is a number.  Once MAX_RESPONSES messages are
        received no further calls are made to RESPONSE_FUNC.

        When a timeout is received and MAX_RESPONSES has not yet been
        reached, RESPONSE_FUNC is immediately called.  The first
        argument will be ('', -1), the second will be None, following
        this are the optional values from RESPONSE_FUNC.
        """
        assert isinstance(pattern, str)
        assert hasattr(response_func, "__call__")
        assert isinstance(response_args, tuple)
        assert isinstance(max_responses, int)
        assert max_responses > 0
        if __debug__:
            self._debug_pattern = pattern
        self._match = re_compile(pattern).match
        self._response_func = response_func
        self._response_args = response_args
        self._responses_remaining = max_responses

    def on_message(self, address, message):
        if self._responses_remaining > 0 and self._match(message.footprint):
            self._responses_remaining -= 1
            # note: this callback may raise DelayMessage, etc
            self._response_func(address, message, *self._response_args)

        # False to remove the Trigger
        return self._responses_remaining > 0

    def on_timeout(self):
        if self._responses_remaining > 0:
            self._responses_remaining = 0
            # note: this callback may raise DelayMessage, etc
            self._response_func(("", -1), None, *self._response_args)

class TriggerPacket(Trigger):
    def __init__(self, pattern, on_incoming_packets, packets):
        """
        Receiving a message matching PATTERN triggers a call to the
        on_incoming_packet method with PACKETS.

        PATTERN is a python regular expression string.

        ON_INCOMING_PACKETS is called when PATTERN matches the
        incoming message footprint.  The only argument is PACKETS.

        PACKETS is a list containing (address, packet) tuples.  These
        packets are effectively delayed until a message matching
        PATTERN was received.

        When a timeout is received this Trigger is removed and PACKETS
        are lost.
        """
        assert isinstance(pattern, str)
        assert hasattr(on_incoming_packets, "__call__")
        assert isinstance(packets, (tuple, list))
        assert len(packets) > 0
        assert not filter(lambda x: not isinstance(x, str), packets)
        if __debug__:
            self._debug_pattern = pattern
        self._match = re_compile(pattern).match
        self._on_incoming_packets = on_incoming_packet
        self._packets = packets

    def on_message(self, address, message):
        if self._match:
            if self._match(message.footprint):
                self._on_incoming_packets(packets)
                # False to remove the Trigger, because we handled the
                # Trigger
                return False
            else:
                # True to keep the Trigger, because we did not handle
                # the Trigger yet
                return True
        else:
            # False to remove the Trigger, because the Trigger
            # timed-out
            return False

    def on_timeout(self):
        if self._match:
            self._match = None

class TriggerMessage(Trigger):
    def __init__(self, pattern, on_incoming_message, address, message):
        """
        Receiving a message matching PATTERN triggers a call to the
        on_incoming_message message with ADDRESS and MESSAGE.

        PATTERN is a python regular expression string.

        ON_INCOMING_MESSAGE is called when PATTERN matches the
        incoming message footprint.  The first argument is ADDRESS,
        the second argument is MESSAGE.

        ADDRESS and MESSAGE are a Message.Implementation and the
        address from where this was received.  This message is
        effectively delayed until a message matching PATTERN is
        received.

        When a timeout is received this Trigger is removed MESSAGE is
        lost.
        """
        assert isinstance(pattern, str)
        assert hasattr(on_incoming_message, "__call__")
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(message, Message.Implementation)
        if __debug__:
            self._debug_pattern = pattern
        self._match = re_compile(pattern).match
        self._on_incoming_message = on_incoming_message
        self._address = address
        self._message = message

    def on_message(self, address, message):
        if self._match:
            if self._match(message.footprint):
                self._on_incoming_message(self._address, self._message)
                # False to remove the Trigger, because we handled the
                # Trigger
                return False
            else:
                # True to keep the Trigger, because we did not handle
                # the Trigger yet
                return True
        else:
            # False to remove the Trigger, because the Trigger
            # timed-out
            return False

    def on_timeout(self):
        if self._match:
            self._match = None

class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """
    def get_meta_messages(self, community):
        """
        Returns the Message instances available to Dispersy.

        Each Message has a name prefixed with dispersy, and each
        Community should support these Messages in order for Dispersy
        to function properly.
        """
        return [Message(community, u"dispersy-routing-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), RoutingRequestPayload()),
                Message(community, u"dispersy-routing-response", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), RoutingResponsePayload()),
                Message(community, u"dispersy-identity", MemberAuthentication(encoding="pem"), PublicResolution(), LastSyncDistribution(cluster=254, history_size=1), CommunityDestination(), IdentityPayload()),
                Message(community, u"dispersy-identity-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), IdentityRequestPayload()),
                Message(community, u"dispersy-sync", MemberAuthentication(), PublicResolution(), DirectDistribution(), CommunityDestination(), SyncPayload()),
                Message(community, u"dispersy-missing-sequence", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), MissingSequencePayload()),
                Message(community, u"dispersy-signature-request", NoAuthentication(), PublicResolution(), DirectDistribution(), MemberDestination(), SignatureRequestPayload()),
                Message(community, u"dispersy-signature-response", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), SignatureResponsePayload()),
                Message(community, u"dispersy-similarity", MemberAuthentication(), PublicResolution(), LastSyncDistribution(cluster=253, history_size=1), CommunityDestination(), SimilarityPayload()),
                Message(community, u"dispersy-similarity-request", NoAuthentication(), PublicResolution(), DirectDistribution(), AddressDestination(), SimilarityRequestPayload())]

    def get_message_handlers(self, community):
        """
        Returns the handler methods for the privileges available to
        Dispersy.
        """
        return [(community.get_meta_message(u"dispersy-routing-request"), self.on_routing_request),
                # (community.get_meta_message(u"dispersy-routing-response"), self.on_general_response),
                (community.get_meta_message(u"dispersy-identity"), self.on_identity),
                (community.get_meta_message(u"dispersy-identity-request"), self.on_identity_request),
                (community.get_meta_message(u"dispersy-sync"), self.on_sync_message),
                (community.get_meta_message(u"dispersy-missing-sequence"), self.on_missing_sequence),
                (community.get_meta_message(u"dispersy-signature-request"), self.on_signature_request),
                (community.get_meta_message(u"dispersy-signature-response"), self.on_ignore_message),
                (community.get_meta_message(u"dispersy-similarity"), self.on_similarity_message),
                (community.get_meta_message(u"dispersy-similarity-request"), self.on_similarity_request)]

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
            ec = ec_generate_key("low")
            public_pem = ec_to_public_pem(ec)
            private_pem = ec_to_private_pem(ec)
            self._database.execute(u"INSERT INTO option VALUES('my_public_pem', ?)", (buffer(public_pem),))

        # this is yourself
        # self._my_member = MyMember.get_instance(public_pem, private_pem)

        # all available communities.  cid:Community pairs.
        self._communities = {}

        # outgoing communication
        self._socket = DummySocket()

        # waiting for incoming messages
        self._triggers = []

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

    # @property
    # def my_member(self):
    #     return self._my_member

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
            raise DelayMessageBySequence(message, sequence+1, message.distribution.sequence_number-1)

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

            except DropPacket as exception:
                dprint(address[0], ":", address[1], ": drop a ", len(packet), " byte packet (", exception, ")", exception=True)
                log("dispersy.log", "drop-packet", address=address, packet=packet, exception=str(exception))

            except DelayPacket as delay:
                if __debug__: dprint(address[0], ":", address[1], ": delay a ", len(packet), " byte packet (", delay, ")")
                trigger = TriggerPacket(delay.pattern, self.on_incoming_packets, [(address, packet)])
                self._triggers.append(trigger)
                self._rawserver.add_task(trigger.on_timeout, 10.0)
                self._send([address], [delay.request_packet])

            else:
                #
                # Update routing table.  We know that some peer (not
                # necessarily message.authentication.member) exists at
                # this address.
                #
                self._database.execute(u"UPDATE routing SET incoming_time = DATETIME() WHERE community = ? AND host = ? AND port = ?",
                                       (message.community.database_id, unicode(address[0]), address[1]))
                if self._database.changes == 0:
                    self._database.execute(u"INSERT INTO routing(community, host, port, incoming_time, outgoing_time) VALUES(?, ?, ?, DATETIME(), '2010-01-01 00:00:00')",
                                           (message.community.database_id, unicode(address[0]), address[1]))

                #
                # Handle the message
                #
                self.on_incoming_message(address, message)

    def on_incoming_message(self, address, message):
        try:
            #
            # Filter messages based on distribution (usually duplicate
            # or old messages)
            #
            self._incoming_distribution_map.get(type(message.distribution), self._check_incoming_OTHER_distribution)(message)

            #
            # Allow community code to handle the message
            #
            if __debug__: dprint("incoming ", message.payload.type, "^", message.name, " (", len(message.packet), " bytes) from ", address[0], ":", address[1])
            if message.payload.type == u"permit":
                message.community.on_message(address, message)
            elif message.payload.type == u"authorize":
                message.community.on_authorize_message(address, message)
            elif message.payload.type == u"revoke":
                message.community.on_revoke_message(address, message)

        except DropMessage as exception:
            dprint(address[0], ":", address[1], ": drop a ", len(message.packet), " byte message (", exception, ")", exception=True)
            log("dispersy.log", "drop-message", address=address, message=message.name, packet=message.packet, exception=str(exception))

        except DelayMessage as delay:
            if __debug__: dprint(address[0], ":", address[1], ": delay a ", len(message.packet), " byte message (", delay, ")")
            trigger = TriggerMessage(delay.pattern, self.on_incoming_message, address, message)
            self._triggers.append(trigger)
            self._rawserver.add_task(trigger.on_timeout, 10.0)
            self._send([address], [delay.request_packet])

        else:
            #
            # Sync messages need to be stored (so they can be synced
            # later)
            #
            if isinstance(message.distribution, SyncDistribution.Implementation):
                self._sync_store(message)

            log("dispersy.log", "handled", address=address, packet=message.packet, message=message.name)

            #
            # This message may 'trigger' a previously delayed message
            #
            self._triggers = [trigger for trigger in self._triggers if trigger.on_message(address, message)]

    def _sync_store(self, message):
        assert isinstance(message.distribution, SyncDistribution.Implementation)

        # we do not store a message when it uses SimilarityDestination
        # and it its not similar
        if isinstance(message.destination, SimilarityDestination.Implementation) and not message.destination.is_similar:
            dprint("Not storing message.  bic:", message.destination.bic_occurrence, "  threshold:", message.destination.threshold)
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

    def await_message(self, footprint, response_func, response_args=(), timeout=10.0, max_responses=1):
        """
        Callback RESPONSE_FUNC when a message matching FOOTPRINT is
        received or after TIMEOUT seconds.

        When the footprint of an incoming message matches the regular
        expression FOOTPRINT it is passed to both the RESPONSE_FUNC
        (or several if the message matches multiple footprints) and
        its regular message handler.  First the regular message
        handler is called, followed by RESPONSE_FUNC.

        RESPONSE_FUNC is called each time when a message is received
        that matches FOOTPRINT or after TIMEOUT seconds when fewer
        than MAX_RESPONSES incoming messages have matched FOOTPRINT.
        The first argument is the sender address (or ('', -1) on a
        timeout), the second argument is the incoming message,
        following this are any optional arguments in RESPONSE_ARGS.

        RESPONSE_ARGS is a tuple that can be given optional values
        that are included with the call to RESPONSE_FUNC.

        TIMEOUT is a positive floating point number.  When less than
        MAX_RESPONSES messages have matched FOOTPRINT, the
        RESPONSE_FUNC is called one last time.  For the address ('',
        -1) and for the message None is given.  Once a timeout
        callback is given no further callbcks will be made.

        MAX_RESPONSES is a positive integer indicating the maximum
        number that RESPONSE_FUNC is called.

        The footprint matching is done as follows: for each incoming
        message a message footprint is made.  This footprint is a
        string that contains a summary of all the message properties.
        Such as 'MemberAuthentication:ABCDE' and
        'FullSyncDistribution:102'.
        """
        assert isinstance(footprint, str)
        assert hasattr(response_func, "__call__")
        assert isinstance(response_args, tuple)
        assert isinstance(timeout, float)
        assert timeout > 0.0
        assert isinstance(max_responses, (int, long))
        assert max_responses > 0

        trigger = TriggerCallback(footprint, response_func, response_args, max_responses)
        self._triggers.append(trigger)
        self._rawserver.add_task(trigger.on_timeout, timeout)

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
                raise DelayMessageBySimilarity(message, cluster)

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

                    if similarity.bic_occurrence(BloomFilter(str(packet_similarity), 0)) < threshold:
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
                                 meta.payload.implement(self._my_external_address, address))
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
                                 meta.payload.implement(self._my_external_address))
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
                                 meta.payload.implement(mid))
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
                                 meta.payload.implement(similarity_owner.destination.identifier, similarity))

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
        assert isinstance(message.payload.message, Message.Implementation), type(message.payload)
        assert isinstance(message.payload.message.authentication, MultiMemberAuthentication.Implementation)

        # submsg contains the message that should receive multiple
        # signatures
        submsg = message.payload.message

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

        # we must be one of the members that needs to sign
        if not has_private_member:
            raise DropMessage("Nothing to sign")

        # the message must be valid
        if not submsg.community._timeline.check(submsg):
            raise DropMessage("Doesn't fit timeline")

        # the community must allow this signature
        if not submsg.authentication.allow_signature_func(submsg):
            raise DropMessage("We choose not to add our signature")

        # create signature(s) and reply
        identifier = sha1(message.packet).digest()
        first_signature_offset = len(submsg.packet) - sum([member.signature_length for member in submsg.authentication.members])
        for member in submsg.authentication.members:
            if isinstance(member, PrivateMember):
                signature = member.sign(submsg.packet, 0, first_signature_offset)

                # send response
                meta = message.community.get_meta_message(u"dispersy-signature-response")
                message = meta.implement(meta.authentication.implement(),
                                         meta.distribution.implement(message.community._timeline.global_time),
                                         meta.destination.implement(address,),
                                         meta.payload.implement(identifier, signature))
                self.store_and_forward([message])

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

    def on_ignore_message(self, address, message):
        """
        Ignores the received message.

        This message handler is used when the incoming message can be
        ignored.  This can happen, for instance, when the message is
        already handled using a trigger set using self.await_message.
        """
        if __debug__:
            i = len([trigger for trigger in self._triggers if trigger._match(message.footprint)])
            j = len(self._triggers)
            dprint("Ignored ", message.name, " (matches ", i, "/", j, " triggers)")

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
                                           meta.payload.implement(global_time, bloom_filter)))
        self.store_and_forward(messages)
        self._rawserver.add_task(self._periodically_disperse, 10.0)

    def _periodically_stats(self):
        log("dispersy.log", "statistics", total_send=self._total_send, total_received=self._total_received)
        self._rawserver.add_task(self._periodically_stats, 1.0)
