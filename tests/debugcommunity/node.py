import sys
from time import time, sleep
import logging

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.task import deferLater
from twisted.python.threadable import isInIOThread

from ...bloomfilter import BloomFilter
from ...candidate import Candidate
from ...endpoint import TUNNEL_PREFIX
from ...exception import ConversionNotFoundException
from ...member import Member
from ...message import Message
from ...resolution import PublicResolution, LinearResolution
from .community import DebugCommunity
from ...util import blocking_call_on_reactor_thread, blockingCallFromThread


class DebugNode(object):

    """
    DebugNode is used to represent an external node/peer while performing unittests.

    One or more debug nodes are generally made, for each unittest, as follows:

       # create external node
       node = DebugNode(community)
       node.init_my_member()
    """

    def __init__(self, testclass, dispersy, communityclass=DebugCommunity, c_master_member=None, curve=u"low"):
        super(DebugNode, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._testclass = testclass
        self._dispersy = dispersy
        self._my_member = self._dispersy.get_new_member(curve)
        self._my_pub_member = Member(self._dispersy, self._my_member._ec.pub(), self._my_member.database_id)

        if c_master_member == None:
            self._community = communityclass.create_community(self._dispersy, self._my_member)
        else:
            mm = self._dispersy.get_member(mid=c_master_member._community._master_member.mid)
            self._community = communityclass.init_community(self._dispersy, mm, self._my_member)

        self._central_node = c_master_member
        self._tunnel = False
        self._connection_type = u"unknown"

    @property
    def community(self):
        """
        The community for this node.
        """
        return self._community

    @property
    def tunnel(self):
        """
        True when this node is behind a tunnel.
        """
        return self._tunnel

    @property
    def lan_address(self):
        """
        The LAN address for this node.
        """
        return self._dispersy.lan_address

    @property
    def wan_address(self):
        """
        The WAN address for this node.
        """
        return self._dispersy.wan_address

    @property
    def connection_type(self):
        """
        The connection type for this node.
        """
        return self._connection_type

    @property
    def my_member(self):
        """
        The member for this node.
        """
        return self._my_member

    @property
    def my_mid(self):
        """
        The mid for this node.
        """
        return self._my_member.mid

    @property
    def my_pub_member(self):
        """
        The member for this node.
        """
        return self._my_pub_member

    @property
    def my_candidate(self):
        """
        A Candidate instance for this node.
        """
        return Candidate(self.lan_address, self.tunnel)

    @inlineCallbacks
    def init_my_member(self, tunnel=False, store_identity=True):
        """
        When STORE_IDENTITY is True this node will send the central node an introduction-request
        """
        self._tunnel = tunnel
        if self._central_node:
            self.send_identity(self._central_node)

            # download mm identity, mm authorizing central_node._my_member
            packets = self._central_node.fetch_packets([u"dispersy-identity", u"dispersy-authorize"], self._community.master_member.mid)
            self.give_packets(packets, self._central_node)

            # add this node to candidate list of mm
            message = self.create_introduction_request(self._central_node.my_candidate, self.lan_address, self.wan_address, False, u"unknown", None, 1, 1)
            yield self._central_node.give_message(message, self)

            # remove introduction responses from socket
            messages = yield self.receive_messages(names=[u'dispersy-introduction-response'])

            assert len(messages), "No introduction messages received!"

    def encode_message(self, message):
        """
        Returns the raw packet after MESSAGE is encoded using the associated community.
        """
        assert isinstance(message, Message.Implementation)
        return self._community.get_conversion_for_message(message).encode_message(message)

    def give_packet(self, packet, source, cache=False):
        self.give_packets([packet], source, cache=cache)

    def give_packets(self, packets, source, cache=False):
        """
        Give multiple PACKETS directly to Dispersy on_incoming_packets.
        Returns PACKETS
        """
        assert isinstance(packets, list), type(packets)
        assert all(isinstance(packet, str) for packet in packets), [type(packet) for packet in packets]
        assert isinstance(source, DebugNode), type(source)
        assert isinstance(cache, bool), type(cache)

        self._logger.debug("%s giving %d bytes", self.my_candidate, sum(len(packet) for packet in packets))
        self._dispersy.endpoint.process_packets([(source.lan_address, TUNNEL_PREFIX + packet if source.tunnel else packet) for packet in packets], cache=cache)

    def give_message(self, message, source, cache=False):
        self.give_messages([message], source, cache=cache)

    def give_messages(self, messages, source, cache=False):
        """
        Give multiple MESSAGES directly to Dispersy on_incoming_packets after they are encoded.
        Returns MESSAGES
        """
        assert isinstance(messages, list), type(messages)
        assert all(isinstance(message, Message.Implementation) for message in messages), [type(message) for message in messages]
        assert isinstance(cache, bool), type(cache)

        packets = [message.packet if message.packet else self.encode_message(message) for message in messages]
        self._logger.debug("%s giving %d messages (%d bytes)",
                           self.my_candidate, len(messages), sum(len(packet) for packet in packets))
        self.give_packets(packets, source, cache=cache)

    def send_packet(self, packet, candidate):
        """
        Sends PACKET to ADDRESS using the nodes' socket.
        Returns PACKET
        """
        assert isinstance(packet, str)
        assert isinstance(candidate, Candidate)
        self._logger.debug("%d bytes to %s", len(packet), candidate)
        return self._dispersy.endpoint.send([candidate], [packet])

    def send_message(self, message, candidate):
        """
        Sends MESSAGE to ADDRESS using the nodes' socket after it is encoded.
        Returns MESSAGE
        """
        assert isinstance(message, Message.Implementation), message
        assert isinstance(candidate, Candidate)

        self._logger.debug("%s to %s", message.name, candidate)
        self.encode_message(message)

        return self.send_packet(message.packet, candidate)

    def process_packets(self, timeout=1.0):
        """
        Process all packets on the nodes' socket.
        """
        timeout = time() + timeout
        while timeout > time():
            packets = self._dispersy.endpoint.process_receive_queue()
            if packets:
                return packets
            else:
                sleep(0.1)

    def drop_packets(self):
        """
        Discard all packets on the nodes' socket.
        """
        for address, packet in self._dispersy.endpoint.clear_receive_queue():
            self._logger.debug("dropped %d bytes from %s:%d", len(packet), address[0], address[1])

    def receive_packet(self, addresses=None, timeout=0.5):
        """
        Returns the first matching (candidate, packet) tuple from incoming UDP packets.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.
        """
        assert addresses is None or isinstance(addresses, list)
        assert addresses is None or all(isinstance(address, tuple) for address in addresses)
        assert isinstance(timeout, (int, float)), type(timeout)

        timeout = time() + timeout
        while timeout > time():
            packets = self._dispersy.endpoint.clear_receive_queue()
            if packets:
                for address, packet in packets:
                    if not (addresses is None or address in addresses or (address[0] == "127.0.0.1" and ("0.0.0.0", address[1]) in addresses)):
                        self._logger.debug("Ignored %d bytes from %s:%d", len(packet), address[0], address[1])
                        continue

                    if packet.startswith("ffffffff".decode("HEX")):
                        tunnel = True
                        packet = packet[4:]
                    else:
                        tunnel = False

                    candidate = Candidate(address, tunnel)
                    self._logger.debug("%d bytes from %s", len(packet), candidate)
                    yield candidate, packet
            else:
                sleep(0.001)

    def receive_packets(self, addresses=None, timeout=0.5):
        return list(self.receive_packet(addresses, timeout))

    def receive_message(self, addresses=None, names=None, timeout=0.5):
        """
        Returns the first matching (candidate, message) tuple from incoming UDP packets.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.

        NAMES must be None or a list of message names.  When it is a list of names, only messages
        with this name will be returned.

        Will raise a socket exception when no matching packets are available.
        """
        assert names is None or isinstance(names, list), type(names)
        assert names is None or all(isinstance(name, unicode) for name in names), [type(name) for name in names]

        for candidate, packet in self.receive_packet(addresses, timeout):
            try:
                message = self.decode_message(candidate, packet)
            except ConversionNotFoundException as exception:
                self._logger.exception("Ignored %s", exception)
                continue

            if not (names is None or message.name in names):
                self._logger.debug("Ignored %s (%d bytes) from %s", message.name, len(packet), candidate)
                continue

            self._logger.debug("%s (%d bytes) from %s", message.name, len(packet), candidate)
            yield candidate, message

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def receive_messages(self, addresses=None, names=None, return_after=sys.maxint, timeout=0.5):
        messages = []
        for _ in xrange(5):
            for message_tuple in self.receive_message(addresses, names, timeout):
                messages.append(message_tuple)
                if len(messages) == return_after:
                    break
            if messages:
                break
            else:
                # Wait for a bit and try again
                yield deferLater(reactor, 0.005, lambda : None)

        returnValue(messages)

    @blocking_call_on_reactor_thread
    def decode_message(self, candidate, packet):
        return self._community.get_conversion_for_packet(packet).decode_message(candidate, packet)

    @blocking_call_on_reactor_thread
    def fetch_packets(self, message_names, mid=None):
        if mid:
            return [str(packet) for packet, in list(self._dispersy.database.execute(u"SELECT packet FROM sync, member WHERE sync.member = member.id "
                                                                                    u"AND mid = ? AND meta_message IN (" + ", ".join("?" * len(message_names)) + ") ORDER BY global_time, packet",
                                                                                [buffer(mid), ] + [self._community.get_meta_message(name).database_id for name in message_names]))]
        return [str(packet) for packet, in list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message IN (" + ", ".join("?" * len(message_names)) + ") ORDER BY global_time, packet",
                                                                                [self._community.get_meta_message(name).database_id for name in message_names]))]

    @blocking_call_on_reactor_thread
    def fetch_messages(self, message_names, mid=None):
        """
        Fetch all packets for MESSAGE_NAMES from the database and converts them into
        Message.Implementation instances.
        """
        return self._dispersy.convert_packets_to_messages(self.fetch_packets(message_names, mid), community=self._community, verify=False)

    @blocking_call_on_reactor_thread
    def count_messages(self, message):
        packets_stored, = self._dispersy.database.execute(u"SELECT count(*) FROM sync, member, meta_message WHERE sync.member = member.id AND sync.meta_message = meta_message.id AND sync.community = ? AND mid = ? AND name = ?", (self._community.database_id, buffer(message.authentication.member.mid), message.name)).next()
        return packets_stored

    @blocking_call_on_reactor_thread
    def assert_is_stored(self, message=None, messages=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                undone, packet = self._dispersy.database.execute(u"SELECT undone, packet FROM sync, member WHERE sync.member = member.id AND community = ? AND mid = ? AND global_time = ?",
                                                         (self._community.database_id, buffer(message.authentication.member.mid), message.distribution.global_time)).next()
                self._testclass.assertEqual(undone, 0, "Message is undone")
                self._testclass.assertEqual(str(packet), message.packet)

            except StopIteration:
                self._testclass.fail("Message is not stored")

    @blocking_call_on_reactor_thread
    def assert_not_stored(self, message=None, messages=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                packet, = self._dispersy.database.execute(u"SELECT packet FROM sync, member WHERE sync.member = member.id AND community = ? AND mid = ? AND global_time = ?",
                                                         (self._community.database_id, buffer(message.authentication.member.mid), message.distribution.global_time)).next()

                self._testclass.assertNotEqual(str(packet), message.packet)
            except StopIteration:
                pass

    assert_is_done = assert_is_stored

    @blocking_call_on_reactor_thread
    def assert_is_undone(self, message=None, messages=None, undone_by=None):
        if messages == None:
            messages = [message]

        for message in messages:
            try:
                undone, = self._dispersy.database.execute(u"SELECT undone FROM sync, member WHERE sync.member = member.id AND community = ? AND mid = ? AND global_time = ?",
                                                         (self._community.database_id, buffer(message.authentication.member.mid), message.distribution.global_time)).next()
                self._testclass.assertGreater(undone, 0, "Message is not undone")
                if undone_by:
                    undone, = self._dispersy.database.execute(
                        u"SELECT packet FROM sync WHERE id = ? ",
                        (undone,)).next()
                    self._testclass.assertEqual(str(undone), undone_by.packet)

            except StopIteration:
                self._testclass.fail("Message is not stored")

    @blocking_call_on_reactor_thread
    def assert_count(self, message, count):
        self._testclass.assertEqual(self.count_messages(message), count)

    def send_identity(self, other):
        packets = self.fetch_packets([u"dispersy-identity", ], self.my_member.mid)
        other.give_packets(packets, self)

        packets = other.fetch_packets([u"dispersy-identity", ], other.my_member.mid)
        self.give_packets(packets, other)

    @blocking_call_on_reactor_thread
    def take_step(self):
        self._community.take_step()

    @blocking_call_on_reactor_thread
    def claim_global_time(self):
        return self._community.claim_global_time()

    @blocking_call_on_reactor_thread
    def get_resolution_policy(self, meta, global_time):
        return self._community.timeline.get_resolution_policy(meta, global_time)

    def call(self, func, *args, **kargs):
        # TODO(emilon): timeout is not supported anymore, clean the tests so they don't pass the named argument.
        if isInIOThread():
            return func(*args, **kargs)
        else:
            return blockingCallFromThread(reactor, func, *args, **kargs)

    @blocking_call_on_reactor_thread
    def store(self, messages):
        self._dispersy._store(messages)

    @blocking_call_on_reactor_thread
    def create_authorize(self, permission_triplets, global_time=None, sequence_number=None):
        """
        Returns a new dispersy-authorize message.
        """
        meta = self._community.get_meta_message(u"dispersy-authorize")

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(permission_triplets,))

    @blocking_call_on_reactor_thread
    def create_revoke(self, permission_triplets, global_time=None, sequence_number=None):
        meta = self._community.get_meta_message(u"dispersy-revoke")

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(permission_triplets,))

    @blocking_call_on_reactor_thread
    def create_dynamic_settings(self, policies, global_time=None, sequence_number=None):
        meta = self._community.get_meta_message(u"dispersy-dynamic-settings")

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        message = meta.impl(authentication=(self.my_member,),
                            distribution=(global_time, sequence_number),
                            payload=(policies,))
        return message

    @blocking_call_on_reactor_thread
    def create_destroy_community(self, degree, global_time=None):
        meta = self._community.get_meta_message(u"dispersy-destroy-community")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=((self._my_member),),
                            distribution=(global_time,),
                            payload=(degree,))

    @blocking_call_on_reactor_thread
    def create_identity(self, global_time=None):
        """
        Returns a new dispersy-identity message.
        """
        meta = self._community.get_meta_message(u"dispersy-identity")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=(self._my_member,), distribution=(global_time,))

    @blocking_call_on_reactor_thread
    def create_undo_own(self, message, global_time=None, sequence_number=None):
        """
        Returns a new dispersy-undo-own message.
        """
        assert message.authentication.member == self._my_member, "use create_dispersy_undo_other"
        meta = self._community.get_meta_message(u"dispersy-undo-own")

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(message.authentication.member, message.distribution.global_time, message))

    @blocking_call_on_reactor_thread
    def create_undo_other(self, message, global_time=None, sequence_number=None):
        """
        Returns a new dispersy-undo-other message.
        """
        meta = self._community.get_meta_message(u"dispersy-undo-other")

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(message.authentication.member, message.distribution.global_time, message))

    @blocking_call_on_reactor_thread
    def create_missing_identity(self, dummy_member=None, global_time=None):
        """
        Returns a new dispersy-missing-identity message.
        """
        assert isinstance(dummy_member, Member), type(dummy_member)
        meta = self._community.get_meta_message(u"dispersy-missing-identity")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,),
                         payload=(dummy_member.mid,))

    @blocking_call_on_reactor_thread
    def create_missing_sequence(self, missing_member, missing_message, missing_sequence_low, missing_sequence_high, global_time=None):
        """
        Returns a new dispersy-missing-sequence message.
        """
        assert isinstance(missing_member, Member)
        assert isinstance(missing_message, Message)
        assert isinstance(missing_sequence_low, (int, long))
        assert isinstance(missing_sequence_high, (int, long))
        meta = self._community.get_meta_message(u"dispersy-missing-sequence")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,),
                         payload=(missing_member, missing_message, missing_sequence_low, missing_sequence_high))

    @blocking_call_on_reactor_thread
    def create_signature_request(self, identifier, message, global_time=None):
        """
        Returns a new dispersy-signature-request message.
        """
        assert isinstance(message, Message.Implementation)
        meta = self._community.get_meta_message(u"dispersy-signature-request")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,), payload=(identifier, message,))

    @blocking_call_on_reactor_thread
    def create_signature_response(self, identifier, message, global_time=None):
        """
        Returns a new dispersy-missing-response message.
        """
        isinstance(identifier, (int, long))
        isinstance(message, Message.Implementation)

        meta = self._community.get_meta_message(u"dispersy-signature-response")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,),
                         payload=(identifier, message))

    @blocking_call_on_reactor_thread
    def create_missing_message(self, missing_member, missing_global_times, global_time=None):
        """
        Returns a new dispersy-missing-message message.
        """
        assert isinstance(missing_member, Member)
        assert isinstance(missing_global_times, list)
        meta = self._community.get_meta_message(u"dispersy-missing-message")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,),
                         payload=(missing_member, missing_global_times))

    @blocking_call_on_reactor_thread
    def create_missing_proof(self, member, global_time=None):
        """
        Returns a new dispersy-missing-proof message.
        """
        assert isinstance(member, Member)
        meta = self._community.get_meta_message(u"dispersy-missing-proof")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(distribution=(global_time,), payload=(member, global_time))

    @blocking_call_on_reactor_thread
    def create_introduction_request(self, destination, source_lan, source_wan, advice, connection_type, sync, identifier, global_time=None):
        """
        Returns a new dispersy-introduction-request message.
        """
        assert isinstance(destination, Candidate), type(destination)
        assert isinstance(source_lan, tuple), type(source_lan)
        assert isinstance(source_wan, tuple), type(source_wan)
        assert isinstance(advice, bool), type(advice)
        assert isinstance(connection_type, unicode), type(connection_type)
        if sync:
            assert isinstance(sync, tuple)
            assert len(sync) == 5
            time_low, time_high, modulo, offset, bloom_packets = sync
            assert isinstance(time_low, (int, long))
            assert isinstance(time_high, (int, long))
            assert isinstance(modulo, int)
            assert isinstance(offset, int)
            assert isinstance(bloom_packets, list)
            assert all(isinstance(packet, str) for packet in bloom_packets)
            bloom_filter = BloomFilter(512 * 8, 0.001, prefix="x")
            for packet in bloom_packets:
                bloom_filter.add(packet)
            sync = (time_low, time_high, modulo, offset, bloom_filter)
        assert isinstance(identifier, int), type(identifier)

        meta = self._community.get_meta_message(u"dispersy-introduction-request")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time,),
                         payload=(destination.sock_addr, source_lan, source_wan, advice, connection_type, sync, identifier))

    @blocking_call_on_reactor_thread
    def create_introduction_response(self, destination, source_lan, source_wan, introduction_lan, introduction_wan, connection_type, tunnel, identifier, global_time=None):
        """
        Returns a new dispersy-introduction-request message.
        """
        assert isinstance(destination, Candidate), type(destination)
        assert isinstance(source_lan, tuple), type(source_lan)
        assert isinstance(source_wan, tuple), type(source_wan)
        assert isinstance(introduction_lan, tuple), type(introduction_lan)
        assert isinstance(introduction_wan, tuple), type(introduction_wan)
        assert isinstance(connection_type, unicode), type(connection_type)
        assert isinstance(tunnel, bool), type(tunnel)
        assert isinstance(identifier, int), type(identifier)

        meta = self._community.get_meta_message(u"dispersy-introduction-response")

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=(self._my_member,),
                         destination=(destination,),
                         distribution=(global_time,),
                         payload=(destination.sock_addr, source_lan, source_wan, introduction_lan, introduction_wan, connection_type, tunnel, identifier))

    @blocking_call_on_reactor_thread
    def _create_text(self, message_name, text, global_time=None, resolution=(), destination=()):
        assert isinstance(message_name, unicode), type(message_name)
        assert isinstance(text, str), type(text)
        assert isinstance(resolution, tuple), type(resolution)
        assert isinstance(destination, tuple), destination

        meta = self._community.get_meta_message(message_name)

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=(self._my_member,),
                         resolution=resolution,
                         distribution=(global_time,),
                         destination=destination,
                         payload=(text,))

    @blocking_call_on_reactor_thread
    def _create_sequence_text(self, message_name, text, global_time=None, sequence_number=None):
        assert isinstance(message_name, unicode)
        assert isinstance(text, str)

        meta = self._community.get_meta_message(message_name)

        if global_time == None:
            global_time = self.claim_global_time()
        if sequence_number == None:
            sequence_number = meta.distribution.claim_sequence_number()

        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(text,))

    @blocking_call_on_reactor_thread
    def _create_doublemember_text(self, message_name, other, text, global_time=None):
        assert isinstance(message_name, unicode)
        assert isinstance(other, Member)
        assert isinstance(text, str)

        # As each node has a separate database, a member instance from a node representing identity A can have the same
        # database ID than one from a different node representing identity B, get our own member object based on
        # `other`'s member ID to avoid this.
        my_other = self._dispersy.get_member(mid=other.mid)

        meta = self._community.get_meta_message(message_name)

        if global_time == None:
            global_time = self.claim_global_time()

        return meta.impl(authentication=([self._my_member, my_other],),
                         distribution=(global_time,),
                         payload=(text,))

    def create_last_1_test(self, text, global_time=None):
        """
        Returns a new last-1-test message.
        """
        return self._create_text(u"last-1-test", text, global_time)

    def create_last_9_test(self, text, global_time=None):
        """
        Returns a new last-9-test message.
        """
        return self._create_text(u"last-9-test", text, global_time)

    def create_last_1_doublemember_text(self, other, text, global_time=None):
        """
        Returns a new last-1-doublemember-text message.
        """
        return self._create_doublemember_text(u"last-1-doublemember-text", other, text, global_time)

    def create_double_signed_text(self, other, text, global_time=None):
        """
        Returns a new double-signed-text message.
        """
        return self._create_doublemember_text(u"double-signed-text", other, text, global_time)

    def create_double_signed_split_payload_text(self, other, text, global_time=None):
        """
        Returns a new double-signed-text-split message.
        """
        return self._create_doublemember_text(u"double-signed-text-split", other, text, global_time)

    def create_full_sync_text(self, text, global_time=None):
        """
        Returns a new full-sync-text message.
        """
        return self._create_text(u"full-sync-text", text, global_time)

    def create_bin_key_text(self, text, global_time=None):
        """
        Returns a new full-sync-text message.
        """
        return self._create_text(u"bin-key-text", text, global_time)

    def create_targeted_full_sync_text(self, text, destination, global_time=None):
        """
        Returns a new targeted-full-sync-text message.
        """
        return self._create_text(u"full-sync-text", text, destination=destination, global_time=global_time)

    def create_full_sync_global_time_pruning_text(self, text, global_time=None):
        """
        Returns a new full-sync-global-time-pruning-text message.
        """
        return self._create_text(u"full-sync-global-time-pruning-text", text, global_time)

    def create_in_order_text(self, text, global_time=None):
        """
        Returns a new ASC-text message.
        """
        return self._create_text(u"ASC-text", text, global_time)

    def create_out_order_text(self, text, global_time=None):
        """
        Returns a new DESC-text message.
        """
        return self._create_text(u"DESC-text", text, global_time)

    def create_protected_full_sync_text(self, text, global_time=None):
        """
        Returns a new protected-full-sync-text message.
        """
        return self._create_text(u"protected-full-sync-text", text, global_time)

    def create_dynamic_resolution_text(self, text, policy, global_time=None):
        """
        Returns a new dynamic-resolution-text message.
        """
        assert isinstance(policy, (PublicResolution.Implementation, LinearResolution.Implementation)), type(policy)
        return self._create_text(u"dynamic-resolution-text", text, global_time, resolution=(policy,))

    def create_sequence_text(self, text, global_time=None, sequence_number=None):
        """
        Returns a new sequence-text message.
        """
        return self._create_sequence_text(u"sequence-text", text, global_time, sequence_number)

    def create_high_priority_text(self, text, global_time=None):
        """
        Returns a new high-priority-text message.
        """
        return self._create_text(u"high-priority-text", text, global_time)

    def create_low_priority_text(self, text, global_time=None):
        """
        Returns a new low-priority-text message.
        """
        return self._create_text(u"low-priority-text", text, global_time)

    def create_medium_priority_text(self, text, global_time=None):
        """
        Returns a new medium-priority-text message.
        """
        return self._create_text(u"medium-priority-text", text, global_time)

    def create_random_order_text(self, text, global_time=None):
        """
        Returns a new RANDOM-text message.
        """
        return self._create_text(u"RANDOM-text", text, global_time)

    def create_batched_text(self, text, global_time=None):
        """
        Returns a new BATCHED-text message.
        """
        return self._create_text(u"batched-text", text, global_time)
