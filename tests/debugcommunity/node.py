import socket
from time import time, sleep

from ...bloomfilter import BloomFilter
from ...candidate import Candidate, WalkCandidate
from ...community import Community
from ...crypto import ec_generate_key, ec_to_public_bin, ec_to_private_bin
from ...logger import get_logger
from ...member import Member
from ...message import Message
from ...resolution import PublicResolution, LinearResolution
logger = get_logger(__name__)


class DebugNode(object):

    """
    DebugNode is used to represent an external node/peer while performing unittests.

    One or more debug nodes are generally made, for each unittest, as follows:

       # create external node
       node = DebugNode(community)
       node.init_socket()
       node.init_my_member()
    """

    _socket_range = (8000, 8999)
    _socket_pool = {}
    _socket_counter = 0

    def __init__(self, community):
        assert community is None or isinstance(community, Community), type(community)
        super(DebugNode, self).__init__()
        self._community = community
        self._dispersy = community.dispersy if community else None
        self._socket = None
        self._tunnel = False
        self._connection_type = u"unknown"
        self._my_member = None

    @property
    def community(self):
        """
        The community for this node.

        Returns None unless self.set_community() has been called.
        """
        return self._community

    @property
    def socket(self):
        """
        The python socket.socket instance for this node.

        Will fail unless self.init_socket() has been called.
        """
        return self._socket

    @property
    def tunnel(self):
        """
        True when this node is behind a tunnel.

        Will fail unless self.init_socket() has been called.
        """
        return self._tunnel

    @property
    def lan_address(self):
        """
        The LAN address for this node.

        Will fail unless self.init_socket() has been called.
        """
        _, port = self._socket.getsockname()
        return ("127.0.0.1", port)

    @property
    def wan_address(self):
        """
        The WAN address for this node.

        Will fail unless self.init_socket() has been called.
        """
        if self._community.dispersy:
            host = self._community.dispersy.wan_address[0]

            if host == "0.0.0.0":
                host = self._community.dispersy.lan_address[0]

        else:
            host = "0.0.0.0"

        _, port = self._socket.getsockname()
        return (host, port)

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

        Returns None unless self.init_my_member() has been called.
        """
        return self._my_member

    @property
    def candidate(self):
        """
        A Candidate instance for this node.

        Will fail unless self.init_socket() has been called.
        """
        return Candidate(self.lan_address, self.tunnel)

    @property
    def walk_candidate(self):
        """
        A WalkCandidate instance for this node.

        Will fail unless self.init_socket() has been called.
        """
        return WalkCandidate(self.lan_address, self.tunnel, self.lan_address, self.wan_address, self.connection_type)

    def set_community(self, community):
        """
        Set the community that this node is associated to.
        """
        assert community is None or isinstance(community, Community), type(community)
        self._community = community
        if community:
            self._dispersy = community.dispersy

    def init_socket(self, tunnel=False, connection_type=u"unknown"):
        """
        Create a socket.socket instance for this node.

        The port will be chosen from self._socket_range.  When there are too many DebugNodes the
        socket.socket instances will be reused.  Hence it is possible to emulate many external
        nodes.
        """
        assert isinstance(tunnel, bool), type(tunnel)
        assert isinstance(connection_type, unicode), type(connection_type)
        assert self._socket is None
        port = self._socket_range[0] + self._socket_counter % (self._socket_range[1] - self._socket_range[0])
        type(self)._socket_counter += 1

        if port in self._socket_pool:
            logger.warning("reuse socket %d", port)

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
            s.setblocking(False)
            s.settimeout(0.0)
            while True:
                try:
                    s.bind(("localhost", port))
                except socket.error:
                    port = self._socket_range[0] + self._socket_counter % (self._socket_range[1] - self._socket_range[0])
                    type(self)._socket_counter += 1
                    continue
                break

            self._socket_pool[port] = s
            logger.debug("create socket %d", port)

        self._socket = self._socket_pool[port]
        self._tunnel = tunnel
        self._connection_type = connection_type

        return self

    def init_my_member(self, bits=None, sync_with_database=None, candidate=True, identity=True):
        """
        Create a Member instance for this node.

        The member will be created without being stored in the Dispersy member cache.  Hence, when
        this member communicates with the associated community the community will create yet another
        Member instance.  However, these two Member instances will share the same database
        identifier!

        BITS is deprecated and should no longer be used.
        SYNC_WITH_DATABASE is deprecated and should no longer be used.

        When IDENTITY is True the community will immediately be given a dispersy-identity message
        for this node.  The identity message will be given global-time 2, and will be encoded using
        the associated community.

        When CANDIDATE is True the community will immediately be told that this node exist using a
        dispersy-introduction-request message.
        """
        assert bits is None, "The parameter bits is deprecated and must be None"
        assert sync_with_database is None, "The parameter sync_with_database is deprecated and must be None"
        assert isinstance(candidate, bool), type(candidate)
        assert isinstance(identity, bool), type(identity)

        ec = ec_generate_key(u"low")
        self._my_member = Member(self._dispersy, ec_to_public_bin(ec), ec_to_private_bin(ec))

        # remove the private key from the database to ensure DebugCommunity has no access to it
        self._dispersy.database.execute(u"DELETE FROM private_key WHERE member = ?", (self._my_member.database_id,))
        assert self._dispersy.database.changes == 1

        if identity:
            # update identity information
            assert self._socket, "Socket needs to be set to candidate"
            assert self._community, "Community needs to be set to candidate"
            message = self.create_dispersy_identity(2)
            self.give_message(message)

        if candidate:
            # update candidate information
            assert self._socket, "Socket needs to be set to candidate"
            assert self._community, "Community needs to be set to candidate"
            message = self.create_dispersy_introduction_request(self._community.my_candidate, self.lan_address, self.wan_address, False, u"unknown", None, 1, 1)
            self.give_message(message)
            sleep(0.1)
            self.receive_message(message_names=[u"dispersy-introduction-response"])

        return self

    def encode_message(self, message):
        """
        Returns the raw packet after MESSAGE is encoded using the associated community.
        """
        assert isinstance(message, Message.Implementation)
        tmp_member = self._community._my_member
        self._community._my_member = self._my_member
        try:
            return self._community.get_conversion_for_message(message).encode_message(message)
        finally:
            self._community._my_member = tmp_member

    def give_packet(self, packet, verbose=False, cache=False, tunnel=None, source_sock_addr=None):
        """
        Give PACKET directly to Dispersy on_incoming_packets.
        Returns PACKET
        """
        assert isinstance(packet, str)
        assert isinstance(verbose, bool)
        assert isinstance(cache, bool)
        assert tunnel is None, "TUNNEL property is set using init_socket(...)"
        assert source_sock_addr is None or isinstance(source_sock_addr, tuple), type(source_sock_addr)
        if verbose:
            logger.debug("giving %d bytes", len(packet))
        if source_sock_addr is None:
            source_sock_addr = self.lan_address
        candidate = Candidate(source_sock_addr, self._tunnel)
        self._dispersy.on_incoming_packets([(candidate, packet)], cache=cache, timestamp=time())
        return packet

    def give_packets(self, packets, verbose=False, cache=False, tunnel=None, source_sock_addr=None):
        """
        Give multiple PACKETS directly to Dispersy on_incoming_packets.
        Returns PACKETS
        """
        assert isinstance(packets, list)
        assert all(isinstance(packet, str) for packet in packets)
        assert isinstance(verbose, bool)
        assert isinstance(cache, bool)
        assert tunnel is None, "TUNNEL property is set using init_socket(...)"
        assert source_sock_addr is None or isinstance(source_sock_addr, tuple), type(source_sock_addr)
        if verbose:
            logger.debug("giving %d bytes", sum(len(packet) for packet in packets))
        if source_sock_addr is None:
            source_sock_addr = self.lan_address
        candidate = Candidate(source_sock_addr, self._tunnel)
        self._dispersy.on_incoming_packets([(candidate, packet) for packet in packets], cache=cache, timestamp=time())
        return packets

    def give_message(self, message, verbose=False, cache=False, tunnel=None, source_sock_addr=None):
        """
        Give MESSAGE directly to Dispersy on_incoming_packets after it is encoded.
        Returns MESSAGE
        """
        assert isinstance(message, Message.Implementation)
        assert isinstance(verbose, bool)
        assert isinstance(cache, bool)
        assert tunnel is None, "TUNNEL property is set using init_socket(...)"
        assert source_sock_addr is None or isinstance(source_sock_addr, tuple), type(source_sock_addr)
        packet = message.packet if message.packet else self.encode_message(message)
        if verbose:
            logger.debug("giving %s (%d bytes)", message.name, len(packet))
        self.give_packet(packet, verbose=verbose, cache=cache, tunnel=tunnel, source_sock_addr=source_sock_addr)
        return message

    def give_messages(self, messages, verbose=False, cache=False, tunnel=None, source_sock_addr=None):
        """
        Give multiple MESSAGES directly to Dispersy on_incoming_packets after they are encoded.
        Returns MESSAGES
        """
        assert isinstance(messages, list)
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert isinstance(verbose, bool)
        assert isinstance(cache, bool)
        assert tunnel is None, "TUNNEL property is set using init_socket(...)"
        assert source_sock_addr is None or isinstance(source_sock_addr, tuple), type(source_sock_addr)
        packets = [message.packet if message.packet else self.encode_message(message) for message in messages]
        if verbose:
            logger.debug("giving %d messages (%d bytes)", len(messages), sum(len(packet) for packet in packets))
        self.give_packets(packets, verbose=verbose, cache=cache, tunnel=tunnel, source_sock_addr=source_sock_addr)
        return messages

    def send_packet(self, packet, address, verbose=False):
        """
        Sends PACKET to ADDRESS using the nodes' socket.
        Returns PACKET
        """
        assert isinstance(packet, str)
        assert isinstance(address, tuple)
        assert isinstance(verbose, bool)
        if verbose:
            logger.debug("%d bytes to %s:%d", len(packet), address[0], address[1])
        self._socket.sendto(packet, address)
        return packet

    def send_message(self, message, address, verbose=False):
        """
        Sends MESSAGE to ADDRESS using the nodes' socket after it is encoded.
        Returns MESSAGE
        """
        assert isinstance(message, Message.Implementation)
        assert isinstance(address, tuple)
        assert isinstance(verbose, bool)
        self.encode_message(message)
        if verbose:
            logger.debug("%s (%d bytes) to %s:%d", message.name, len(message.packet), address[0], address[1])
        self.send_packet(message.packet, address)
        return message

    def drop_packets(self, verbose=False):
        """
        Discard all packets on the nodes' socket.
        """
        while True:
            try:
                packet, address = self._socket.recvfrom(10240)
            except:
                break

            if verbose:
                logger.debug("dropped %d bytes from %s:%d", len(packet), address[0], address[1])

    def receive_packet(self, timeout=None, addresses=None, packets=None):
        """
        Returns the first matching (candidate, packet) tuple from incoming UDP packets.

        TIMEOUT is deprecated and should no longer be used.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.

        PACKETS must be None or a list of packets.  When it is a list of packets, only those PACKETS
        will be returned.

        Will raise a socket exception when no matching packets are available.
        """
        assert timeout is None, "The parameter TIMEOUT is deprecated and must be None"
        assert addresses is None or isinstance(addresses, list)
        assert addresses is None or all(isinstance(address, tuple) for address in addresses)
        assert packets is None or isinstance(packets, list)
        assert packets is None or all(isinstance(packet, str) for packet in packets)

        while True:
            try:
                packet, address = self._socket.recvfrom(10240)
            except:
                logger.debug("No more packets on %s", self.wan_address)
                raise

            if not (addresses is None or address in addresses or (address[0] == "127.0.0.1" and ("0.0.0.0", address[1]) in addresses)):
                logger.debug("Ignored %d bytes from %s:%d", len(packet), address[0], address[1])
                continue

            if not (packets is None or packet in packets):
                logger.debug("Ignored %d bytes from %s:%d", len(packet), address[0], address[1])
                continue

            if packet.startswith("ffffffff".decode("HEX")):
                tunnel = True
                packet = packet[4:]
            else:
                tunnel = False

            candidate = Candidate(address, tunnel)
            logger.debug("%d bytes from %s", len(packet), candidate)
            return candidate, packet

    def receive_packets(self, timeout=None, addresses=None, packets=None):
        """
        Returns a list with (candidate, packet) tuples from all matching incoming UDP packets.

        TIMEOUT is deprecated and should no longer be used.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.

        PACKETS must be None or a list of packets.  When it is a list of packets, only those PACKETS
        will be returned.
        """
        packets_ = []
        while True:
            try:
                packets_.append(self.receive_packet(timeout, addresses, packets))
            except socket.error:
                break
        return packets_

    def receive_message(self, timeout=None, addresses=None, packets=None, message_names=None, payload_types=None, distributions=None, destinations=None, names=None):
        """
        Returns the first matching (candidate, message) tuple from incoming UDP packets.

        TIMEOUT is deprecated and should no longer be used.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.

        PACKETS must be None or a list of packets.  When it is a list of packets, only those PACKETS
        will be returned.

        NAMES must be None or a list of message names.  When it is a list of names, only messages
        with this name will be returned.

        PAYLOAD_TYPES is deprecated and should no longer be used.
        DISTRIBUTIONS is deprecated and should no longer be used.
        DESTINATIONS is deprecated and should no longer be used.
        MESSAGE_NAMES is deprecated use NAMES instead.

        Will raise a socket exception when no matching packets are available.
        """
        if names is None:
            # TODO remove this backwards compatibility with the MESSAGE_NAMES parameter
            names = message_names
            message_names = None

        assert timeout is None, "The parameter TIMEOUT is deprecated and must be None"
        assert names is None or isinstance(names, list), type(names)
        assert names is None or all(isinstance(name, unicode) for name in names), [type(name) for name in names]
        assert payload_types is None, "The parameter PAYLOAD_TYPES is deprecated and must be None"
        assert distributions is None, "The parameter DISTRIBUTIONS is deprecated and must be None"
        assert destinations is None, "The parameter DESTINATIONS is deprecated and must be None"
        assert message_names is None, "The parameter MESSAGE_NAMES is deprecated use NAMES instead"

        while True:
            candidate, packet = self.receive_packet(timeout, addresses, packets)

            try:
                message = self._community.get_conversion_for_packet(packet).decode_message(candidate, packet)
            except KeyError as exception:
                logger.exception("Ignored %s", exception)
                continue

            if not (names is None or message.name in names):
                logger.debug("Ignored %s (%d bytes) from %s", message.name, len(packet), candidate)
                continue

            logger.debug("%s (%d bytes) from %s", message.name, len(packet), candidate)
            return candidate, message

    def receive_messages(self, timeout=None, addresses=None, packets=None, message_names=None, payload_types=None, distributions=None, destinations=None, names=None, counts=None):
        """
        Returns a list with (candidate, message) tuples from all matching incoming UDP packets.

        TIMEOUT is deprecated and should no longer be used.

        ADDRESSES must be None or a list of address tuples.  When it is a list of addresses, only
        UDP packets from ADDRESSES will be returned.

        PACKETS must be None or a list of packets.  When it is a list of packets, only those PACKETS
        will be returned.

        NAMES must be None or a list of message names.  When it is a list of names, only messages
        with this name will be returned.

        COUNTS must be None or a list of acceptable message counts.  When it is a list of counts an
        assert is raised when the number of acceptable messages is different than one of the
        acceptable message counts.

        PAYLOAD_TYPES is deprecated and should no longer be used.
        DISTRIBUTIONS is deprecated and should no longer be used.
        DESTINATIONS is deprecated and should no longer be used.
        MESSAGE_NAMES is deprecated use NAMES instead.
        """
        assert counts is None or isinstance(counts, list), type(counts)
        assert counts is None or all(isinstance(count, int) for count in counts), [type(count) for count in counts]

        messages = []
        while True:
            try:
                messages.append(self.receive_message(timeout, addresses, packets, message_names, payload_types, distributions, destinations, names))
            except socket.error:
                break

        if counts and not len(messages) in counts:
            raise AssertionError("Received %d messages while expecting %s messages" % (len(messages), counts))
        return messages

    def create_dispersy_authorize(self, permission_triplets, sequence_number, global_time):
        """
        Returns a new dispersy-authorize message.
        """
        meta = self._community.get_meta_message(u"dispersy-authorize")
        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(permission_triplets,))

    def create_dispersy_identity(self, global_time):
        """
        Returns a new dispersy-identity message.
        """
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-identity")
        return meta.impl(authentication=(self._my_member,), distribution=(global_time,))

    def create_dispersy_undo_own(self, message, global_time, sequence_number):
        """
        Returns a new dispersy-undo-own message.
        """
        assert message.authentication.member == self._my_member, "use create_dispersy_undo_other"
        meta = self._community.get_meta_message(u"dispersy-undo-own")
        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(message.authentication.member, message.distribution.global_time, message))

    def create_dispersy_undo_other(self, message, global_time, sequence_number):
        """
        Returns a new dispersy-undo-other message.
        """
        assert message.authentication.member != self._my_member, "use create_dispersy_undo_own"
        meta = self._community.get_meta_message(u"dispersy-undo-other")
        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(message.authentication.member, message.distribution.global_time, message))

    def create_dispersy_missing_identity(self, dummy_member, global_time, destination_candidate):
        """
        Returns a new dispersy-missing-identity message.
        """
        assert isinstance(dummy_member, Member), type(dummy_member)
        assert isinstance(global_time, (int, long)), type(global_time)
        assert isinstance(destination_candidate, Candidate), type(destination_candidate)
        meta = self._community.get_meta_message(u"dispersy-missing-identity")
        return meta.impl(distribution=(global_time,),
                         destination=(destination_candidate,),
                         payload=(dummy_member.mid,))

    def create_dispersy_missing_sequence(self, missing_member, missing_message, missing_sequence_low, missing_sequence_high, global_time, destination_candidate):
        """
        Returns a new dispersy-missing-sequence message.
        """
        assert isinstance(missing_member, Member)
        assert isinstance(missing_message, Message)
        assert isinstance(missing_sequence_low, (int, long))
        assert isinstance(missing_sequence_high, (int, long))
        assert isinstance(global_time, (int, long))
        assert isinstance(destination_candidate, Candidate)
        meta = self._community.get_meta_message(u"dispersy-missing-sequence")
        return meta.impl(distribution=(global_time,),
                         destination=(destination_candidate,),
                         payload=(missing_member, missing_message, missing_sequence_low, missing_sequence_high))

    def create_dispersy_signature_request(self, identifier, message, global_time):
        """
        Returns a new dispersy-signature-request message.
        """
        assert isinstance(message, Message.Implementation)
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-signature-request")
        return meta.impl(distribution=(global_time,), payload=(identifier, message,))

    def create_dispersy_signature_response(self, identifier, message, global_time, destination_candidate):
        """
        Returns a new dispersy-missing-response message.
        """
        isinstance(identifier, (int, long))
        isinstance(message, Message.Implementation)
        assert isinstance(global_time, (int, long))
        assert isinstance(destination_candidate, Candidate)
        meta = self._community.get_meta_message(u"dispersy-signature-response")
        return meta.impl(distribution=(global_time,),
                         destination=(destination_candidate,),
                         payload=(identifier, message))

    def create_dispersy_missing_message(self, missing_member, missing_global_times, global_time, destination_candidate):
        """
        Returns a new dispersy-missing-message message.
        """
        assert isinstance(missing_member, Member)
        assert isinstance(missing_global_times, list)
        assert all(isinstance(global_time, (int, long)) for global_time in missing_global_times)
        assert isinstance(global_time, (int, long))
        assert isinstance(destination_candidate, Candidate)
        meta = self._community.get_meta_message(u"dispersy-missing-message")
        return meta.impl(distribution=(global_time,),
                         destination=(destination_candidate,),
                         payload=(missing_member, missing_global_times))

    def create_dispersy_missing_proof(self, member, global_time):
        """
        Returns a new dispersy-missing-proof message.
        """
        assert isinstance(member, Member)
        assert isinstance(global_time, (int, long))
        assert global_time > 0
        meta = self._community.get_meta_message(u"dispersy-missing-proof")
        return meta.impl(distribution=(global_time,), payload=(member, global_time))

    def create_dispersy_introduction_request(self, destination, source_lan, source_wan, advice, connection_type, sync, identifier, global_time):
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
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-introduction-request")
        return meta.impl(authentication=(self._my_member,),
                         destination=(destination,),
                         distribution=(global_time,),
                         payload=(destination.sock_addr, source_lan, source_wan, advice, connection_type, sync, identifier))

    def create_dispersy_introduction_response(self, destination, source_lan, source_wan, introduction_lan, introduction_wan, connection_type, tunnel, identifier, global_time):
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
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(u"dispersy-introduction-response")
        return meta.impl(authentication=(self._my_member,),
                         destination=(destination,),
                         distribution=(global_time,),
                         payload=(destination.sock_addr, source_lan, source_wan, introduction_lan, introduction_wan, connection_type, tunnel, identifier))

    def _create_text(self, message_name, text, global_time, resolution=(), destination=()):
        assert isinstance(message_name, unicode), type(message_name)
        assert isinstance(text, str), type(text)
        assert isinstance(global_time, (int, long)), type(global_time)
        assert isinstance(resolution, tuple), type(resolution)
        assert isinstance(destination, tuple), type(destination)
        meta = self._community.get_meta_message(message_name)
        return meta.impl(authentication=(self._my_member,),
                         resolution=resolution,
                         distribution=(global_time,),
                         destination=destination,
                         payload=(text,))

    def _create_sequence_text(self, message_name, text, global_time, sequence_number):
        assert isinstance(message_name, unicode)
        assert isinstance(text, str)
        assert isinstance(global_time, (int, long))
        assert isinstance(sequence_number, (int, long))
        meta = self._community.get_meta_message(message_name)
        return meta.impl(authentication=(self._my_member,),
                         distribution=(global_time, sequence_number),
                         payload=(text,))

    def _create_doublemember_text(self, message_name, other, text, global_time, sign):
        assert isinstance(message_name, unicode)
        assert isinstance(other, Member)
        assert not self._my_member == other
        assert isinstance(text, str)
        assert isinstance(global_time, (int, long))
        meta = self._community.get_meta_message(message_name)
        return meta.impl(authentication=([self._my_member, other],),
                         distribution=(global_time,),
                         payload=(text,),
                         sign=sign)

    def create_last_1_test(self, text, global_time):
        """
        Returns a new last-1-test message.
        """
        return self._create_text(u"last-1-test", text, global_time)

    def create_last_9_test(self, text, global_time):
        """
        Returns a new last-9-test message.
        """
        return self._create_text(u"last-9-test", text, global_time)

    def create_last_1_doublemember_text(self, other, text, global_time, sign):
        """
        Returns a new last-1-doublemember-text message.
        """
        return self._create_doublemember_text(u"last-1-doublemember-text", other, text, global_time, sign)

    def create_double_signed_text(self, other, text, global_time, sign):
        """
        Returns a new double-signed-text message.
        """
        return self._create_doublemember_text(u"double-signed-text", other, text, global_time, sign)

    def create_full_sync_text(self, text, global_time):
        """
        Returns a new full-sync-text message.
        """
        return self._create_text(u"full-sync-text", text, global_time)

    def create_full_sync_global_time_pruning_text(self, text, global_time):
        """
        Returns a new full-sync-global-time-pruning-text message.
        """
        return self._create_text(u"full-sync-global-time-pruning-text", text, global_time)

    def create_in_order_text(self, text, global_time):
        """
        Returns a new ASC-text message.
        """
        return self._create_text(u"ASC-text", text, global_time)

    def create_out_order_text(self, text, global_time):
        """
        Returns a new DESC-text message.
        """
        return self._create_text(u"DESC-text", text, global_time)

    def create_protected_full_sync_text(self, text, global_time):
        """
        Returns a new protected-full-sync-text message.
        """
        return self._create_text(u"protected-full-sync-text", text, global_time)

    def create_dynamic_resolution_text(self, text, global_time, policy):
        """
        Returns a new dynamic-resolution-text message.
        """
        assert isinstance(policy, (PublicResolution.Implementation, LinearResolution.Implementation))
        return self._create_text(u"dynamic-resolution-text", text, global_time, resolution=(policy,))

    def create_sequence_text(self, text, global_time, sequence_number):
        """
        Returns a new sequence-text message.
        """
        return self._create_sequence_text(u"sequence-text", text, global_time, sequence_number)

    def create_high_priority_text(self, text, global_time):
        """
        Returns a new high-priority-text message.
        """
        return self._create_text(u"high-priority-text", text, global_time)

    def create_low_priority_text(self, text, global_time):
        """
        Returns a new low-priority-text message.
        """
        return self._create_text(u"low-priority-text", text, global_time)

    def create_medium_priority_text(self, text, global_time):
        """
        Returns a new medium-priority-text message.
        """
        return self._create_text(u"medium-priority-text", text, global_time)

    def create_random_order_text(self, text, global_time):
        """
        Returns a new RANDOM-text message.
        """
        return self._create_text(u"RANDOM-text", text, global_time)
