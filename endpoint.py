import errno
import logging
import socket
import sys
import threading
from abc import ABCMeta, abstractmethod
from itertools import product
from select import select
from time import time

from twisted.internet import reactor

from .candidate import Candidate


if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035  # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK

TUNNEL_PREFIX = "ffffffff".decode("HEX")
TUNNEL_PREFIX_LENGHT = 4


def strip_if_tunnel(datagram):
    """
    Returns is_tunnel, prefix_stripped_datagram
    """
    if datagram.startswith(TUNNEL_PREFIX):
        return True, datagram[TUNNEL_PREFIX_LENGHT:]
    return False, datagram


class Endpoint(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._dispersy = None

    @abstractmethod
    def get_address(self):
        pass

    @abstractmethod
    def send(self, candidates, packets):
        pass

    @abstractmethod
    def send_packet(self, candidate, packet):
        pass

    def open(self, dispersy):
        self._dispersy = dispersy
        return True

    def close(self, timeout=0.0):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(timeout, float), type(timeout)
        return True

    def log_packet(self, sock_addr, packet, outbound=True):
        try:
            community = self._dispersy.get_community(packet[2:22], load=False, auto_load=False)

            # find associated conversion
            conversion = community.get_conversion_for_packet(packet)
            name = conversion.decode_meta_message(packet).name
        except:
            name = "???"
        self._logger.debug("%30s %s %15s:%-5d %4d bytes", name, '->' if outbound else '<-',
                     sock_addr[0], sock_addr[1], len(packet))

        if outbound:
            self._dispersy.statistics.dict_inc(u"endpoint_send", name)
        else:
            self._dispersy.statistics.dict_inc(u"endpoint_recv", name)


class NullEndpoint(Endpoint):

    """
    NullEndpoint will ignore not send or receive anything.

    This Endpoint can be used during unit tests that should not communicate with other peers.
    """

    def __init__(self, address=("0.0.0.0", 42)):
        super(NullEndpoint, self).__init__()
        self._address = address

    def get_address(self):
        return self._address

    def send(self, candidates, packets):
        if any(len(packet) > 2 ** 16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % max(len(packet) for packet in packets))
        self._dispersy.statistics.total_up += sum(len(packet) for packet in packets) * len(candidates)

    def send_packet(self, candidate, packet):
        if len(packet) > 2 ** 16 - 60:
            raise RuntimeError("UDP does not support %d byte packets" % len(packet))
        self._dispersy.statistics.total_up += len(packet)


class RawserverEndpoint(Endpoint):

    def __init__(self, rawserver, port, ip="0.0.0.0"):
        super(RawserverEndpoint, self).__init__()

        self._rawserver = rawserver
        self._port = port
        self._ip = ip
        self._add_task = self._rawserver.add_task
        self._sendqueue_lock = threading.RLock()
        self._sendqueue = []

        # _SOCKET is set during open(...)
        self._socket = None
        self.packet_handlers = {}

    def listen_to(self, prefix, handler):
        self.packet_handlers[prefix] = handler

    def stop_listen_to(self, prefix):
        del self.packet_handlers[prefix]

    def open(self, dispersy):
        super(RawserverEndpoint, self).open(dispersy)

        while True:
            try:
                self._socket = self._rawserver.create_udpsocket(self._port, self._ip)
                self._logger.debug("Listening at %d", self._port)
            except socket.error:
                self._port += 1
                continue
            break
        self._rawserver.start_listening_udp(self._socket, self)
        return True

    def close(self, timeout=0.0):
        self._rawserver.stop_listening_udp(self._socket)
        return super(RawserverEndpoint, self).close(timeout)

    def get_address(self):
        assert self._dispersy, "Should not be called before open(...)"
        return self._socket.getsockname()

    def data_came_in(self, packets, cache=True):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(packets, (list, tuple)), type(packets)
        # called on the Tribler rawserver

        normal_packets = []
        for packet in packets:

            prefix = next((p for p in self.packet_handlers if
                           packet[1].startswith(p)), None)
            if prefix:
                sock_addr, data = packet
                self.packet_handlers[prefix](sock_addr, data[len(prefix):])
            else:
                normal_packets.append(packet)

        # the rawserver SUCKS.  every now and then exceptions are not shown and apparently we are
        # sometimes called without any packets...
        if normal_packets:
            self._dispersy.statistics.total_down += sum(len(data) for _, data in normal_packets)
            if self._logger.isEnabledFor(logging.DEBUG):
                for sock_addr, data in normal_packets:
                    self.log_packet(sock_addr, data, outbound=False)

            # The endpoint runs on it's own thread, so we can't do a callLater here
            reactor.callFromThread(self.dispersythread_data_came_in, normal_packets, time(), cache)

    def dispersythread_data_came_in(self, packets, timestamp, cache=True):
        assert self._dispersy, "Should not be called before open(...)"
        iterator = ((data.startswith(TUNNEL_PREFIX), sock_addr, data) for sock_addr, data in packets)
        self._dispersy.on_incoming_packets([(Candidate(sock_addr, tunnel), data[4:] if tunnel else data)
                                            for tunnel, sock_addr, data
                                            in iterator],
                                           cache,
                                           timestamp,
                                           u"rawserver")

    def send(self, candidates, packets, prefix=None):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates), [type(candidate) for candidate in candidates]
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets), [type(packet) for packet in packets]
        assert all(len(packet) > 0 for packet in packets), [len(packet) for packet in packets]

        prefix = prefix or ''
        packets = [prefix + packet for packet in packets]

        if any(len(packet) > 2 ** 16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % max(len(packet) for packet in packets))

        send_packet = False
        for candidate, packet in product(candidates, packets):
            if self.send_packet(candidate, packet):
                send_packet = True

        return send_packet

    def send_packet(self, candidate, packet, prefix=None):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidate, Candidate), type(candidate)
        assert isinstance(packet, str), type(packet)
        assert len(packet) > 0

        packet = (prefix or '') + packet

        if len(packet) > 2 ** 16 - 60:
            raise RuntimeError("UDP does not support %d byte packets" % len(packet))

        self._dispersy.statistics.total_up += len(packet)
        self._dispersy.statistics.total_send += 1

        data = TUNNEL_PREFIX + packet if candidate.tunnel else packet

        try:
            self._socket.sendto(data, candidate.sock_addr)

            if self._logger.isEnabledFor(logging.DEBUG):
                self.log_packet(candidate.sock_addr, packet)

        except socket.error:
            with self._sendqueue_lock:
                did_have_senqueue = bool(self._sendqueue)
                self._sendqueue.append((candidate.sock_addr, data))

            # If we did not have a sendqueue, then we need to call process_sendqueue in order send these messages
            if not did_have_senqueue:
                self._process_sendqueue()

        return True

    def _process_sendqueue(self):
        assert self._dispersy, "Should not be called before start(...)"
        with self._sendqueue_lock:
            if self._sendqueue:
                index = 0
                NUM_PACKETS = min(max(50, len(self._sendqueue) / 10), len(self._sendqueue))
                self._logger.debug("%d left in sendqueue, trying to send %d packets",
                                   len(self._sendqueue), NUM_PACKETS)

                for i in xrange(NUM_PACKETS):
                    sock_addr, data = self._sendqueue[i]
                    try:
                        self._socket.sendto(data, sock_addr)
                        index += 1

                        if self._logger.isEnabledFor(logging.DEBUG):
                            self.log_packet(sock_addr, data)

                    except socket.error as e:
                        if e[0] != SOCKET_BLOCK_ERRORCODE:
                            self._logger.warning("could not send %d to %s (%d in sendqueue)",
                                                 len(data), sock_addr, len(self._sendqueue))

                        self._dispersy.statistics.dict_inc(u"endpoint_send", u"socket-error")
                        break

                self._sendqueue = self._sendqueue[index:]
                if self._sendqueue:
                    # And schedule a new attempt
                    self._add_task(self._process_sendqueue, 0.1, "process_sendqueue")
                    self._logger.debug("%d left in sendqueue", len(self._sendqueue))

                self._dispersy.statistics.cur_sendqueue = len(self._sendqueue)


class StandaloneEndpoint(RawserverEndpoint):

    def __init__(self, port, ip="0.0.0.0"):
        # do NOT call RawserverEndpoint.__init__!
        Endpoint.__init__(self)

        self._port = port
        self._ip = ip
        self._running = False
        self._add_task = lambda task, delay = 0.0, id = "": None
        self._sendqueue_lock = threading.RLock()
        self._sendqueue = []

        # _THREAD and _THREAD are set during open(...)
        self._thread = None
        self._socket = None
        self.packet_handlers = {}

    def open(self, dispersy):
        # do NOT call RawserverEndpoint.open!
        Endpoint.open(self, dispersy)
        for _ in xrange(10000):
            try:
                self._logger.debug("Listening at %d", self._port)
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
                self._socket.bind((self._ip, self._port))
                self._socket.setblocking(0)

                self._port = self._socket.getsockname()[1]
            except socket.error:
                self._port += 1
                continue
            break

        self._running = True
        self._thread = threading.Thread(name="StandaloneEndpoint", target=self._loop)
        self._thread.daemon = True
        self._thread.start()
        return True

    def close(self, timeout=10.0):
        self._running = False
        result = True

        if timeout > 0.0:
            self._thread.join(timeout)

            if self._thread.is_alive():
                self._logger.error("the endpoint thread is still running (after waiting %f seconds)", timeout)
                result = False

        else:
            if self._thread.is_alive():
                self._logger.debug("the endpoint thread is still running (use timeout > 0.0 to ensure the thread stops)")
                result = False

        try:
            self._socket.close()
        except socket.error as exception:
            self._logger.exception("%s", exception)
            result = False

        # do NOT call RawserverEndpoint.open!
        return Endpoint.close(self, timeout) and result

    def _loop(self):
        assert self._dispersy, "Should not be called before open(...)"
        recvfrom = self._socket.recvfrom
        socket_list = [self._socket.fileno()]

        prev_sendqueue = 0
        while self._running:
            # This is a tricky, if we are running on the DAS4 whenever a socket is ready for writing all processes of
            # this node will try to write. Therefore, we have to limit the frequency of trying to write a bit.
            if self._sendqueue and (time() - prev_sendqueue) > 0.1:
                read_list, write_list, _ = select(socket_list, socket_list, [], 0.1)
            else:
                read_list, write_list, _ = select(socket_list, [], [], 0.1)

            # Furthermore, if we are allowed to send, process sendqueue immediately
            if write_list:
                self._process_sendqueue()
                prev_sendqueue = time()

            if read_list:
                packets = []
                try:
                    while True:
                        (data, sock_addr) = recvfrom(65535)
                        if data:
                            packets.append((sock_addr, data))
                        else:
                            break

                except socket.error as e:
                    self._dispersy.statistics.dict_inc(u"endpoint_recv", u"socket-error-'%s'" % str(e))

                finally:
                    if packets:
                        self._logger.debug('%d came in, %d bytes in total', len(packets), sum(len(packet) for _, packet in packets))
                        self.data_came_in(packets)

class ManualEnpoint(StandaloneEndpoint):

    def __init__(self, *args, **kwargs):
        StandaloneEndpoint.__init__(self, *args, **kwargs)
        self.receive_lock = threading.RLock()
        self.received_packets = []

    def data_came_in(self, packets):
        self._logger.debug('added %d packets to receivequeue, %d packets are queued in total', len(packets), len(packets) + len(self.received_packets))

        with self.receive_lock:
            self.received_packets.extend(packets)

    def clear_receive_queue(self):
        with self.receive_lock:
            packets = self.received_packets
            self.received_packets = []

        if packets:
            self._logger.debug('returning %d packets, %d bytes in total',
                         len(packets), sum(len(packet) for _, packet in packets))
        return packets

    def process_receive_queue(self):
        packets = self.clear_receive_queue()
        self.process_packets(packets)
        return packets

    def process_packets(self, packets, cache=True):
        self._logger.debug('processing %d packets', len(packets))
        StandaloneEndpoint.data_came_in(self, packets, cache=cache)

class TunnelEndpoint(Endpoint):

    def __init__(self, swift_process):
        super(TunnelEndpoint, self).__init__()
        self._swift = swift_process
        self._session = "ffffffff".decode("HEX")

    def listen_to(self, prefix, handler):
        def handler_wrapper(session, sock_addr, data):
            handler(sock_addr, data)
            self._dispersy.statistics.total_down += len(data)

        self._swift.register_tunnel(prefix, handler_wrapper)

    def open(self, dispersy):
        super(TunnelEndpoint, self).open(dispersy)
        self._swift.register_tunnel(self._session, self.i2ithread_data_came_in)
        return True

    def close(self, timeout=0.0):
        self._swift.unregister_tunnel(self._session)
        return super(TunnelEndpoint, self).close(timeout)

    def get_address(self):
        return ("0.0.0.0", self._swift.listenport)

    def send(self, candidates, packets, prefix=None):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates)
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets)
        assert all(len(packet) > 0 for packet in packets)
        if any(len(packet) > 2 ** 16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % max(len(packet) for packet in packets))

        send_packet = False
        for candidate, packet in product(candidates, packets):
            if self.send_packet(candidate, packet, prefix):
                send_packet = True

        return send_packet

    def send_packet(self, candidate, packet, prefix=None):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidate, Candidate), type(candidate)
        assert isinstance(packet, str), type(packet)
        assert len(packet) > 0
        if len(packet) > 2 ** 16 - 60:
            raise RuntimeError("UDP does not support %d byte packets" % len(packet))

        self._dispersy.statistics.total_up += len(packet)
        self._dispersy.statistics.total_send += 1

        with self._swift.splock:
            self._swift.send_tunnel(prefix or self._session, candidate.sock_addr, packet)

        if self._logger.isEnabledFor(logging.DEBUG):
            self.log_packet(candidate.sock_addr, packet)

        return True

    def i2ithread_data_came_in(self, session, sock_addr, data):
        assert self._dispersy, "Should not be called before open(...)"
        if self._logger.isEnabledFor(logging.DEBUG):
            self.log_packet(sock_addr, data, outbound=False)

        self._dispersy.statistics.total_down += len(data)
        # The endpoint runs on it's own thread, so we can't do a callLater here
        reactor.callFromThread(self.dispersythread_data_came_in, sock_addr, data, time())

    def dispersythread_data_came_in(self, sock_addr, data, timestamp):
        assert self._dispersy, "Should not be called before open(...)"
        self._dispersy.on_incoming_packets([(Candidate(sock_addr, True), data)], True, timestamp, u"swift")
