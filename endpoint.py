from abc import ABCMeta, abstractmethod
from itertools import product
from select import select
from time import time
import errno
import logging
import socket
import sys
import threading

from .candidate import Candidate
from .logger import get_logger
logger = get_logger(__name__)

if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035  # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK

TUNNEL_PREFIX = "ffffffff".decode("HEX")


class Endpoint(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        self._dispersy = None
        self._total_up = 0
        self._total_down = 0
        self._total_send = 0
        self._cur_sendqueue = 0

    @property
    def total_up(self):
        return self._total_up

    @property
    def total_down(self):
        return self._total_down

    @property
    def total_send(self):
        return self._total_send

    @property
    def cur_sendqueue(self):
        return self._cur_sendqueue

    def reset_statistics(self):
        self._total_up = 0
        self._total_down = 0
        self._total_send = 0
        self._cur_sendqueue = 0

    @abstractmethod
    def get_address(self):
        pass

    @abstractmethod
    def send(self, candidates, packets):
        pass

    def open(self, dispersy):
        self._dispersy = dispersy
        return True

    def close(self, timeout=0.0):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(timeout, float), type(timeout)
        return True


class NullEndpoint(Endpoint):

    """
    NullEndpoint will ignore not send or receive anything.

    This Endpoint can be used during unit tests that should not communicate with other peers.
    """

    def __init__(self, address=("0.0.0.0", -1)):
        super(NullEndpoint, self).__init__()
        self._address = address

    def get_address(self):
        return self._address

    def send(self, candidates, packets):
        if any(len(packet) > 2**16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % len(max(len(packet) for packet in packets)))
        self._total_up += sum(len(packet) for packet in packets) * len(candidates)


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

    def open(self, dispersy):
        super(RawserverEndpoint, self).open(dispersy)

        while True:
            try:
                self._socket = self._rawserver.create_udpsocket(self._port, self._ip)
                logger.debug("Listening at %d", self._port)
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

    def data_came_in(self, packets):
        assert self._dispersy, "Should not be called before open(...)"
        # called on the Tribler rawserver

        # the rawserver SUCKS.  every now and then exceptions are not shown and apparently we are
        # sometimes called without any packets...
        if packets:
            self._total_down += sum(len(data) for _, data in packets)

            if logger.isEnabledFor(logging.DEBUG):
                for sock_addr, data in packets:
                    try:
                        name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                    except:
                        name = "???"
                    logger.debug("%30s <- %15s:%-5d %4d bytes", name, sock_addr[0], sock_addr[1], len(data))
                    self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, name)

            self._dispersy.callback.register(self.dispersythread_data_came_in, (packets, time()))

    def dispersythread_data_came_in(self, packets, timestamp):
        assert self._dispersy, "Should not be called before open(...)"
        # iterator = ((self._dispersy.get_candidate(sock_addr), data.startswith(TUNNEL_PREFIX), sock_addr, data) for sock_addr, data in packets)
        # self._dispersy.on_incoming_packets([(candidate if candidate else self._dispersy.create_candidate(WalkCandidate, sock_addr, tunnel), data[4:] if tunnel else data)
        #                                     for candidate, tunnel, sock_addr, data
        #                                     in iterator],
        #                                    True,
        #                                    timestamp)
        iterator = ((data.startswith(TUNNEL_PREFIX), sock_addr, data) for sock_addr, data in packets)
        self._dispersy.on_incoming_packets([(Candidate(sock_addr, tunnel), data[4:] if tunnel else data)
                                            for tunnel, sock_addr, data
                                            in iterator],
                                           True,
                                           timestamp)

    def send(self, candidates, packets):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates), [type(candidate) for candidate in candidates]
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets), [type(packet) for packet in packets]
        assert all(len(packet) > 0 for packet in packets), [len(packet) for packet in packets]
        if any(len(packet) > 2**16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % len(max(len(packet) for packet in packets)))

        self._total_up += sum(len(data) for data in packets) * len(candidates)
        self._total_send += (len(packets) * len(candidates))

        with self._sendqueue_lock:
            batch = [(candidate.sock_addr, TUNNEL_PREFIX + data if candidate.tunnel else data)
                     for candidate, data
                     in product(candidates, packets)]

            if len(batch) > 0:
                did_have_senqueue = bool(self._sendqueue)
                self._sendqueue.extend(batch)

                # If we did not already a sendqueue, then we need to call process_sendqueue in order send these messages
                if not did_have_senqueue:
                    self._process_sendqueue()

                # return True when something has been send
                return True

        return False

    def _process_sendqueue(self):
        assert self._dispersy, "Should not be called before start(...)"
        with self._sendqueue_lock:
            if self._sendqueue:
                index = 0
                NUM_PACKETS = min(max(50, len(self._sendqueue) / 10), len(self._sendqueue))
                logger.debug("%d left in sendqueue, trying to send %d packets", len(self._sendqueue), NUM_PACKETS)

                for i in xrange(NUM_PACKETS):
                    sock_addr, data = self._sendqueue[i]
                    try:
                        self._socket.sendto(data, sock_addr)
                        if logger.isEnabledFor(logging.DEBUG):
                            try:
                                name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                            except:
                                name = "???"
                            logger.debug("%30s -> %15s:%-5d %4d bytes", name, sock_addr[0], sock_addr[1], len(data))
                            self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, name)

                        index += 1

                    except socket.error as e:
                        if e[0] != SOCKET_BLOCK_ERRORCODE:
                            logger.warning("could not send %d to %s (%d in sendqueue)", len(data), sock_addr, len(self._sendqueue))

                        self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, u"socket-error")
                        break

                self._sendqueue = self._sendqueue[index:]
                if self._sendqueue:
                    # And schedule a new attempt
                    self._add_task(self._process_sendqueue, 0.1, "process_sendqueue")
                    logger.debug("%d left in sendqueue", len(self._sendqueue))

                self._cur_sendqueue = len(self._sendqueue)


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

    def open(self, dispersy):
        # do NOT call RawserverEndpoint.open!
        Endpoint.open(self, dispersy)

        while True:
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
                self._socket.bind((self._ip, self._port))
                self._socket.setblocking(0)
                logger.debug("Listening at %d", self._port)
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
                logger.error("the endpoint thread is still running (after waiting %f seconds)", timeout)
                result = False

        else:
            if self._thread.is_alive():
                logger.debug("the endpoint thread is still running (use timeout > 0.0 to ensure the thread stops)")
                result = False

        try:
            self._socket.close()
        except socket.error as exception:
            logger.exception("%s", exception)
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
                    self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, u"socket-error-'%s'" % str(e))

                finally:
                    if packets:
                        self.data_came_in(packets)


class TunnelEndpoint(Endpoint):

    def __init__(self, swift_process):
        super(TunnelEndpoint, self).__init__()
        self._swift = swift_process
        self._session = "ffffffff".decode("HEX")

    def open(self, dispersy):
        super(TunnelEndpoint, self).open(dispersy)
        self._swift.add_download(self)
        return True

    def close(self, timeout=0.0):
        self._swift.remove_download(self, True, True)
        return super(TunnelEndpoint, self).close(timeout)

    def get_def(self):
        class DummyDef(object):

            def get_roothash(self):
                return "dispersy-endpoint"

            def get_roothash_as_hex(self):
                return "dispersy-endpoint".encode("HEX")
        return DummyDef()

    def get_address(self):
        return ("0.0.0.0", self._swift.listenport)

    def send(self, candidates, packets):
        assert self._dispersy, "Should not be called before open(...)"
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates)
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets)
        assert all(len(packet) > 0 for packet in packets)
        if any(len(packet) > 2**16 - 60 for packet in packets):
            raise RuntimeError("UDP does not support %d byte packets" % len(max(len(packet) for packet in packets)))

        self._total_up += sum(len(data) for data in packets) * len(candidates)
        self._total_send += (len(packets) * len(candidates))

        self._swift.splock.acquire()
        try:
            for candidate in candidates:
                for data in packets:
                    if logger.isEnabledFor(logging.DEBUG):
                        try:
                            name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                        except:
                            name = "???"
                        logger.debug("%30s -> %15s:%-5d %4d bytes", name, candidate.sock_addr[0], candidate.sock_addr[1], len(data))
                        self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, name)

                    self._swift.send_tunnel(self._session, candidate.sock_addr, data)

            # return True when something has been send
            return candidates and packets

        finally:
            self._swift.splock.release()

    def i2ithread_data_came_in(self, session, sock_addr, data):
        assert self._dispersy, "Should not be called before open(...)"
        # assert session == self._session, [session, self._session]
        if logger.isEnabledFor(logging.DEBUG):
            try:
                name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
            except:
                name = "???"
            logger.debug("%30s <- %15s:%-5d %4d bytes", name, sock_addr[0], sock_addr[1], len(data))
            self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, name)

        self._total_down += len(data)
        self._dispersy.callback.register(self.dispersythread_data_came_in, (sock_addr, data, time()))

    def dispersythread_data_came_in(self, sock_addr, data, timestamp):
        assert self._dispersy, "Should not be called before open(...)"
        # candidate = self._dispersy.get_candidate(sock_addr) or self._dispersy.create_candidate(WalkCandidate, sock_addr, True)
        self._dispersy.on_incoming_packets([(Candidate(sock_addr, True), data)], True, timestamp)
