# Python 2.5 features
from __future__ import with_statement

from itertools import product
from select import select
from time import time
from traceback import print_exc
import errno
import socket
import sys
import threading

from .candidate import Candidate

if __debug__:
    from .dprint import dprint

if sys.platform == 'win32':
    SOCKET_BLOCK_ERRORCODE = 10035    # WSAEWOULDBLOCK
else:
    SOCKET_BLOCK_ERRORCODE = errno.EWOULDBLOCK

TUNNEL_PREFIX = "ffffffff".decode("HEX")
DEBUG = False

class Endpoint(object):
    def __init__(self):
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

    def get_address(self):
        raise NotImplementedError()

    def send(self, candidates, packets):
        raise NotImplementedError()

class DummyEndpoint(Endpoint):
    """
    A dummy socket class.

    When Dispersy starts it does not yet have an endpoint object, however, it may (under certain
    conditions) start sending packets anyway.

    To avoid problems we initialize the Dispersy socket to this dummy object that will do nothing
    but throw away all packets it is supposed to sent.
    """
    def get_address(self):
        return ("0.0.0.0", 0)

    def send(self, candidates, packets):
        if __debug__: dprint("Thrown away ", sum(len(data) for data in packets), " bytes worth of outgoing data to ", ",".join(str(candidate) for candidate in candidates), level="warning")

class RawserverEndpoint(Endpoint):
    def __init__(self, rawserver, dispersy, port, ip="0.0.0.0"):
        super(RawserverEndpoint, self).__init__()

        while True:
            try:
                self._socket = rawserver.create_udpsocket(port, ip)
                if __debug__: dprint("Listening at ", port)
            except socket.error:
                port += 1
                continue
            break

        self._rawserver = rawserver
        self._rawserver.start_listening_udp(self._socket, self)
        self._add_task = self._rawserver.add_task
        self._dispersy = dispersy
        
        self._sendqueue_lock = threading.RLock()
        self._sendqueue = []

    def get_address(self):
        return self._socket.getsockname()

    def data_came_in(self, packets):
        # called on the Tribler rawserver

        # the rawserver SUCKS.  every now and then exceptions are not shown and apparently we are
        # sometimes called without any packets...
        if packets:
            self._total_down += sum(len(data) for _, data in packets)

            if DEBUG:
                for sock_addr, data in packets:
                    try:
                        name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                    except:
                        name = "???"
                    print >> sys.stderr, "endpoint: %.1f %30s <- %15s:%-5d %4d bytes" % (time(), name, sock_addr[0], sock_addr[1], len(data))
                    self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, name)
                    
            self._dispersy.callback.register(self.dispersythread_data_came_in, (packets, time()))

    def dispersythread_data_came_in(self, packets, timestamp):
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
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates)
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets)
        assert all(len(packet) > 0 for packet in packets)

        self._total_up += sum(len(data) for data in packets) * len(candidates)
        self._total_send += (len(packets) * len(candidates))
        
        wan_address = self._dispersy.wan_address

        with self._sendqueue_lock:
            batch = [(candidate.get_destination_address(wan_address), TUNNEL_PREFIX + data if candidate.tunnel else data)
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
        with self._sendqueue_lock:
            if self._sendqueue:
                index = 0
                NUM_PACKETS = min(max(50, len(self._sendqueue) / 10), len(self._sendqueue))
                if DEBUG:
                    print >> sys.stderr, "endpoint:", len(self._sendqueue), "left in queue, trying to send", NUM_PACKETS
                
                for i in xrange(NUM_PACKETS):
                    sock_addr, data = self._sendqueue[i]
                    try:
                        self._socket.sendto(data, sock_addr)
                        if DEBUG:
                            try:
                                name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                            except:
                                name = "???"
                            print >> sys.stderr, "endpoint: %.1f %30s -> %15s:%-5d %4d bytes" % (time(), name, sock_addr[0], sock_addr[1], len(data))
                            self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, name)
                            
                        index += 1
    
                    except socket.error, e:
                        if e[0] != SOCKET_BLOCK_ERRORCODE:
                            if DEBUG:
                                print >> sys.stderr, long(time()), "endpoint: could not send", len(data), "to", sock_addr, len(self._sendqueue)
                                print_exc()
                                
                        self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, u"socket-error")
                        break
    
                self._sendqueue = self._sendqueue[index:]
                if self._sendqueue:
                    # And schedule a new attempt
                    self._add_task(self._process_sendqueue, 0.1, "process_sendqueue")
                    if DEBUG:
                        print >> sys.stderr, "endpoint:", len(self._sendqueue), "left in queue"
                
                self._cur_sendqueue = len(self._sendqueue)
                
class StandaloneEndpoint(RawserverEndpoint):
    def __init__(self, dispersy, port, ip="0.0.0.0"):
        Endpoint.__init__(self)
        
        self._running = True
        self._dispersy = dispersy
        self._thread = threading.Thread(name="StandaloneEndpoint", target=self._loop, args=(port, ip))
        self._thread.daemon = True

        while True:
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
                self._socket.bind((ip, port))
                self._socket.setblocking(0)
                if __debug__: dprint("Listening at ", port)
            except socket.error:
                port += 1
                continue
            break
        
        self._add_task = lambda task, delay = 0.0, id = "": None 
        self._sendqueue_lock = threading.RLock()
        self._sendqueue = []

    def start(self):
        self._thread.start()

    def stop(self, timeout=10.0):
        self._running = False
        self._thread.join(timeout)

    def _loop(self, port, ip):
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
                        
                except socket.error, e:
                    self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, u"socket-error-'%s'"%str(e))
                        
                finally:
                    if packets:
                        self.data_came_in(packets)

class TunnelEndpoint(Endpoint):
    def __init__(self, swift_process, dispersy):
        super(TunnelEndpoint, self).__init__()
        self._swift = swift_process
        self._dispersy = dispersy
        self._session = "ffffffff".decode("HEX")

    def get_def(self):
        class DummyDef(object):
            def get_roothash(self):
                return "dispersy"
            def get_roothash_as_hex(self):
                return "dispersy".encode("HEX")
        return DummyDef()

    def get_address(self):
        return ("0.0.0.0", self._swift.listenport)

    def send(self, candidates, packets):
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        assert all(isinstance(candidate, Candidate) for candidate in candidates)
        assert isinstance(packets, (tuple, list, set)), type(packets)
        assert all(isinstance(packet, str) for packet in packets)
        assert all(len(packet) > 0 for packet in packets)

        self._total_up += sum(len(data) for data in packets) * len(candidates)
        self._total_send += (len(packets) * len(candidates)) 
        wan_address = self._dispersy.wan_address

        self._swift.splock.acquire()
        try:
            for candidate in candidates:
                sock_addr = candidate.get_destination_address(wan_address)
                assert self._dispersy.is_valid_address(sock_addr), sock_addr

                for data in packets:
                    if DEBUG:
                        try:
                            name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
                        except:
                            name = "???"
                            
                        print >> sys.stderr, "endpoint: %.1f %30s -> %15s:%-5d %4d bytes" % (time(), name, sock_addr[0], sock_addr[1], len(data))
                        self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_send, name)
                        
                    self._swift.send_tunnel(self._session, sock_addr, data)

            # return True when something has been send
            return candidates and packets

        finally:
            self._swift.splock.release()

    def i2ithread_data_came_in(self, session, sock_addr, data):
        # assert session == self._session, [session, self._session]
        if DEBUG:
            try:
                name = self._dispersy.convert_packet_to_meta_message(data, load=False, auto_load=False).name
            except:
                name = "???"
            
            print >> sys.stderr, "endpoint: %.1f %30s <- %15s:%-5d %4d bytes" % (time(), name, sock_addr[0], sock_addr[1], len(data))
            self._dispersy.statistics.dict_inc(self._dispersy.statistics.endpoint_recv, name)
            
        self._total_down += len(data)
        self._dispersy.callback.register(self.dispersythread_data_came_in, (sock_addr, data, time()))

    def dispersythread_data_came_in(self, sock_addr, data, timestamp):
        # candidate = self._dispersy.get_candidate(sock_addr) or self._dispersy.create_candidate(WalkCandidate, sock_addr, True)
        self._dispersy.on_incoming_packets([(Candidate(sock_addr, True), data)], True, timestamp)
