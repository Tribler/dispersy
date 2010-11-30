"""
Run some python code, usually to test one or more features.
"""

import socket
import hashlib
import types
from struct import pack, unpack_from

from Singleton import Singleton
from Authentication import MultiMemberAuthentication
from Community import Community
from Conversion import DictionaryConversion, BinaryConversion
from Debug import Node
from Destination import CommunityDestination
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution
from Member import Member
from Message import Message
from Payload import Permit
from Print import dprint
from Resolution import PublicResolution

from DebugCommunity import DebugCommunity, DebugNode

from Tribler.Community.Discovery.Community import DiscoveryCommunity
from Tribler.Community.Discovery.Database import DiscoveryDatabase

class Script(Singleton):
    class Terminator(object):
        def __init__(self, rawserver):
            self._rawserver = rawserver
            self._counter = 0

        def start(self):
            self._counter += 1

        def stop(self):
            assert self._counter > 0
            self._counter -= 1

        def run(self):
            self._rawserver.add_task(self.loop, 0.0)

        def loop(self):
            if self._counter == 0:
                dprint("Shutdown")
                self._rawserver.doneflag.set()
                self._rawserver.shutdown()

            else:
                self._rawserver.add_task(self.loop, 1.0)

    def __init__(self):
        self._scripts = {}

    def add(self, name, script, include_with_all=True):
        assert isinstance(name, str)
        assert not name in self._scripts
        assert issubclass(script, ScriptBase)
        self._scripts[name] = (include_with_all, script)

    def load(self, rawserver, name):
        dprint(name)
        terminator = Script.Terminator(rawserver)
       
        if name == "all":
            for name, (include_with_all, script) in self._scripts.iteritems():
                if include_with_all:
                    dprint(name)
                    script(terminator, name, rawserver)

        elif name in self._scripts:
            self._scripts[name][1](terminator, name, rawserver)

        else:
            for available in sorted(self._scripts):
                dprint("Available: ", available)
            raise ValueError("Unknown script '{0}'".format(name))

        terminator.run()

class ScriptBase(object):
    def __init__(self, terminator, name, rawserver):
        self._terminator = terminator
        self._name = name
        self._rawserver = rawserver
        self._dispersy = Dispersy.get_instance()
        self._dispersy_database = DispersyDatabase.get_instance()
        self._discovery = DiscoveryCommunity.get_instance()
        self._discovery_database = DiscoveryDatabase.get_instance()
        self.caller(self.run)

    def caller(self, run):
        def helper():
            try:
                delay = run_generator.next()
            except StopIteration:
                self._terminator.stop()
            else:
                assert isinstance(delay, float)
                self._rawserver.add_task(helper, delay)

        self._terminator.start()
        run_generator = run()
        if isinstance(run_generator, types.GeneratorType):
            self._rawserver.add_task(helper, 0.0)
        else:
            self._terminator.stop()

    def run():
        raise NotImplementedError("Must implement a generator")

class DispersyScript(ScriptBase):
    def run(self):
        self.caller(self.last_1_test)
        self.caller(self.last_9_test)
        self.caller(self.double_signed_timeout)
        self.caller(self.double_signed_response)
        self.caller(self.triple_signed_timeout)
        self.caller(self.triple_signed_response)
        self.caller(self.similarity_check_incoming_packets)
        self.caller(self.similarity_fullsync)
        self.caller(self.similarity_lastsync)
        self.caller(self.similarity_missing_sim)

    def last_1_test(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        cluster = community.get_meta_message(u"last-1-test").distribution.cluster
        
        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_last_1_test_message("1", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 11
        node.send_message(node.create_last_1_test_message("2", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message (older: should be dropped)
        node.send_message(node.create_last_1_test_message("-1", 8), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message (duplicate: should be dropped)
        node.send_message(node.create_last_1_test_message("2", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 12
        node.send_message(node.create_last_1_test_message("3", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        dprint("finished")

    def last_9_test(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        cluster = community.get_meta_message(u"last-1-test").distribution.cluster
        
        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster)))
        assert len(times) == 0

        number_of_messages = 0
        for global_time in [11, 10, 18, 17, 12, 13, 14, 16, 15]:
            # send a message
            message = node.create_last_9_test_message(str(global_time), global_time)
            node.send_message(message, address)
            number_of_messages += 1
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            dprint(sorted(times))
            assert len(times) == number_of_messages, (len(times), number_of_messages)
            assert global_time in times
        assert number_of_messages == 9, number_of_messages

        for global_time in [1, 2, 3, 9, 8, 7]:
            # send a message (older: should be dropped)
            node.send_message(node.create_last_9_test_message(str(global_time), global_time), address)
            yield 0.1
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            assert len(times) == 9, len(times)
            assert not global_time in times
            
        for global_time in [11, 10, 18, 17, 12, 13, 14, 16, 15]:
            # send a message (duplicate: should be dropped)
            message = node.create_last_9_test_message("wrong content!", global_time)
            node.send_message(message, address)
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert not str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            assert sorted(times) == range(10, 19), sorted(times)

        match_times = sorted(times[:])
        for global_time in [20, 25, 27, 21, 22, 24, 23, 26, 28, 35, 34, 33, 32, 31, 30, 29]:
            # send a message (should be added and old one removed)
            message = node.create_last_9_test_message("wrong content!", global_time)
            node.send_message(message, address)
            match_times.pop(0)
            match_times.append(global_time)
            match_times.sort()
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND distribution_cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            dprint(sorted(times))
            assert sorted(times) == match_times, sorted(times)

        dprint("finished")

    def double_signed_timeout(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # create node and ensure that SELF knows the node address
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # SELF requests NODE to double sign
        def on_response(address, response, request):
            assert address == ("", -1)
            assert response is None
            container["timeout"] += 1
        request = community.create_double_signed_text("Hello World!", Member.get_instance(node.my_member.pem), on_response, 3.0)

        # receive dispersy-signature-request message
        _, message = node.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should time out
        yield 4.0

        assert container["timeout"] == 1, container["timeout"]
        dprint("finished")

    def double_signed_response(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"response":0, "signature":""}

        # create node and ensure that SELF knows the node address
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # SELF requests NODE to double sign
        def on_response(address, response, request):
            assert container["response"] == 0, container["response"]
            assert address == node.socket.getsockname(), address
            assert request.authentication.is_signed
            container["response"] += 1
            container["signature"] = response.payload.signature
        request = community.create_double_signed_text("Hello World!", Member.get_instance(node.my_member.pem), on_response, 3.0)

        # receive dispersy-signature-request message
        address, message = node.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        second_signature_offset = len(message.payload.packet) - community.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        assert message.payload.packet[second_signature_offset:] == "\x00" * node.my_member.signature_length
        signature = node.my_member.sign(message.payload.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node.send_message(node.create_dispersy_signature_response_message(request_id, signature, global_time, community.my_member), address)

        # should not time out
        yield 4.0

        assert container["response"] == 1, container["response"]
        assert container["signature"] == signature, container["signature"]
        dprint("finished")

    def triple_signed_timeout(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # create node and ensure that SELF knows the node address
        node1 = Node()
        node1.init_socket()
        node1.set_community(community)
        node1.init_my_member()
        yield 0.1

        # create node and ensure that SELF knows the node address
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1

        # SELF requests NODE1 and NODE2 to double sign
        def on_response(address, response, request):
            assert address == ("", -1)
            assert response is None
            container["timeout"] += 1
        request = community.create_triple_signed_text("Hello World!", Member.get_instance(node1.my_member.pem), Member.get_instance(node2.my_member.pem), on_response, 3.0)

        # receive dispersy-signature-request message
        _, message = node1.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        _, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should time out
        yield 4.0

        assert container["timeout"] == 1, container["timeout"]
        dprint("finished")

    def triple_signed_response(self):
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"response":0, "signature":[]}

        # create node and ensure that SELF knows the node address
        node1 = Node()
        node1.init_socket()
        node1.set_community(community)
        node1.init_my_member()
        yield 0.1

        # create node and ensure that SELF knows the node address
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1

        # SELF requests NODE1 and NODE2 to add their signature
        def on_response(address, response, request):
            assert container["response"] == 0 or request.authentication.is_signed
            container["response"] += 1
            container["signature"].append(response.payload.signature)
        request = community.create_triple_signed_text("Hello World!", Member.get_instance(node1.my_member.pem), Member.get_instance(node2.my_member.pem), on_response, 3.0)

        # receive dispersy-signature-request message
        address, message = node1.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        third_signature_offset = len(message.payload.packet) - node2.my_member.signature_length
        second_signature_offset = third_signature_offset - node1.my_member.signature_length
        first_signature_offset = second_signature_offset - community.my_member.signature_length
        assert message.payload.packet[second_signature_offset:third_signature_offset] == "\x00" * node1.my_member.signature_length
        signature1 = node1.my_member.sign(message.payload.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node1.send_message(node1.create_dispersy_signature_response_message(request_id, signature1, global_time, community.my_member), address)

        # receive dispersy-signature-request message
        address, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        third_signature_offset = len(message.payload.packet) - node2.my_member.signature_length
        second_signature_offset = third_signature_offset - node1.my_member.signature_length
        first_signature_offset = second_signature_offset - community.my_member.signature_length
        assert message.payload.packet[third_signature_offset:] == "\x00" * node2.my_member.signature_length
        signature2 = node2.my_member.sign(message.payload.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node2.send_message(node2.create_dispersy_signature_response_message(request_id, signature2, global_time, community.my_member), address)

        # should not time out
        yield 4.0

        assert container["response"] == 2, container["response"]
        assert container["signature"] == [signature1, signature2], container["signature"]
        dprint("finished")

    def similarity_check_incoming_packets(self):
        """
        Check functionallity of accepting or rejecting
        incoming packets based on similarity of the user
        sending the packet
        """
        from Bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        ##
        ## Similar Nodes
        ##
        
        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 2), address)
        yield 0.1

        msg = node.create_taste_aware_message(5, 1, 1)
        msg_blob = node.encode_message(msg)
        node.send_message(msg, address)
        yield 0.1

        with self._dispersy.database as execute:
            d, = execute(u"SELECT count(*) FROM sync WHERE packet = ?", (buffer(str(msg_blob)),)).next()
            assert d == 1

        ##
        ## Not Similar Nodes
        ##

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b11111111)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 3), address)
        yield 0.1

        msg = node.create_taste_aware_message(5, 2, 2)
        msg_blob = node.encode_message(msg)
        node.send_message(msg, address)
        yield 0.1

        with self._dispersy.database as execute:
            d,= execute(u"SELECT count(*) FROM sync WHERE packet = ?", (buffer(str(msg_blob)),)).next()
            assert d == 0

        dprint("finished")

    def similarity_fullsync(self):
        from Bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create second node - node-02
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1

        ##
        ## Similar Nodes Threshold 12 Similarity 14
        ##
        dprint("Testing similar nodes")
        
        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 2), address)
        yield 0.1

        # create similarity for node-02
        # node node-02 has 14/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 2), address)
        yield 0.1

        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message(5, 1, 1), address)

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1

        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])

        ##
        ## Similar Nodes Threshold 12 Similarity 12
        ##
        dprint("Testing similar nodes 2")

        # create similarity for node-02
        # node node-02 has 12/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110011), chr(0b11000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 3), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1

        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])

        ##
        ## Not Similar Nodes Threshold 12 Similarity 2
        ##
        dprint("Testing not similar nodes")

        # create similarity for node-02
        # node node-02 has 2/16 same bits with node-01
        # BELOW threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b00001111), chr(0b11111100)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 4), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1
        
        # receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
        except socket.timeout:
            pass
        else:
            raise Exception("Message received error")

        yield 1.0
        ##
        ## Not Similar Nodes Threshold 12 Similarity 11
        ##
        dprint("Testing not similar nodes 2")

        # create similarity for node-02
        # node node-02 has 11/16 same bits with node-01
        # BELOW threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110010), chr(0b00110011)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 5), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1
        
        # receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
        except socket.timeout:
            pass
        else:
            raise Exception("Message received error")

        dprint("finished")

    def similarity_lastsync(self):
        from Bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 2, buffer(str(bf))))

        # create first node - node-01
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create second node - node-02
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1

        ##
        ## Similar Nodes
        ## 
        dprint("Testing similar nodes")

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(2, community.database_id, bf, 2), address)
        yield 0.1

        # create similarity for node-02
        # node node-02 has 15/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(2, community.database_id, bf, 2), address)
        yield 0.1

        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message_last(5, 3), address)

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1
        
        # receive a message
        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record-last"])

        ##
        ## Not Similar Nodes
        ## 
        dprint("Testing not similar nodes")

        # create similarity for node-02
        # node node-02 has 11/16 same bits with node-01
        # BELOW threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b00100011), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(2, community.database_id, bf, 3), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1
        
        # receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record-last"])
        except socket.timeout:
            dprint("finished")
        else:
            raise Exception("Message received error")

    def similarity_missing_sim(self):
        from Bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        community = DebugCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 2), address)
        yield 0.1

        # create second node - node-02
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1
        
        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message(5, 1, 1), address)
        yield 0.1

        # node-02 sends a sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1

        # because 'self' does not have our similarity
        # we should first receive a 'dispersy-similarity-request' message
        # and 'synchronize' e.g. send our similarity
        _, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-similarity-request"])
        
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 2), address)
        yield 0.1      

        # receive the taste message
        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
        assert  message.payload.number == 5
 
        dprint("finished")
