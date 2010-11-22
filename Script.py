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
        times = list(self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_last_1_test_message("1", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 11
        node.send_message(node.create_last_1_test_message("2", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message (older: should be dropped)
        node.send_message(node.create_last_1_test_message("-1", 8), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message (duplicate: should be dropped)
        node.send_message(node.create_last_1_test_message("2", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 12
        node.send_message(node.create_last_1_test_message("3", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
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
        times = list(self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster)))
        assert len(times) == 0

        number_of_messages = 0
        for global_time in [11, 10, 18, 17, 12, 13, 14, 16, 15]:
            # send a message
            message = node.create_last_9_test_message(str(global_time), global_time)
            node.send_message(message, address)
            number_of_messages += 1
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync_last WHERE community = ? AND user = ? AND global = ? AND cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            dprint(sorted(times))
            assert len(times) == number_of_messages, (len(times), number_of_messages)
            assert global_time in times
        assert number_of_messages == 9, number_of_messages

        for global_time in [1, 2, 3, 9, 8, 7]:
            # send a message (older: should be dropped)
            node.send_message(node.create_last_9_test_message(str(global_time), global_time), address)
            yield 0.1
            times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
            assert len(times) == 9, len(times)
            assert not global_time in times
            
        for global_time in [11, 10, 18, 17, 12, 13, 14, 16, 15]:
            # send a message (duplicate: should be dropped)
            message = node.create_last_9_test_message("wrong content!", global_time)
            node.send_message(message, address)
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync_last WHERE community = ? AND user = ? AND global = ? AND cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert not str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
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
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync_last WHERE community = ? AND user = ? AND global = ? AND cluster = ?", (community.database_id, node.my_member.database_id, global_time, cluster)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global FROM sync_last WHERE community = ? AND user = ? AND cluster = ?", (community.database_id, node.my_member.database_id, cluster))]
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
        def on_response(address, request, response):
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
        def on_response(address, request, response):
            assert container["response"] == 0, container["response"]
            assert address == node.socket.getsockname(), address
            assert request.authentication.is_signed
            container["response"] += 1
            container["signature"] = response.signature
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
        def on_response(address, request, response):
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
        def on_response(address, request, response):
            assert container["response"] == 0 or request.authentication.is_signed
            container["response"] += 1
            container["signature"].append(response.signature)
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
