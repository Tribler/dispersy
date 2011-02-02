"""
Run some python code, usually to test one or more features.
"""

import hashlib
import types
from struct import pack, unpack_from

from authentication import MultiMemberAuthentication
from community import Community
from conversion import BinaryConversion
from crypto import ec_generate_key, ec_to_public_pem, ec_to_private_pem
from debug import Node
from destination import CommunityDestination
from dispersy import Dispersy
from dispersydatabase import DispersyDatabase
from distribution import FullSyncDistribution, LastSyncDistribution
from dprint import dprint
from member import Member, MyMember
from message import Message
from resolution import PublicResolution
from singleton import Singleton

from debugcommunity import DebugCommunity, DebugNode

class Script(Singleton):
    def __init__(self, rawserver):
        self._call_generators = []
        self._scripts = {}
        self._rawserver = rawserver

    def add(self, name, script, args={}, include_with_all=True):
        assert isinstance(name, str)
        assert not name in self._scripts
        assert issubclass(script, ScriptBase)
        self._scripts[name] = (include_with_all, script, args)

    def load(self, name):
        dprint(name)

        if name == "all":
            for name, (include_with_all, script, args) in self._scripts.iteritems():
                if include_with_all:
                    dprint(name)
                    script(self, name, self._rawserver, **args)

        elif name in self._scripts:
            self._scripts[name][1](self, name, self._rawserver, **self._scripts[name][2])

        else:
            for available in sorted(self._scripts):
                dprint("available: ", available)
            raise ValueError("Unknown script '{0}'".format(name))

    def add_generator(self, call, call_generator):
        self._call_generators.append((call, call_generator))
        if len(self._call_generators) == 1:
            dprint("start: ", call)
            self._rawserver.add_task(self._process_generators, 0.0)

    def _process_generators(self):
        if self._call_generators:
            call, call_generator = self._call_generators[0]
            try:
                delay = call_generator.next()

            except StopIteration:
                self._call_generators.pop(0)
                delay = 0.1
                dprint("finished: ", call)
                if self._call_generators:
                    call, call_generator = self._call_generators[0]
                    dprint("start: ", call)

            self._rawserver.add_task(self._process_generators, delay)

        else:
            dprint("shutdown")
            self._rawserver.doneflag.set()
            self._rawserver.shutdown()

class ScriptBase(object):
    def __init__(self, script, name, rawserver, **kargs):
        self._script = script
        self._name = name
        # self._rawserver = rawserver
        self._dispersy = Dispersy.get_instance()
        self._dispersy_database = DispersyDatabase.get_instance()
        self.caller(self.run)

    def caller(self, run):
        run_generator = run()
        if isinstance(run_generator, types.GeneratorType):
            self._script.add_generator(run, run_generator)

    def run():
        raise NotImplementedError("Must implement a generator or use self.caller(...)")

class DispersyDestroyCommunityScript(ScriptBase):
    def run(self):
        ec = ec_generate_key("low")
        self._my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)

        self.caller(self.hard_kill)

    def hard_kill(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_full_sync_text_message("should be accepted (1)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # destroy the community
        community.create_dispersy_destroy_community(u"hard-kill")
        yield 0.1

        # node should receive the dispersy-destroy-community message
        _, message = node.receive_message(addresses=[address], message_names=[u"dispersy-destroy-community"])
        assert not message.payload.is_soft_kill
        assert message.payload.is_hard_kill

        # the database should be cleaned

class DispersyMemberTagScript(ScriptBase):
    def run(self):
        ec = ec_generate_key("low")
        self._my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)

        self.caller(self.ignore_test)
        self.caller(self.drop_test)

    def ignore_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_full_sync_text_message("should be accepted (1)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # we now tag the member as ignore
        Member.get_instance(node.my_member.pem).must_ignore = True

        tags, = self._dispersy_database.execute(u"SELECT tags FROM user WHERE id = ?", (node.my_member.database_id,)).next()
        assert tags & 2

        # send a message and ensure it is in the database
        global_time = 20
        node.send_message(node.create_full_sync_text_message("should be accepted (2)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 2
        assert global_time in times

        # we now tag the member not to ignore
        Member.get_instance(node.my_member.pem).must_ignore = False

        # send a message
        global_time = 30
        node.send_message(node.create_full_sync_text_message("should be accepted (3)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 3
        assert global_time in times

    def drop_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_full_sync_text_message("should be accepted (1)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # we now tag the member as drop
        Member.get_instance(node.my_member.pem).must_drop = True

        tags, = self._dispersy_database.execute(u"SELECT tags FROM user WHERE id = ?", (node.my_member.database_id,)).next()
        assert tags & 4

        # send a message and ensure it is not in the database
        global_time = 20
        node.send_message(node.create_full_sync_text_message("should NOT be accepted (2)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time not in times

        # we now tag the member not to drop
        Member.get_instance(node.my_member.pem).must_drop = False

        # send a message
        global_time = 30
        node.send_message(node.create_full_sync_text_message("should be accepted (3)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 2
        assert global_time in times

class DispersySyncScript(ScriptBase):
    def run(self):
        ec = ec_generate_key("low")
        self._my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)

        self.caller(self.in_order_test)
        self.caller(self.out_order_test)
        self.caller(self.random_order_test)
        self.caller(self.mixed_order_test)
        self.caller(self.last_1_test)
        self.caller(self.last_9_test)

    def in_order_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"in-order-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # create some data
        global_times = range(10, 15)
        for global_time in global_times:
            node.send_message(node.create_in_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1

        # send an empty sync message to obtain all messages in-order
        node.send_message(node.create_dispersy_sync_message(min(global_times), max(global_times), [], max(global_times)), address)
        yield 0.1

        for global_time in global_times:
            _, message = node.receive_message(addresses=[address], message_names=[u"in-order-text"])
            assert message.distribution.global_time == global_time

    def out_order_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"out-order-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # create some data
        global_times = range(10, 15)
        for global_time in global_times:
            node.send_message(node.create_out_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1

        # send an empty sync message to obtain all messages out-order
        node.send_message(node.create_dispersy_sync_message(min(global_times), max(global_times), [], max(global_times)), address)
        yield 0.1

        for global_time in reversed(global_times):
            _, message = node.receive_message(addresses=[address], message_names=[u"out-order-text"])
            assert message.distribution.global_time == global_time

    def random_order_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"random-order-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # create some data
        global_times = range(10, 15)
        for global_time in global_times:
            node.send_message(node.create_random_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1

        def get_messages_back():
            received_times = []
            for _ in range(len(global_times)):
                _, message = node.receive_message(addresses=[address], message_names=[u"random-order-text"])
                received_times.append(message.distribution.global_time)

            return received_times

        lists = []
        for _ in range(5):
            # send an empty sync message to obtain all messages in random-order
            node.send_message(node.create_dispersy_sync_message(min(global_times), max(global_times), [], max(global_times)), address)
            yield 0.1

            received_times = get_messages_back()
            if not received_times in lists:
                lists.append(received_times)

        dprint(lists, lines=True)
        assert len(lists) > 1

    def mixed_order_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        in_order_message = community.get_meta_message(u"in-order-text")
        out_order_message = community.get_meta_message(u"out-order-text")
        random_order_message = community.get_meta_message(u"random-order-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND (name = ? OR name = ? OR name = ?)", (community.database_id, node.my_member.database_id, in_order_message.database_id, out_order_message.database_id, random_order_message.database_id)))
        assert len(times) == 0, times

        # create some data
        global_times = range(10, 25, 3)
        in_order_times = []
        out_order_times = []
        random_order_times = []
        for global_time in global_times:
            in_order_times.append(global_time)
            node.send_message(node.create_in_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1
            global_time += 1
            out_order_times.append(global_time)
            node.send_message(node.create_out_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1
            global_time += 1
            random_order_times.append(global_time)
            node.send_message(node.create_random_order_text_message("Message #{0}".format(global_time), global_time), address)
            yield 0.1
        out_order_times.sort(reverse=True)

        def get_messages_back():
            received_times = []
            for _ in range(len(global_times) * 3):
                _, message = node.receive_message(addresses=[address], message_names=[u"in-order-text", u"out-order-text", u"random-order-text"])
                received_times.append(message.distribution.global_time)

            return received_times

        lists = []
        for _ in range(5):
            # send an empty sync message to obtain all messages in random-order
            node.send_message(node.create_dispersy_sync_message(min(global_times), max(global_times), [], max(global_times)), address)
            yield 0.1

            received_times = get_messages_back()

            # the first items must be in-order
            received_in_times = received_times[0:len(in_order_times)]
            assert in_order_times == received_in_times

            # followed by out-order
            received_out_times = received_times[len(in_order_times):len(in_order_times) + len(out_order_times)]
            assert out_order_times == received_out_times

            # followed by random-order
            received_random_times = received_times[len(in_order_times) + len(out_order_times):]
            for global_time in received_random_times:
                assert global_time in random_order_times

            if not received_times in lists:
                lists.append(received_times)

        dprint(lists, lines=True)
        assert len(lists) > 1

    def last_1_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"last-1-test")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0, times

        # send a message
        global_time = 10
        node.send_message(node.create_last_1_test_message("should be accepted (1)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 11
        node.send_message(node.create_last_1_test_message("should be accepted (2)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # send a message (older: should be dropped)
        node.send_message(node.create_last_1_test_message("should be dropped (1)", 8), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # send a message (duplicate: should be dropped)
        node.send_message(node.create_last_1_test_message("should be dropped (2)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

        # send a message
        global_time = 12
        node.send_message(node.create_last_1_test_message("should be accepted (3)", global_time), address)
        yield 0.1
        times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        assert len(times) == 1
        assert global_time in times

    def last_9_test(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        message = community.get_meta_message(u"last-1-test")

        # create node and ensure that SELF knows the node address
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # should be no messages from NODE yet
        times = list(self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        assert len(times) == 0

        number_of_messages = 0
        for global_time in [21, 20, 28, 27, 22, 23, 24, 26, 25]:
            # send a message
            message = node.create_last_9_test_message(str(global_time), global_time)
            node.send_message(message, address)
            number_of_messages += 1
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND name = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            dprint(sorted(times))
            assert len(times) == number_of_messages, (len(times), number_of_messages)
            assert global_time in times
        assert number_of_messages == 9, number_of_messages

        for global_time in [11, 12, 13, 19, 18, 17]:
            # send a message (older: should be dropped)
            node.send_message(node.create_last_9_test_message(str(global_time), global_time), address)
            yield 0.1
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            assert len(times) == 9, len(times)
            assert not global_time in times

        for global_time in [21, 20, 28, 27, 22, 23, 24, 26, 25]:
            # send a message (duplicate: should be dropped)
            message = node.create_last_9_test_message("wrong content!", global_time)
            node.send_message(message, address)
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND name = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            assert not str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            assert sorted(times) == range(20, 29), sorted(times)

        match_times = sorted(times[:])
        for global_time in [30, 35, 37, 31, 32, 34, 33, 36, 38, 45, 44, 43, 42, 41, 40, 39]:
            # send a message (should be added and old one removed)
            message = node.create_last_9_test_message("wrong content!", global_time)
            node.send_message(message, address)
            match_times.pop(0)
            match_times.append(global_time)
            match_times.sort()
            yield 0.1
            packet, = self._dispersy_database.execute(u"SELECT packet FROM sync WHERE community = ? AND user = ? AND global_time = ? AND name = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            assert str(packet) == message.packet
            times = [x for x, in self._dispersy_database.execute(u"SELECT global_time FROM sync WHERE community = ? AND user = ? AND name = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            dprint(sorted(times))
            assert sorted(times) == match_times, sorted(times)

class DispersySignatureScript(ScriptBase):
    def run(self):
        ec = ec_generate_key("low")
        self._my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)

        self.caller(self.double_signed_timeout)
        self.caller(self.double_signed_response)
        self.caller(self.triple_signed_timeout)
        self.caller(self.triple_signed_response)

    def double_signed_timeout(self):
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # create node and ensure that SELF knows the node address
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # SELF requests NODE to double sign
        def on_response(address, response):
            assert address == ("", -1)
            assert response is None
            container["timeout"] += 1
        request = community.create_double_signed_text("Accept=<does not reach this point>", Member.get_instance(node.my_member.pem), on_response, (), 3.0)
        yield 0.1

        # receive dispersy-signature-request message
        _, message = node.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should time out
        yield 4.0

        assert container["timeout"] == 1, container["timeout"]

    def double_signed_response(self):
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"response":0}

        # create node and ensure that SELF knows the node address
        node = Node()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # SELF requests NODE to double sign
        def on_response(address, response):
            assert container["response"] == 0, container["response"]
            assert address == node.socket.getsockname(), address
            assert request.authentication.is_signed
            container["response"] += 1
        request = community.create_double_signed_text("Accept=False", Member.get_instance(node.my_member.pem), on_response, (), 3.0)
        yield 0.1

        # receive dispersy-signature-request message
        address, message = node.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        submsg = message.payload.message
        second_signature_offset = len(submsg.packet) - community.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        assert submsg.packet[second_signature_offset:] == "\x00" * node.my_member.signature_length
        signature = node.my_member.sign(submsg.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node.send_message(node.create_dispersy_signature_response_message(request_id, signature, global_time, address), address)

        # should not time out
        yield 4.0

        assert container["response"] == 1, container["response"]

    def triple_signed_timeout(self):
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
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
        def on_response(address, response):
            assert address == ("", -1)
            assert response is None
            container["timeout"] += 1
        request = community.create_triple_signed_text("Hello World!", Member.get_instance(node1.my_member.pem), Member.get_instance(node2.my_member.pem), on_response, (), 3.0)
        yield 0.1

        # receive dispersy-signature-request message
        _, message = node1.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        _, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should time out
        yield 4.0

        assert container["timeout"] == 1, container["timeout"]

    def triple_signed_response(self):
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"response":0}

        # create node and ensure that SELF knows the node address
        node1 = Node()
        node1.init_socket()
        node1.set_community(community)
        node1.init_my_member()
        yield 0.2

        # create node and ensure that SELF knows the node address
        node2 = Node()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.2

        # SELF requests NODE1 and NODE2 to add their signature
        def on_response(address, response):
            assert container["response"] == 0 or request.authentication.is_signed
            container["response"] += 1
        request = community.create_triple_signed_text("Hello World!", Member.get_instance(node1.my_member.pem), Member.get_instance(node2.my_member.pem), on_response, (), 3.0)

        # receive dispersy-signature-request message
        address, message = node1.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        submsg = message.payload.message
        third_signature_offset = len(submsg.packet) - node2.my_member.signature_length
        second_signature_offset = third_signature_offset - node1.my_member.signature_length
        first_signature_offset = second_signature_offset - community.my_member.signature_length
        assert submsg.packet[second_signature_offset:third_signature_offset] == "\x00" * node1.my_member.signature_length
        signature1 = node1.my_member.sign(submsg.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node1.send_message(node1.create_dispersy_signature_response_message(request_id, signature1, global_time, address), address)

        # receive dispersy-signature-request message
        address, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        submsg = message.payload.message
        third_signature_offset = len(submsg.packet) - node2.my_member.signature_length
        second_signature_offset = third_signature_offset - node1.my_member.signature_length
        first_signature_offset = second_signature_offset - community.my_member.signature_length
        assert submsg.packet[third_signature_offset:] == "\x00" * node2.my_member.signature_length
        signature2 = node2.my_member.sign(submsg.packet, length=first_signature_offset)

        # send dispersy-signature-response message
        request_id = hashlib.sha1(request.packet).digest()
        global_time = community._timeline.global_time
        node2.send_message(node2.create_dispersy_signature_response_message(request_id, signature2, global_time, address), address)

        # should not time out
        yield 4.0

        assert container["response"] == 2, container["response"]

class DispersySimilarityScript(ScriptBase):
    def run(self):
        ec = ec_generate_key("low")
        self._my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)

        # self.caller(self.similarity_check_incoming_packets)
        self.caller(self.similarity_fullsync)
        self.caller(self.similarity_lastsync)
        self.caller(self.similarity_missing_sim)

    def similarity_check_incoming_packets(self):
        """
        Check functionallity of accepting or rejecting
        incoming packets based on similarity of the user
        sending the packet
        """
        from bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        ##
        ## Similar Nodes
        ##

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 20), address)
        yield 0.1

        msg = node.create_taste_aware_message(5, 10, 1)
        msg_blob = node.encode_message(msg)
        node.send_message(msg, address)
        yield 0.1

        dprint(len(msg_blob), "-", len(msg.packet))
        dprint(msg_blob.encode("HEX"))
        dprint(msg.packet.encode("HEX"))
        assert msg_blob == msg.packet

        dprint(msg_blob.encode("HEX"))

        with self._dispersy.database as execute:
            d, = execute(u"SELECT count(*) FROM sync WHERE packet = ?", (buffer(msg.packet),)).next()
            assert d == 1, d

        ##
        ## Not Similar Nodes
        ##

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11111111), chr(0b11111111)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 30), address)
        yield 0.1

        msg = node.create_taste_aware_message(5, 20, 2)
        msg_blob = node.encode_message(msg)
        node.send_message(msg, address)
        yield 0.1

        with self._dispersy.database as execute:
            d,= execute(u"SELECT count(*) FROM sync WHERE packet = ?", (buffer(str(msg_blob)),)).next()
            assert d == 0

    def similarity_fullsync(self):
        from bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create second node - node-02
        node2 = DebugNode()
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
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 20), address)
        yield 0.1

        # create similarity for node-02
        # node node-02 has 14/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 20), address)
        yield 0.1

        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message(5, 10, 1), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # should receive a message
        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])

        ##
        ## Similar Nodes Threshold 12 Similarity 12
        ##
        dprint("Testing similar nodes 2")

        # create similarity for node-02
        # node node-02 has 12/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110011), chr(0b11000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 30), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # should receive a message
        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])

        ##
        ## Not Similar Nodes Threshold 12 Similarity 2
        ##
        dprint("Testing not similar nodes")

        # create similarity for node-02
        # node node-02 has 2/16 same bits with node-01
        # BELOW threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b00001111), chr(0b11111100)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 40), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # should NOT receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
            assert False
        except:
            pass

        yield 1.0
        ##
        ## Not Similar Nodes Threshold 12 Similarity 11
        ##
        dprint("Testing not similar nodes 2")

        # create similarity for node-02
        # node node-02 has 11/16 same bits with node-01
        # BELOW threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110010), chr(0b00110011)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 50), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # should NOT receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
            assert False
        except:
            pass

    def similarity_lastsync(self):
        from bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 2, buffer(str(bf))))

        # create first node - node-01
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create second node - node-02
        node2 = DebugNode()
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
        node.send_message(node.create_dispersy_similarity_message(2, community.database_id, bf, 20), address)
        yield 0.1

        # create similarity for node-02
        # node node-02 has 15/16 same bits with node-01
        # ABOVE threshold
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(2, community.database_id, bf, 20), address)
        yield 0.1

        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message_last(5, 30, 1), address)

        # node-02 sends a sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
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
        node2.send_message(node2.create_dispersy_similarity_message(2, community.database_id, bf, 30), address)
        yield 0.1

        # node-02 sends an sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # receive a message
        try:
            _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record-last"])
            assert False
        except:
            pass

    def similarity_missing_sim(self):
        from bloomfilter import BloomFilter
        import struct

        # create community
        # taste-aware-record  uses SimilarityDestination with the following parameters
        # 16 Bits Bloom Filter, minimum 6, maximum 10, threshold 12
        ec = ec_generate_key("low")
        my_member = MyMember.get_instance(ec_to_public_pem(ec), ec_to_private_pem(ec), sync_with_database=True)
        community = DebugCommunity.create_community(self._my_member)
        address = self._dispersy.socket.get_address()
        container = {"timeout":0}

        # setting similarity for self
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        self._dispersy._database.execute(u"INSERT INTO similarity (community, user, cluster, similarity) VALUES (?, ?, ?, ?)",
                                         (community.database_id, community._my_member.database_id, 1, buffer(str(bf))))

        # create first node - node-01
        node = DebugNode()
        node.init_socket()
        node.set_community(community)
        node.init_my_member()
        yield 0.1

        # create similarity for node-01
        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b11110000), chr(0b00000000)), 0)
        node.send_message(node.create_dispersy_similarity_message(1, community.database_id, bf, 20), address)
        yield 0.1

        # create second node - node-02
        node2 = DebugNode()
        node2.init_socket()
        node2.set_community(community)
        node2.init_my_member()
        yield 0.1

        # node-01 creates and sends a message to 'self'
        node.send_message(node.create_taste_aware_message(5, 10, 1), address)
        yield 0.1

        # node-02 sends a sync message with an empty bloomfilter
        # to 'self'. It should collect the message
        node2.send_message(node2.create_dispersy_sync_message(1, 100, [], 3), address)
        yield 0.1

        # because 'self' does not have our similarity
        # we should first receive a 'dispersy-similarity-request' message
        # and 'synchronize' e.g. send our similarity
        _, message = node2.receive_message(addresses=[address], message_names=[u"dispersy-similarity-request"])

        bf = BloomFilter(struct.pack("!LLcc", 1, 16, chr(0b10111000), chr(0b00000000)), 0)
        node2.send_message(node2.create_dispersy_similarity_message(1, community.database_id, bf, 20), address)
        yield 0.1

        # receive the taste message
        _, message = node2.receive_message(addresses=[address], message_names=[u"taste-aware-record"])
        assert  message.payload.number == 5
