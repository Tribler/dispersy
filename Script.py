"""
Run some python code, usually to test one or more features.
"""

import socket
import hashlib
import types
from struct import pack, unpack_from

from Authentication import MultiMemberAuthentication
from Community import Community
from Conversion import DictionaryConversion, BinaryConversion
from Debug import Node, DiscoveryNode, ForumNode
from Destination import CommunityDestination
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Distribution import FullSyncDistribution, LastSyncDistribution
from Message import Message
from Payload import Permit
from Print import dprint
from Resolution import PublicResolution
from Member import Member

from Tribler.Community.Discovery.Discovery import DiscoveryCommunity
from Tribler.Community.Discovery.DiscoveryDatabase import DiscoveryDatabase
from Tribler.Community.Forum.Forum import ForumCommunity

class Script(object):
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

    @staticmethod
    def load(rawserver, script):
        terminator = Script.Terminator(rawserver)
        mapping = {"discovery-user":DiscoveryUserScript,
                   "discovery-community":DiscoveryCommunityScript,
                   "discovery-sync":DiscoverySyncScript,
                   # "conversion":ConversionScript,
                   "dispersy":DispersyScript,
                   # "dispersy-callback":DispersyCallbackScript,
                   "forum":ForumScript}
        
        dprint(script)
        if script == "all":
            for script, cls in mapping.iteritems():
                dprint(script)
                cls(terminator, script, rawserver)

        elif script in mapping:
            mapping[script](terminator, script, rawserver)

        else:
            raise ValueError("Unknown script '{0}'".format(script))

        terminator.run()

class ScriptBase(object):
    def __init__(self, terminator, script, rawserver):
        self._terminator = terminator
        self._script = script
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

class DiscoveryCommunityScript(ScriptBase):
    def run(self):
        self.caller(self.my_community_metadata)
        self.caller(self.food)
        self.caller(self.drink)
        self.caller(self.drinks)

    def my_community_metadata(self):

        cid, alias, comment = (hashlib.sha1("MY-FIRST-COMMUNITY").digest(), u"My First Community", u"My First Community Comment")
        self._discovery.create_community_metadata(cid, alias, comment)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == alias
        assert tup[1] == comment

        cid, alias, comment = (hashlib.sha1("MY-SECOND-COMMUNITY").digest(), u"My Second Community", u"My Second Community Comment")
        self._discovery.create_community_metadata(cid, alias, comment)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == alias
        assert tup[1] == comment

        cid, alias, comment = (hashlib.sha1("MY-THIRD-COMMUNITY").digest(), u"My Third Community", u"My Third Community Comment")
        self._discovery.create_community_metadata(cid, alias, comment)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == alias
        assert tup[1] == comment
        dprint("finished")

    def food(self):
        """
        Create a community and update its metadata one by one.
        Packets are send in order.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)

        address = self._dispersy.socket.get_address()
        cid = hashlib.sha1("FOOD").digest()

        node.send_message(node.create_community_metadata_message(cid, u"Food-01", u"Comment-01", 1, 1), address)
        yield 0.1
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        assert tup[0] == u"Food-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_community_metadata_message(cid, u"Food-02", u"Comment-02", 2, 2), address)
        yield 0.1
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        assert tup[0] == u"Food-02"
        assert tup[1] == u"Comment-02"

        node.send_message(node.create_community_metadata_message(cid, u"Food-03", u"Comment-03", 3, 3), address)
        yield 0.1
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        assert tup[0] == u"Food-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

    def drink(self):
        """
        Create a community and update its metadata one by one.
        Packets are send OUT OF order.  This must cause a request for
        the missing packet.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)

        address = self._dispersy.socket.get_address()
        cid = hashlib.sha1("DRINK").digest()

        node.send_message(node.create_community_metadata_message(cid, u"Drink-01", u"Comment-01", 1, 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drink-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_community_metadata_message(cid, u"Drink-03", u"Comment-03", 3, 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drink-01"
        assert tup[1] == u"Comment-01"

        _, pckt, message = node.receive_message(addresses=[address], message_names=[u"dispersy-missing-sequence"])
        # must ask for missing sequence 2
        assert message.payload.member.pem == node.my_member.pem
        assert message.payload.message.name == u"community-metadata"
        assert message.payload.missing_low == 2
        assert message.payload.missing_high == 2

        node.send_message(node.create_community_metadata_message(cid, u"Drink-02", u"Comment-02", 2, 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drink-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

    def drinks(self):
        """
        Create a community and update its metadata one by one.
        Packets are send OUT OF order.  This must cause a request for
        the missing packet.

        Checks the same as self.drink, but with a bigger gap between
        the sequence numbers.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)

        address = self._dispersy.socket.get_address()
        cid = hashlib.sha1("DRINKS").digest()

        node.send_message(node.create_community_metadata_message(cid, u"Drinks-01", u"Comment-01", 1, 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_community_metadata_message(cid, u"Drinks-05", u"Comment-05", 5, 5), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        _, pckt, message = node.receive_message(addresses=[address], message_names=[u"dispersy-missing-sequence"])
        # must ask for missing sequence 2, 3, and 4
        assert message.payload.member.pem == node.my_member.pem
        assert message.payload.message.name == u"community-metadata"
        assert message.payload.missing_low == 2
        assert message.payload.missing_high == 4

        node.send_message(node.create_community_metadata_message(cid, u"Drinks-03", u"Comment-03", 3, 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_community_metadata_message(cid, u"Drinks-04", u"Comment-04", 4, 4), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_community_metadata_message(cid, u"Drinks-02", u"Comment-02", 2, 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-05"
        assert tup[1] == u"Comment-05"
        dprint("finished")

class DiscoveryUserScript(ScriptBase):
    def run(self):
        self.caller(self.my_user_metadata)
        self.caller(self.alice)
        self.caller(self.bob)

    def my_user_metadata(self):
        my_member = self._discovery.my_member

        address = self._dispersy.socket.get_address()
        self._discovery.create_user_metadata(address, u"My Alias", u"My Comment")
        try:
            id_, = self._dispersy_database.execute(u"SELECT id FROM user WHERE pem = ? LIMIT 1", (buffer(my_member.pem),)).next()
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (id_,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"My Alias"
        assert tup[1] == u"My Comment"
        dprint("finished")
        
    def alice(self):
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)

        address = self._dispersy.socket.get_address()
        node_address = node.socket.getsockname()

        node.send_message(node.create_user_metadata_message(node_address, u"Alice-01", u"Comment-01", 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-01"
        assert tup[1] == u"Comment-01"

        node.send_message(node.create_user_metadata_message(node_address, u"Alice-03", u"Comment-03", 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"

        node.send_message(node.create_user_metadata_message(node_address, u"Alice-02", u"Comment-02", 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

    def bob(self):
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)

        address = self._dispersy.socket.get_address()
        node_address = node.socket.getsockname()

        node.send_message(node.create_user_metadata_message(node_address, u"Bob-03", u"Comment-03", 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        node.send_message(node.create_user_metadata_message(node_address, u"Bob-01", u"Comment-01", 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        node.send_message(node.create_user_metadata_message(node_address, u"Bob-02", u"Comment-02", 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE user = ?", (node.my_member.database_id,)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

class DiscoverySyncScript(ScriptBase):
    def run(self):
        self.caller(self.to_node)
        self.caller(self.from_node)

    def to_node(self):
        """
        We ensure that SELF has a the communities COPPER and TIN.  We
        send a dispersy-sync message with an empty bloom filter.  SELF
        should respond by offering the COPPER and TIN metadata.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)
        address = self._dispersy.socket.get_address()

        # create COPPER and TIN communities
        messages = []
        messages.append(node.create_community_metadata_message(hashlib.sha1("COPPER").digest(), u"Copper Community", u"Copper Community Comment", 1, 1))
        messages.append(node.create_community_metadata_message(hashlib.sha1("TIN").digest(), u"Tin Community", u"Tin Community Comment", 2, 2))
        packets = [node.encode_message(message) for message in messages]
        for packet in packets:
            node.send_packet(packet, address)
            yield 0.1

        # send empty bloomfilter
        node.send_message(node.create_dispersy_sync_message(1, [], 3), address)
        yield 0.1

        # receive COPPER and TIN communities
        received = [False] * len(packets)
        while filter(lambda x: not x, received):
            _, pckt = node.receive_packet(addresses=[address], packets=packets)
            for index, packet in zip(xrange(len(packets)), packets):
                if pckt == packet:
                    received[index] = True
        assert not filter(lambda x: not x, received)

        dprint("finished")

    def from_node(self):
        """
        We wait until SELF sends a dispersy-sync message to ensure
        that the messages are in its sync message.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member(sync_with_database=True)
        node.set_community(self._discovery)
        address = self._dispersy.socket.get_address()

        # create messages should show up in the bloom filter from SELF
        messages = []
        messages.append(node.create_community_metadata_message(hashlib.sha1("IRON").digest(), u"Iron Community", u"Iron Community Comment", 1, 1))
        messages.append(node.create_community_metadata_message(hashlib.sha1("MITHRIL").digest(), u"Mithril Community", u"Mithril Community Comment", 2, 2))
        packets = [node.encode_message(message) for message in messages]
        for packet in packets:
            node.send_packet(packet, address)
            yield 0.1

        # wait for dispersy-sync message
        for _ in xrange(10):
            yield 1.0
            try:
                _, packet, message = node.receive_message(timeout=0.1, addresses=[address], message_names=[u"dispersy-sync"])
            except socket.timeout:
                continue

            for packet in packets:
                assert packet in message.payload.bloom_filter
            break

        else:
            assert False

        dprint("finished")

# class ConversionScript(ScriptBase):
#     def run(self):
#         self.caller(self.size)

#     def size(self):
#         node = DiscoveryNode()
#         node.init_my_member()
#         node.set_community(self._discovery)

#         node2 = DiscoveryNode()
#         node2.init_my_member()

#         conversion = DictionaryConversion(self._discovery, "\x00\x00")
#         b1 = conversion.encode_message(node.create_dispersy_sync_message(1, [], 3))
#         b2 = conversion.encode_message(node.create_dispersy_missing_sequence_message(node2.my_member, node._user_metadata_message, 1, 10, 10, ("127.0.0.1", 123)))
#         dprint(len(b1), " ", len(b2))

#         def encode_msg(*args):
#             pass

#         def decode_msg(*args):
#             pass

#         conversion = BinaryConversion(self._discovery, "\x00\x01")
#         conversion.define_meta_message(chr(1), node._user_metadata_message, encode_msg, decode_msg)
#         b1 = conversion.encode_message(node.create_dispersy_sync_message(1, [], 3))
#         b2 = conversion.encode_message(node.create_dispersy_missing_sequence_message(node2.my_member, node._user_metadata_message, 1, 10, 10, ("127.0.0.1", 123)))
#         dprint(len(b1), " ", len(b2))
#         dprint("finished")

class DispersyScript(ScriptBase):
    class TestCommunityConversion(BinaryConversion):
        def __init__(self, community):
            super(DispersyScript.TestCommunityConversion, self).__init__(community, "\x00\x02")
            self.define_meta_message(chr(1), community.get_meta_message(u"double-signed-message"), self._encode_double_signed_message, self._decode_double_signed_message)

        def _encode_double_signed_message(self, message):
            return pack("!B", len(message.payload.message)), message.payload.message

        def _decode_double_signed_message(self, offset, data):
            if len(data) < offset + 1:
                raise DropPacket("Insufficient packet size")

            message_length, = unpack_from("!B", data, offset)
            offset += 1

            if len(data) < offset + message_length:
                raise DropPacket("Insufficient packet size")

            message = data[offset:offset+message_length]
            offset += message_length

            return offset, DispersyScript.DoubleSignedMessagePayload(message)

    class DoubleSignedMessagePayload(Permit):
        def __init__(self, message):
            assert isinstance(message, str)
            self._message = message

        @property
        def message(self):
            return self._message

    class TestCommunity(Community):
        """
        Community to test Dispersy related messages and policies.
        """
        def get_meta_messages(self):
            return [Message(self, u"double-signed-message", MultiMemberAuthentication(2, self.allow_signature_func), PublicResolution(), LastSyncDistribution(), CommunityDestination())]

        def __init__(self, cid):
            super(DispersyScript.TestCommunity, self).__init__(cid)

            # mapping
            self._incoming_message_map = {u"double-signed-message":self.on_doubled_sign_message}

            # add the Dispersy message handlers to the
            # _incoming_message_map
            for message, handler in self._dispersy.get_message_handlers(self):
                assert message.name not in self._incoming_message_map
                self._incoming_message_map[message.name] = handler

            # available conversions
            self.add_conversion(DispersyScript.TestCommunityConversion(self), True)

        def allow_signature_func(self, message):
            """
            Received a request to double sign MESSAGE.
            """
            dprint(message)
            return False

        def on_message(self, address, message):
            self._incoming_message_map[message.name](address, message)

        def on_doubled_sign_message(self, address, message):
            """
            Received a double signed message.
            """
            dprint(message, stack=1)

    def run(self):
        self.caller(self.double_signature)

    def double_signature(self):
        community = DispersyScript.TestCommunity.create_community(self._discovery.my_member)
        address = self._dispersy.socket.get_address()

        # create node and ensure that SELF knows the node address
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member()
        Member.get_instance(node.my_member.pem)
        node.set_community(self._discovery)
        node.send_message(node.create_user_metadata_message(node.socket.getsockname(), u"Node-01", u"Commen-01", 1), address)
        node.set_community(community)
        yield 0.1

        # SELF requests NODE to double sign
        def on_response(address, request, reply):
            dprint(address)
            dprint(request)
            dprint(reply)
        double_signed_message = DispersyScript.DoubleSignedMessagePayload("Hello World!")
        request = community.signature_request(community.get_meta_message(u"double-signed-message"), double_signed_message, (community.my_member, Member.get_instance(node.my_member.pem)))
        community.await_response(request, on_response, 1.0)
        yield 1.0

        # receive dispersy-signature-request message
        _, _, message = node.receive_message(addresses=[address], message_names=[u"dispersy-signature-request"])
        yield 2.0
        # should have timed out
        
        dprint("TODO")
        
class ForumScript(ScriptBase):
    def run(self):
        self.caller(self.create_my_forum)
        # self.caller(self.wow_forum)

    def create_my_forum(self):
        community = ForumCommunity.create_community(self._dispersy.my_member)
        community.create_set_settings(u"My Forum", u"My Forum Description")
        welcome_thread_message = community.create_thread(u"Welcome", u"Welcome everyone")
        community.create_post(welcome_thread_message.payload.key, u"Anyone else here?")

    def wow_forum(self):
        def get_or_create_node(nodes, user):
            if not user in nodes:
                # create user
                dprint("Creating '", user, "'")
                node = ForumNode()
                node.init_socket()
                node.init_my_member()
                node.set_community(community)
                node.sequence_number = 0

                # authorize user
                permission_pairs = []
                for privilege_name in [u"create-thread", u"create-post"]:
                    privilege = community.get_privilege(privilege_name)
                    for permission in [PermitPermission]:
                        permission_pairs.append((privilege, permission))
                community.authorize(node.my_member, permission_pairs)

                # set Discovery metadata
                global_time = self._discovery._timeline.global_time
                node.set_community(self._discovery)
                node.send_message(node.create_user_metadata_message(node.socket.getsockname(), unicode(user), u"Wow player {0}".format(user), global_time), address)
                node.set_community(community)

                # store for later
                nodes[user] = node
            return nodes[user]

        import apsw
        connection = apsw.Connection("/home/boudewijn/fetch_forum.db")
        cursor = connection.cursor()

        address = self._dispersy.socket.get_address()

        thread_counter = 0
        post_counter = 0
        nodes = {}
        community = ForumCommunity.create_community(self._dispersy.my_member)
        community.create_forum_settings(u"World of Warcraft", u"A database scrape from the World of Warcraft forums")
        for id_, in list(cursor.execute(u"SELECT id FROM thread ORDER BY id DESC")):
            gen = cursor.execute(u"SELECT user, title, comment FROM post WHERE thread = ? ORDER BY id DESC", (id_,))
            try:
                user, title, comment = gen.next()
            except StopIteration:
                continue

            node = get_or_create_node(nodes, user)
            key = "key#{0}".format(id_)
            global_time = community._timeline.global_time
            node.sequence_number += 1
            node.send_message(node.create_create_thread_message(key, title, comment, global_time, node.sequence_number), address)
            thread_counter += 1
            post_counter += 1
            yield 0.01

            while True:
                try:
                    user, title, comment = gen.next()
                except StopIteration:
                    break

                node = get_or_create_node(nodes, user)
                global_time = community._timeline.global_time
                node.sequence_number += 1
                node.send_message(node.create_create_post_message(key, comment, global_time, node.sequence_number), address)
                post_counter += 1
                yield 0.01

        dprint("Threads:", thread_counter, "; Posts:", post_counter)
        dprint("finished")
