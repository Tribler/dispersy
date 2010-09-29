"""
Run some python code, usually to test one or more features.
"""

import hashlib
import types

from Tribler.Community.Discovery.Discovery import DiscoveryCommunity
from Tribler.Community.Discovery.DiscoveryDatabase import DiscoveryDatabase
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Permission import PermitPermission
from Distribution import LastSyncDistribution
from Print import dprint
from Debug import DiscoveryNode

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
                   "discovery-community":DiscoveryCommunityScript}
        
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
        self.caller(self.sync)

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
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        cid = hashlib.sha1("FOOD").digest()

        send = node.send_message
        create = node.create_community_metadata_message

        send(create(cid, u"Food-01", u"Comment-01", 1, 1), address)
        yield 0.1
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        assert tup[0] == u"Food-01"
        assert tup[1] == u"Comment-01"

        send(create(cid, u"Food-02", u"Comment-02", 2, 2), address)
        yield 0.1
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        assert tup[0] == u"Food-02"
        assert tup[1] == u"Comment-02"

        send(create(cid, u"Food-03", u"Comment-03", 3, 3), address)
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
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        cid = hashlib.sha1("DRINK").digest()

        send = node.send_message
        create = node.create_community_metadata_message

        send(create(cid, u"Drink-01", u"Comment-01", 1, 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drink-01"
        assert tup[1] == u"Comment-01"

        send(create(cid, u"Drink-03", u"Comment-03", 3, 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drink-01"
        assert tup[1] == u"Comment-01"

        _, pckt, message = node.receive_message(addresses=[address], privileges=[node.community.get_privilege(u"dispersy-missing-sequence")])
        # must ask for missing sequence 2
        assert message.permission.payload == {"privilege":u"community-metadata", "missing_low":2, "missing_high":2, "user":node.my_member.pem}

        send(create(cid, u"Drink-02", u"Comment-02", 2, 2), address)
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
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        cid = hashlib.sha1("DRINKS").digest()

        send = node.send_message
        create = node.create_community_metadata_message

        send(create(cid, u"Drinks-01", u"Comment-01", 1, 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        send(create(cid, u"Drinks-05", u"Comment-05", 5, 5), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"

        _, pckt, message = node.receive_message(addresses=[address], privileges=[node.community.get_privilege(u"dispersy-missing-sequence")])
        # must ask for missing sequence 2, 3, and 4
        assert message.permission.payload == {"privilege":u"community-metadata", "missing_low":2, "missing_high":4, "user":node.my_member.pem}

        send(create(cid, u"Drinks-03", u"Comment-03", 3, 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"
        dprint("finished")

        send(create(cid, u"Drinks-04", u"Comment-04", 4, 4), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-01"
        assert tup[1] == u"Comment-01"
        dprint("finished")

        send(create(cid, u"Drinks-02", u"Comment-02", 2, 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM community_metadata WHERE cid = ?", (buffer(cid),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Drinks-05"
        assert tup[1] == u"Comment-05"
        dprint("finished")

    def sync(self):
        """
        We ensure that SELF has a the communities CATS and DOGS.  We
        send a dispersy-sync message with an empty bloom filter.  SELF
        should respond by offering the CATS and DOGS metadata.
        """
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member()
        node.set_community(self._discovery)
        address = self._dispersy.get_socket().get_address()

        # create CATS and DOGS communities
        messages = []
        messages.append(node.create_community_metadata_message(hashlib.sha1("CATS").digest(), u"Cat Community", u"Cat Community Comment", 1, 1))
        messages.append(node.create_community_metadata_message(hashlib.sha1("DOGS").digest(), u"Dog Community", u"Dog Community Comment", 2, 2))
        packets = [node.encode_message(message) for message in messages]
        for packet in packets:
            node.send_packet(packet, address)
            yield 0.1

        # send empty bloomfilter
        node.send_message(node.create_dispersy_sync_message([(u"community-metadata", [])], 3), address)
        yield 0.1

        # receive CATS and DOGS communities
        received = [False] * len(packets)
        while filter(lambda x: not x, received):
            _, pckt = node.receive_packet(addresses=[address], packets=packets)
            for index, packet in zip(xrange(len(packets)), packets):
                if pckt == packet:
                    received[index] = True
        
        # create = node.create_dispersy_sync_message
        # encode = node.encode_message

        # cid, alias, comment = (hashlib.sha1("CATS").digest(), u"Cat Community", u"Cat Community Comment")
        # cats_payload = encode(node.create_community_metadata_message(cid, alias, comment, 1, 1))
        # cid, alias, comment = (hashlib.sha1("DOGS").digest(), u"Dog Community", u"Dog Community Comment")
        # dogs_payload = encode(node.create_community_metadata_message(cid, alias, comment, 2, 2))
        # send(create([(u"community-metadata", [cats_payload, dogs_payload])], 2), address)

        dprint("finished")

class DiscoveryUserScript(ScriptBase):
    def run(self):
        self.caller(self.my_user_metadata)
        self.caller(self.alice)
        self.caller(self.bob)

    def my_user_metadata(self):
        my_member = self._discovery.my_member

        address = self._dispersy.get_socket().get_address()
        self._discovery.create_user_metadata(address, u"My Alias", u"My Comment")
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"My Alias"
        assert tup[1] == u"My Comment"
        dprint("finished")
        
    def alice(self):
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        node_address = node.socket.getsockname()

        send = node.send_message
        create = node.create_user_metadata_message

        send(create(node_address, u"Alice-01", u"Comment-01", 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-01"
        assert tup[1] == u"Comment-01"

        send(create(node_address, u"Alice-03", u"Comment-03", 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Alice-02", u"Comment-02", 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

    def bob(self):
        node = DiscoveryNode()
        node.init_socket()
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        node_address = node.socket.getsockname()

        send = node.send_message
        create = node.create_user_metadata_message

        send(create(node_address, u"Bob-03", u"Comment-03", 3), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Bob-01", u"Comment-01", 1), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Bob-02", u"Comment-02", 2), address)
        yield 0.1
        try:
            tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        except StopIteration:
            assert False, "Entry not found"
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

# class DiscoverScript(ScriptBase):
#     def __init__(self, *args, **kargs):
#         ScriptBase.__init__(self, *args, **kargs)

#         alias = u"Alias({0})".format(self._script)
#         address = self._dispersy.get_socket().get_address()
#         my_member = self._dispersy.get_my_member()

#         permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-01"))
#         message01 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

#         permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-02--"))
#         message02 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

#         permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-03----"))
#         message03 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

#         self._dispersy._store(message01.community.get_conversion().encode_message(message01), message01)
#         self._dispersy._store(message02.community.get_conversion().encode_message(message02), message02)
#         self._dispersy.store_and_forward([message03])
        
        

# class DiscoverStuff(ScriptBase):
#     def __init__(self, *args, **kargs):
#         ScriptBase.__init__(self, *args, **kargs)

#         alias = u"Alias({0})".format(self._script)
#         comment = u"Comment({0})".format(self._script)

#         my_member = self._dispersy.get_my_member()
#         user_metadata = self._discovery.get_user_metadata(my_member)
#         assert user_metadata.get_address() == ("", -1)
#         assert user_metadata.get_alias() == u""
#         assert user_metadata.get_comment() == u""

#         self._discovery.create_user_metadata(self._dispersy.get_socket().get_address(), alias, comment)
#         metadata = self._discovery.get_user_metadata(my_member)
#         assert user_metadata.get_address() == ("0.0.0.0", 12345)
#         assert user_metadata.get_alias() == alias
#         assert user_metadata.get_comment() == comment

        
