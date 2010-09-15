"""
Run some python code, usually to test one or more features.
"""

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
    @staticmethod
    def load(rawserver, script):
        dprint(script)
        mapping = {"discover-stuff-1":DiscoverStuff,
                   "discover-stuff-2":DiscoverStuff,
                   "discover-script":DiscoverScript,
                   "discover-node":DiscoverNode}
        if script in mapping:
            mapping[script](script, rawserver)
        else:
            raise ValueError("Unknown script '{0}'".format(script))

class ScriptBase(object):
    def __init__(self, script, rawserver):
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
                pass
            else:
                assert isinstance(delay, float)
                self._rawserver.add_task(helper, delay)

        run_generator = run()
        if isinstance(run_generator, types.GeneratorType):
            self._rawserver.add_task(helper, 0.0)

    def run():
        raise NotImplementedError("Must implement a generator")
        

class DiscoverNode(ScriptBase):
    def run(self):
        self.caller(self.my_metadata)
        self.caller(self.alice)
        self.caller(self.bob)

    def my_metadata(self):
        address = self._dispersy.get_socket().get_address()
        self._discovery.create_user_metadata(address, u"my alias", u"my comment")
        
    def alice(self):
        node = DiscoveryNode()
        node.init_socket(6661)
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        node_address = node.socket.getsockname()

        send = node.send_message
        receive = node.receive_message
        create = node.create_user_metadata_message

        send(create(node_address, u"Alice-01", u"Comment-01", 1), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Alice-01"
        assert tup[1] == u"Comment-01"

        send(create(node_address, u"Alice-03", u"Comment-03", 3), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Alice-02", u"Comment-02", 2), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Alice-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

    def bob(self):
        node = DiscoveryNode()
        node.init_socket(6662)
        node.init_my_member()
        node.set_community(self._discovery)

        address = self._dispersy.get_socket().get_address()
        node_address = node.socket.getsockname()

        send = node.send_message
        create = node.create_user_metadata_message

        send(create(node_address, u"Bob-03", u"Comment-03", 3), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Bob-01", u"Comment-01", 1), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"

        send(create(node_address, u"Bob-02", u"Comment-02", 2), address)
        yield 0.5
        tup = self._discovery_database.execute(u"SELECT alias, comment FROM user_metadata WHERE public_pem = ?", (buffer(node.my_member.pem),)).next()
        assert tup[0] == u"Bob-03"
        assert tup[1] == u"Comment-03"
        dprint("finished")

class DiscoverScript(ScriptBase):
    def __init__(self, *args, **kargs):
        ScriptBase.__init__(self, *args, **kargs)

        alias = u"Alias({0})".format(self._script)
        address = self._dispersy.get_socket().get_address()
        my_member = self._dispersy.get_my_member()

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-01"))
        message01 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-02--"))
        message02 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-03----"))
        message03 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

        self._dispersy._store(message01.community.get_conversion().encode_message(message01), message01)
        self._dispersy._store(message02.community.get_conversion().encode_message(message02), message02)
        self._dispersy.store_and_forward([message03])
        
        

class DiscoverStuff(ScriptBase):
    def __init__(self, *args, **kargs):
        ScriptBase.__init__(self, *args, **kargs)

        alias = u"Alias({0})".format(self._script)
        comment = u"Comment({0})".format(self._script)

        my_member = self._dispersy.get_my_member()
        user_metadata = self._discovery.get_user_metadata(my_member)
        assert user_metadata.get_address() == ("", -1)
        assert user_metadata.get_alias() == u""
        assert user_metadata.get_comment() == u""

        self._discovery.create_user_metadata(self._dispersy.get_socket().get_address(), alias, comment)
        metadata = self._discovery.get_user_metadata(my_member)
        assert user_metadata.get_address() == ("0.0.0.0", 12345)
        assert user_metadata.get_alias() == alias
        assert user_metadata.get_comment() == comment

        
