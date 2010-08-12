"""
Run some python code, usually to test one or more features.
"""

from Tribler.Community.Discovery.Discovery import DiscoveryCommunity
from Tribler.Community.Discovery.DiscoveryDatabase import DiscoveryDatabase
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Print import dprint

class Script(object):
    @staticmethod
    def load(rawserver, script):
        dprint(script)
        mapping = {"discover-stuff":DiscoverStuff}
        if script in mapping:
            mapping[script](rawserver)
        else:
            raise ValueError("Unknown script '{0}'".format(script))

class ScriptBase(object):
    def __init__(self, rawserver):
        self._rawserver = rawserver
        self._dispersy = Dispersy.get_instance()
        self._dispersy_database = DispersyDatabase.get_instance()
        self._discovery = DiscoveryCommunity.get_instance()
        self._discovery_database = DispersyDatabase.get_instance()
        
class DiscoverStuff(ScriptBase):
    def __init__(self, *args, **kargs):
        ScriptBase.__init__(self, *args, **kargs)

        my_member = self._dispersy.get_my_member()
        user_metadata = self._discovery.get_user_metadata(my_member)
        assert user_metadata.get_address() == ("", -1)
        assert user_metadata.get_alias() == u""
        assert user_metadata.get_comment() == u""

        self._discovery.create_user_metadata(self._dispersy.get_socket().get_address(), u"Alice", u"Hello everyone, I am Alice")
        metadata = self._discovery.get_user_metadata(my_member)
        assert user_metadata.get_address() == ("0.0.0.0", 12345)
        assert user_metadata.get_alias() == u"Alice"
        assert user_metadata.get_comment() == u"Hello everyone, I am Alice"

        
