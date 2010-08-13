"""
Run some python code, usually to test one or more features.
"""

from Tribler.Community.Discovery.Discovery import DiscoveryCommunity
from Tribler.Community.Discovery.DiscoveryDatabase import DiscoveryDatabase
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Permission import PermitPermission
from Message import LastSyncDistribution
from Print import dprint

class Script(object):
    @staticmethod
    def load(rawserver, script):
        dprint(script)
        mapping = {"discover-stuff-1":DiscoverStuff,
                   "discover-stuff-2":DiscoverStuff,
                   "discover-script":DiscoverScript}
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
        self._discovery_database = DispersyDatabase.get_instance()

class DiscoverScript(ScriptBase):
    def __init__(self, *args, **kargs):
        ScriptBase.__init__(self, *args, **kargs)

        alias = u"Alias({0})".format(self._script)
        address = self._dispersy.get_socket().get_address()
        my_member = self._dispersy.get_my_member()

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-01"))
        message01 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-02"))
        message02 = self._discovery.permit(permission, LastSyncDistribution, update_locally=False, store_and_forward=False)

        permission = PermitPermission(self._discovery.get_privilege(u"user-metadata"), (address, alias, u"Comment-03"))
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

        
