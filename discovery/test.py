from Tribler.dispersy.community import Community
from Tribler.community.privatesemantic.community import DiscoveryCommunity


class NoFSemanticCommunity(DiscoveryCommunity, Community):

    @classmethod
    def load_community(cls, dispersy, master, my_member, max_prefs=None):
        dispersy_database = dispersy.database
        try:
            dispersy_database.execute(u"SELECT 1 FROM community WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            return cls.join_community(dispersy, master, my_member, my_member, max_prefs=max_prefs)
        else:
            return super(DiscoveryCommunity, cls).load_community(dispersy, master, max_prefs=max_prefs)

    def __init__(self, dispersy, master, max_prefs=None):
        Community.__init__(self, dispersy, master)
        DiscoveryCommunity.__init__(self, dispersy, master, max_prefs)

    def initiate_conversions(self):
        return DiscoveryCommunity.initiate_conversions(self)

    def initiate_meta_messages(self):
        return DiscoveryCommunity.initiate_meta_messages(self)

    def unload_community(self):
        DiscoveryCommunity.unload_community(self)
        Community.unload_community(self)
