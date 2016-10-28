from twisted.internet.defer import inlineCallbacks
from ..exception import CommunityNotFoundException
from ..util import call_on_reactor_thread
from .debugcommunity.community import DebugCommunity
from .dispersytestclass import DispersyTestFunc


class TestClassification(DispersyTestFunc):

    @call_on_reactor_thread
    @inlineCallbacks
    def test_reclassify_unloaded_community(self):
        """
        Load a community, reclassify it, load all communities of that classification to check.
        """
        class ClassTestA(DebugCommunity):
            pass

        class ClassTestB(DebugCommunity):
            pass

        # create master member
        master = self._dispersy.get_new_member(u"high")

        # create community
        self._dispersy.database.execute(u"INSERT INTO community (master, member, classification) VALUES (?, ?, ?)",
                                        (master.database_id, self._mm.my_member.database_id, ClassTestA.get_classification()))

        # reclassify
        community = yield self._dispersy.reclassify_community(master, ClassTestB)
        self.assertIsInstance(community, ClassTestB)
        self.assertEqual(community.cid, master.mid)
        try:
            classification, = self._dispersy.database.execute(u"SELECT classification FROM community WHERE master = ?",
                                                              (master.database_id,)).next()
        except StopIteration:
            self.fail()
        self.assertEqual(classification, ClassTestB.get_classification())

    @call_on_reactor_thread
    @inlineCallbacks
    def test_reclassify_loaded_community(self):
        """
        Load a community, reclassify it, load all communities of that classification to check.
        """
        class ClassTestC(DebugCommunity):
            pass

        class ClassTestD(DebugCommunity):
            pass

        # create community
        community_c = ClassTestC.create_community(self._dispersy, self._mm._my_member)
        self.assertEqual(len(list(self._dispersy.database.execute(u"SELECT * FROM community WHERE classification = ?",
                                                                  (ClassTestC.get_classification(),)))), 1)

        # reclassify
        community_d = yield self._dispersy.reclassify_community(community_c, ClassTestD)
        self.assertIsInstance(community_d, ClassTestD)
        self.assertEqual(community_c.cid, community_d.cid)

        try:
            classification, = self._dispersy.database.execute(u"SELECT classification FROM community WHERE master = ?",
                                                              (community_c.master_member.database_id,)).next()
        except StopIteration:
            self.fail()
        self.assertEqual(classification, ClassTestD.get_classification())

    @call_on_reactor_thread
    def test_load_one_communities(self):
        """
        Try to load communities of a certain classification while there is exactly one such
        community available.
        """
        class ClassificationLoadOneCommunities(DebugCommunity):
            pass

        # create master member
        master = self._dispersy.get_new_member(u"high")

        # create one community
        self._dispersy.database.execute(u"INSERT INTO community (master, member, classification) VALUES (?, ?, ?)",
                                        (master.database_id, self._mm._my_member.database_id, ClassificationLoadOneCommunities.get_classification()))

        # load one community
        communities = [ClassificationLoadOneCommunities(self._dispersy, master, self._mm._my_member)
                       for master in ClassificationLoadOneCommunities.get_master_members(self._dispersy)]
        self.assertEqual(len(communities), 1)
        self.assertIsInstance(communities[0], ClassificationLoadOneCommunities)

    @call_on_reactor_thread
    @inlineCallbacks
    def test_load_two_communities(self):
        """
        Try to load communities of a certain classification while there is exactly two such
        community available.
        """
        class LoadTwoCommunities(DebugCommunity):
            pass

        masters = []
        # create two communities
        community = LoadTwoCommunities.create_community(self._dispersy, self._mm.my_member)
        masters.append(community.master_member.public_key)
        yield community.unload_community()

        community = LoadTwoCommunities.create_community(self._dispersy, self._mm.my_member)
        masters.append(community.master_member.public_key)
        yield community.unload_community()

        # load two communities
        self.assertEqual(sorted(masters), sorted(master.public_key
                                                 for master in LoadTwoCommunities.get_master_members(self._dispersy)))
        communities = [LoadTwoCommunities(self._dispersy, master, self._mm._my_member)
                       for master in LoadTwoCommunities.get_master_members(self._dispersy)]

        self.assertEqual(sorted(masters), sorted(community.master_member.public_key for community in communities))
        self.assertEqual(len(communities), 2)
        self.assertIsInstance(communities[0], LoadTwoCommunities)
        self.assertIsInstance(communities[1], LoadTwoCommunities)

    @call_on_reactor_thread
    def test_enable_autoload(self, auto_load=True):
        """
        Test enable autoload.

        - Create community
        - Enable auto-load (should be enabled by default)
        - Define auto load
        - Unload community
        - Send community message
        - Verify that the community got auto-loaded
        """
        # create community
        cid = self._community.cid
        my_member = self._community.my_member

        # verify auto-load is enabled (default)
        self._community.dispersy_auto_load = auto_load
        self.assertEqual(self._community.dispersy_auto_load, auto_load)

        if auto_load:
            # define auto load
            self._dispersy.define_auto_load(DebugCommunity, my_member)

        # create wake-up message
        wakeup = self._mm.create_full_sync_text("Should auto-load", 42)

        # unload community
        yield self._community.unload_community()

        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except CommunityNotFoundException:
            pass

        # send wakeup message
        self._mm.give_message(wakeup, self._mm)

        yield 0.11

        # verify that the community got auto-loaded
        try:
            _ = self._dispersy.get_community(cid, auto_load=False)

            if not auto_load:
                self.fail('Should not have been loaded by wakeup message')
        except CommunityNotFoundException:
            if auto_load:
                self.fail('Should have been loaded by wakeup message')

        # verify that the message was received
        self._mm.assert_count(wakeup, 1 if auto_load else 0)

    def test_enable_disable_autoload(self):
        self.test_enable_autoload(False)
