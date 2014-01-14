import gc
import inspect
import unittest

from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestClassification(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_reclassify_unloaded_community(self):
        """
        Load a community, reclassify it, load all communities of that classification to check.
        """
        class ClassTestA(DebugCommunity):
            pass

        class ClassTestB(DebugCommunity):
            pass

        # no communities should exist
        self.assertEqual([ClassTestA.load_community(self._dispersy, master) for master in ClassTestA.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")
        self.assertEqual([ClassTestB.load_community(self._dispersy, master) for master in ClassTestB.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")

        # create master member
        master = self._dispersy.get_new_member(u"high")

        # create community
        self._dispersy.database.execute(u"INSERT INTO community (master, member, classification) VALUES (?, ?, ?)",
                                        (master.database_id, self._my_member.database_id, ClassTestA.get_classification()))

        # reclassify
        community = self._dispersy.reclassify_community(master, ClassTestB)
        self.assertIsInstance(community, ClassTestB)
        self.assertEqual(community.cid, master.mid)
        try:
            classification, = self._dispersy.database.execute(u"SELECT classification FROM community WHERE master = ?", (master.database_id,)).next()
        except StopIteration:
            self.fail()
        self.assertEqual(classification, ClassTestB.get_classification())

        # cleanup
        community.unload_community()

    @call_on_dispersy_thread
    def test_reclassify_loaded_community(self):
        """
        Load a community, reclassify it, load all communities of that classification to check.
        """
        class ClassTestC(DebugCommunity):
            pass

        class ClassTestD(DebugCommunity):
            pass

        # no communities should exist
        self.assertEqual([ClassTestC.load_community(self._dispersy, master) for master in ClassTestC.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")
        self.assertEqual([ClassTestD.load_community(self._dispersy, master) for master in ClassTestD.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")

        # create community
        community_c = ClassTestC.create_community(self._dispersy, self._my_member)
        self.assertEqual(len(list(self._dispersy.database.execute(u"SELECT * FROM community WHERE classification = ?", (ClassTestC.get_classification(),)))), 1)

        # reclassify
        community_d = self._dispersy.reclassify_community(community_c, ClassTestD)
        self.assertIsInstance(community_d, ClassTestD)
        self.assertEqual(community_c.cid, community_d.cid)
        try:
            classification, = self._dispersy.database.execute(u"SELECT classification FROM community WHERE master = ?", (community_c.master_member.database_id,)).next()
        except StopIteration:
            self.fail()
        self.assertEqual(classification, ClassTestD.get_classification())

        # cleanup
        community_d.unload_community()

    @call_on_dispersy_thread
    def test_load_no_communities(self):
        """
        Try to load communities of a certain classification while there are no such communities.
        """
        class ClassificationLoadNoCommunities(DebugCommunity):
            pass
        self.assertEqual([ClassificationLoadNoCommunities.load_community(self._dispersy, master) for master in ClassificationLoadNoCommunities.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")

    @call_on_dispersy_thread
    def test_load_one_communities(self):
        """
        Try to load communities of a certain classification while there is exactly one such
        community available.
        """
        class ClassificationLoadOneCommunities(DebugCommunity):
            pass

        # no communities should exist
        self.assertEqual([ClassificationLoadOneCommunities.load_community(self._dispersy, master) for master in ClassificationLoadOneCommunities.get_master_members(self._dispersy)], [], "Did you remove the database before running this testcase?")

        # create master member
        master = self._dispersy.get_new_member(u"high")

        # create one community
        self._dispersy.database.execute(u"INSERT INTO community (master, member, classification) VALUES (?, ?, ?)",
                                        (master.database_id, self._my_member.database_id, ClassificationLoadOneCommunities.get_classification()))

        # load one community
        communities = [ClassificationLoadOneCommunities.load_community(self._dispersy, master) for master in ClassificationLoadOneCommunities.get_master_members(self._dispersy)]
        self.assertEqual(len(communities), 1)
        self.assertIsInstance(communities[0], ClassificationLoadOneCommunities)

        # cleanup
        communities[0].unload_community()

    @call_on_dispersy_thread
    def test_load_two_communities(self):
        """
        Try to load communities of a certain classification while there is exactly two such
        community available.
        """
        class LoadTwoCommunities(DebugCommunity):
            pass

        # no communities should exist
        self.assertEqual([LoadTwoCommunities.load_community(self._dispersy, master) for master in LoadTwoCommunities.get_master_members(self._dispersy)], [])

        masters = []
        # create two communities
        community = LoadTwoCommunities.create_community(self._dispersy, self._my_member)
        masters.append(community.master_member.public_key)
        community.unload_community()

        community = LoadTwoCommunities.create_community(self._dispersy, self._my_member)
        masters.append(community.master_member.public_key)
        community.unload_community()

        # load two communities
        self.assertEqual(sorted(masters), sorted(master.public_key for master in LoadTwoCommunities.get_master_members(self._dispersy)))
        communities = [LoadTwoCommunities.load_community(self._dispersy, master) for master in LoadTwoCommunities.get_master_members(self._dispersy)]
        self.assertEqual(sorted(masters), sorted(community.master_member.public_key for community in communities))
        self.assertEqual(len(communities), 2)
        self.assertIsInstance(communities[0], LoadTwoCommunities)
        self.assertIsInstance(communities[1], LoadTwoCommunities)

        # cleanup
        communities[0].unload_community()
        communities[1].unload_community()

    @unittest.skip("nosetests uses BufferingHandler to capture output.  This handler keeps references to the community, breaking this test.  Run nosetests --nologcapture --no-skip")
    @call_on_dispersy_thread
    def test_unloading_community(self):
        """
        Test that calling community.unload_community() eventually results in a call to
        community.__del__().
        """
        class ClassificationUnloadingCommunity(DebugCommunity):
            pass

        def check(verbose=False):
            # using a function to ensure all local variables are removed (scoping)

            i = 0
            j = 0
            for x in gc.get_objects():
                if isinstance(x, ClassificationUnloadingCommunity):
                    i += 1
                    for obj in gc.get_referrers(x):
                        j += 1
                        if verbose:
                            logger.debug("%s", str(type(obj)))
                            try:
                                lines, lineno = inspect.getsourcelines(obj)
                                logger.debug("Check %d %s", j, [line.rstrip() for line in lines])
                            except TypeError:
                                logger.debug("TypeError")

            logger.debug("%d referrers", j)
            return i

        community = ClassificationUnloadingCommunity.create_community(self._dispersy, self._my_member)
        master = community.master_member
        cid = community.cid
        del community
        self.assertIsInstance(self._dispersy.get_community(cid), ClassificationUnloadingCommunity)
        self.assertEqual(check(), 1)

        # unload the community
        self._dispersy.get_community(cid).unload_community()
        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except KeyError:
            pass

        # must be garbage collected
        wait = 10
        for i in range(wait):
            gc.collect()
            logger.debug("waiting... %d", wait - i)
            if check() == 0:
                break
            else:
                yield 1.0
        self.assertEqual(check(True), 0)

        # load the community for cleanup
        community = ClassificationUnloadingCommunity.load_community(self._dispersy, master)
        self.assertEqual(check(), 1)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_enable_autoload(self):
        """
        Test enable autoload.

        - Create community
        - Enable auto-load (should be enabled by default)
        - Define auto load
        - Unload community
        - Send community message
        - Verify that the community got auto-loaded
        - Undefine auto load
        """
        # create community
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        cid = community.cid
        message = community.get_meta_message(u"full-sync-text")

        # create node
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False)
        yield 0.555

        logger.debug("verify auto-load is enabled (default)")
        self.assertTrue(community.dispersy_auto_load)
        yield 0.555

        logger.debug("define auto load")
        self._dispersy.define_auto_load(DebugCommunity)
        yield 0.555

        logger.debug("create wake-up message")
        global_time = 10
        wakeup = node.encode_message(node.create_full_sync_text("Should auto-load", global_time))

        logger.debug("unload community")
        community.unload_community()
        community = None
        node.set_community(None)
        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except KeyError:
            pass
        yield 0.555

        logger.debug("send community message")
        node.give_packet(wakeup)
        yield 0.555

        logger.debug("verify that the community got auto-loaded")
        try:
            community = self._dispersy.get_community(cid)
        except KeyError:
            self.fail()
        # verify that the message was received
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertIn(global_time, times)
        yield 0.555

        logger.debug("undefine auto load")
        self._dispersy.undefine_auto_load(DebugCommunity)
        yield 0.555

        logger.debug("cleanup")
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_enable_disable_autoload(self):
        """
        Test enable disable autoload.

        - Create community
        - Enable auto-load (should be enabled by default)
        - Define auto load
        - Unload community
        - Send community message
        - Verify that the community got auto-loaded
        - Disable auto-load
        - Send community message
        - Verify that the community did NOT get auto-loaded
        - Undefine auto load
        """
        # create community
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        cid = community.cid
        community_database_id = community.database_id
        master_member = community.master_member
        message = community.get_meta_message(u"full-sync-text")

        # create node
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False)

        logger.debug("verify auto-load is enabled (default)")
        self.assertTrue(community.dispersy_auto_load)

        logger.debug("define auto load")
        self._dispersy.define_auto_load(DebugCommunity)

        logger.debug("create wake-up message")
        global_time = 10
        wakeup = node.encode_message(node.create_full_sync_text("Should auto-load", global_time))

        logger.debug("unload community")
        community.unload_community()
        community = None
        node.set_community(None)
        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except KeyError:
            pass

        logger.debug("send community message")
        node.give_packet(wakeup)

        logger.debug("verify that the community got auto-loaded")
        try:
            community = self._dispersy.get_community(cid)
        except KeyError:
            self.fail()
        # verify that the message was received
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertIn(global_time, times)

        logger.debug("disable auto-load")
        community.dispersy_auto_load = False
        self.assertFalse(community.dispersy_auto_load)

        logger.debug("create wake-up message")
        node.set_community(community)
        global_time = 11
        wakeup = node.encode_message(node.create_full_sync_text("Should auto-load", global_time))

        logger.debug("unload community")
        community.unload_community()
        community = None
        node.set_community(None)
        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except KeyError:
            pass

        logger.debug("send community message")
        node.give_packet(wakeup)

        logger.debug("verify that the community did not get auto-loaded")
        try:
            self._dispersy.get_community(cid, auto_load=False)
            self.fail()
        except KeyError:
            pass
        # verify that the message was NOT received
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community_database_id, node.my_member.database_id, message.database_id))]
        self.assertNotIn(global_time, times)

        logger.debug("undefine auto load")
        self._dispersy.undefine_auto_load(DebugCommunity)

        logger.debug("cleanup")
        community = DebugCommunity.load_community(self._dispersy, master_member)
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
