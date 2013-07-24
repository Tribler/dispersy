from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestMemberTag(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_ignore_test(self):
        """
        Test the must_ignore = True feature.

        When we ignore a specific member we will still accept messages from that member and store
        them in our database.  However, the GUI may choose not to display any messages from them.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        self.assertEqual(community.fetch_packets(meta.name), [])

        # send a message
        global_time = 10
        messages = []
        messages.append(node.give_message(node.create_full_sync_text("should be accepted (1)", global_time)))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # we now tag the member as ignore
        self._dispersy.get_member(node.my_member.public_key).must_ignore = True

        tags, = self._dispersy.database.execute(u"SELECT tags FROM member WHERE id = ?", (node.my_member.database_id,)).next()
        self.assertIn(u"ignore", tags.split(","))

        # send a message and ensure it is in the database (ignore still means it must be stored in
        # the database)
        global_time = 20
        messages.append(node.give_message(node.create_full_sync_text("should be accepted (2)", global_time)))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # we now tag the member not to ignore
        self._dispersy.get_member(node.my_member.public_key).must_ignore = False

        # send a message
        global_time = 30
        messages.append(node.give_message(node.create_full_sync_text("should be accepted (3)", global_time)))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_blacklist_test(self):
        """
        Test the must_blacklist = True feature.

        When we 'blacklist' a specific member we will no longer accept or store messages from that
        member.  No callback will be given to the community code.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        self.assertEqual(community.fetch_packets(meta.name), [])

        # send a message
        global_time = 10
        messages = []
        messages.append(node.give_message(node.create_full_sync_text("should be accepted (1)", global_time)))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # we now tag the member as blacklist
        self._dispersy.get_member(node.my_member.public_key).must_blacklist = True

        tags, = self._dispersy.database.execute(u"SELECT tags FROM member WHERE id = ?", (node.my_member.database_id,)).next()
        self.assertIn(u"blacklist", tags.split(","))

        # send a message and ensure it is not in the database
        global_time = 20
        node.give_message(node.create_full_sync_text("should NOT be accepted (2)", global_time))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # we now tag the member not to blacklist
        self._dispersy.get_member(node.my_member.public_key).must_blacklist = False

        # send a message
        global_time = 30
        messages.append(node.give_message(node.create_full_sync_text("should be accepted (3)", global_time)))
        self.assertEqual([message.packet for message in messages], community.fetch_packets(meta.name))

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
