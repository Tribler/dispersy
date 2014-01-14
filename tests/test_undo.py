from ..logger import get_logger
from ..message import Message
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestUndo(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_self_undo_own(self):
        """
        SELF generates a few messages and then undoes them.

        This is always allowed.  In fact, no check is made since only externally received packets
        will be checked.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create messages
        messages = [community.create_full_sync_text("Should undo #%d" % i, forward=False) for i in xrange(10)]

        # check that they are in the database and are NOT undone
        for message in messages:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, community.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # undo all messages
        undoes = [community.create_undo(message, forward=False) for message in messages]

        # check that they are in the database and ARE undone
        for undo, message in zip(undoes, messages):
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, community.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(undo.packet_id,)])

        # check that all the undo messages are in the database and are NOT undone
        for message in undoes:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, community.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # cleanup
        community.create_destroy_community(u"hard-kill", forward=False)
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_self_undo_other(self):
        """
        NODE generates a few messages and then SELF undoes them.

        This is always allowed.  In fact, no check is made since only externally received packets
        will be checked.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # NODE creates messages
        messages = [node.create_full_sync_text("Should undo #%d" % global_time, global_time) for global_time in xrange(10, 20)]
        node.give_messages(messages)

        # check that they are in the database and are NOT undone
        for message in messages:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # SELF undoes all messages
        undoes = [community.create_undo(message, forward=False) for message in messages]

        # check that they are in the database and ARE undone
        for undo, message in zip(undoes, messages):
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(undo.packet_id,)])

        # check that all the undo messages are in the database and are NOT undone
        for message in undoes:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, community.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # cleanup
        community.create_destroy_community(u"hard-kill", forward=False)
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_node_undo_own(self):
        """
        SELF gives NODE permission to undo, NODE generates a few messages and then undoes them.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF grants undo permission to NODE
        community.create_authorize([(node.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # create messages
        messages = [node.create_full_sync_text("Should undo @%d" % global_time, global_time) for global_time in xrange(10, 20)]
        node.give_messages(messages)

        # check that they are in the database and are NOT undone
        for message in messages:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # undo all messages
        sequence_number = 1
        undoes = [node.create_dispersy_undo_own(message, message.distribution.global_time + 100, sequence_number + i) for i, message in enumerate(messages)]
        node.give_messages(undoes)

        # check that they are in the database and ARE undone
        for undo, message in zip(undoes, messages):
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(len(undone), 1)
            undone_packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE id = ?", (undone[0][0],)).next()
            undone_packet = str(undone_packet)
            self.assertEqual(undo.packet, undone_packet)

        # check that all the undo messages are in the database and are NOT undone
        for message in undoes:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_node_undo_other(self):
        """
        SELF gives NODE1 permission to undo, NODE2 generates a few messages and then NODE1 undoes
        them.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node1 = DebugNode(community)
        node1.init_socket()
        node1.init_my_member()

        node2 = DebugNode(community)
        node2.init_socket()
        node2.init_my_member()

        # SELF grants undo permission to NODE1
        community.create_authorize([(node1.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # NODE2 creates messages
        messages = [node2.create_full_sync_text("Should undo @%d" % global_time, global_time) for global_time in xrange(10, 20)]
        node2.give_messages(messages)

        # check that they are in the database and are NOT undone
        for message in messages:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node2.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # NODE1 undoes all messages
        sequence_number = 1
        undoes = [node1.create_dispersy_undo_other(message, message.distribution.global_time + 100, sequence_number + i) for i, message in enumerate(messages)]
        node1.give_messages(undoes)

        # check that they are in the database and ARE undone
        for undo, message in zip(undoes, messages):
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node2.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(len(undone), 1)
            undone_packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE id = ?", (undone[0][0],)).next()
            undone_packet = str(undone_packet)
            self.assertEqual(undo.packet.encode("HEX"), undone_packet.encode("HEX"))

        # check that all the undo messages are in the database and are NOT undone
        for message in undoes:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node1.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_self_malicious_undo(self):
        """
        SELF generated a message and then undoes it twice.  The dispersy core should ensure that
        (given that the message was processed, hence update=True) that the second undo is refused
        and the first undo should be returned instead.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create message
        message = community.create_full_sync_text("Should undo")

        # undo once
        undo1 = community.create_undo(message)
        self.assertIsInstance(undo1, Message.Implementation)

        # undo twice.  instead of a new dispersy-undo, a new instance of the previous UNDO1 must be
        # returned
        undo2 = community.create_undo(message)
        self.assertEqual(undo1.packet, undo2.packet)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_node_malicious_undo(self):
        """
        SELF gives NODE permission to undo, NODE generates a message and then undoes it twice.  The
        second undo can cause nodes to keep syncing packets that other nodes will keep dropping
        (because you can only drop a message once, but the two messages are binary unique).

        Sending two undoes for the same message is considered malicious behavior, resulting in:
         1. the offending node must be put on the blacklist
         2. the proof of malicious behaviour must be forwarded to other nodes
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF grants undo permission to NODE
        community.create_authorize([(node.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # create message
        global_time = 10
        message = node.create_full_sync_text("Should undo @%d" % global_time, global_time)
        node.give_message(message)

        # undo once
        global_time = 20
        sequence_number = 1
        undo1 = node.create_dispersy_undo_own(message, global_time, sequence_number)
        node.give_message(undo1)

        # undo twice
        global_time = 30
        sequence_number = 2
        undo2 = node.create_dispersy_undo_own(message, global_time, sequence_number)
        node.give_message(undo2)
        yield 0.1

        # check that the member is declared malicious
        self.assertTrue(self._dispersy.get_member(node.my_member.public_key).must_blacklist)

        # all messages for the malicious member must be removed
        packets = list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ?",
                                                       (community.database_id, node.my_member.database_id)))
        self.assertEqual(packets, [])

        node2 = DebugNode(community)

        node2.init_socket()
        node2.init_my_member()

        # ensure we don't obtain the messages from the socket cache
        yield 0.1
        node2.drop_packets()

        # propagate a message from the malicious member
        logger.debug("giving faulty message %s", message)
        node2.give_message(message)
        yield 0.1

        # we should receive proof that NODE is malicious
        malicious_packets = [packet for _, packet in node2.receive_packets()]
        self.assertEqual(sorted(malicious_packets), sorted([undo1.packet, undo2.packet]))

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_node_non_malicious_undo(self):
        """
        SELF gives NODE permission to undo, NODE generates a message, SELF generates an undo, NODE
        generates an undo.  The second undo should NOT cause NODE of SELF to be marked as malicious.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF grants undo permission to NODE
        community.create_authorize([(node.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # create message
        global_time = 10
        message = node.create_full_sync_text("Should undo @%d" % global_time, global_time)
        node.give_message(message)

        # SELF undoes
        community.create_undo(message)

        # NODE undoes
        global_time = 30
        sequence_number = 1
        undo = node.create_dispersy_undo_own(message, global_time, sequence_number)
        node.give_message(undo)

        # check that they are in the database and ARE undone
        undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                      (community.database_id, message.authentication.member.database_id, message.distribution.global_time)))
        self.assertEqual(len(undone), 1)
        undone_packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE id = ?", (undone[0][0],)).next()
        undone_packet = str(undone_packet)
        self.assertEqual(undo.packet, undone_packet)

        # check that the member is not declared malicious
        self.assertFalse(self._dispersy.get_member(node.my_member.public_key).must_blacklist)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_missing_message(self):
        """
        SELF gives NODE permission to undo, NODE generates a few messages without sending them to
        SELF.  Following, NODE undoes the messages and sends the undo messages to SELF.  SELF must
        now use a dispersy-missing-message to request the messages that are about to be undone.  The
        messages need to be processed and subsequently undone.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF grants undo permission to NODE
        community.create_authorize([(node.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # create messages
        messages = [node.create_full_sync_text("Should undo @%d" % global_time, global_time) for global_time in xrange(10, 20)]

        # undo all messages
        sequence_number = 1
        undoes = [node.create_dispersy_undo_own(message, message.distribution.global_time + 100, i + sequence_number) for i, message in enumerate(messages)]
        node.give_messages(undoes)

        # receive the dispersy-missing-message messages
        global_times = [message.distribution.global_time for message in messages]
        global_time_requests = []
        for _ in xrange(len(messages)):
            _, message = node.receive_message(message_names=[u"dispersy-missing-message"])
            self.assertEqual(message.payload.member.public_key, node.my_member.public_key)
            global_time_requests.extend(message.payload.global_times)
        self.assertEqual(sorted(global_times), sorted(global_time_requests))

        # give all 'delayed' messages
        node.give_messages(messages)

        yield sum(community.get_meta_message(name).batch.max_window for name in [u"full-sync-text", u"dispersy-undo-own", u"dispersy-undo-other"])
        yield 2.0

        # check that they are in the database and ARE undone
        for undo, message in zip(undoes, messages):
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(len(undone), 1)
            undone_packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE id = ?", (undone[0][0],)).next()
            undone_packet = str(undone_packet)
            self.assertEqual(undo.packet, undone_packet)

        # check that all the undo messages are in the database and are NOT undone
        for message in undoes:
            undone = list(self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                          (community.database_id, node.my_member.database_id, message.distribution.global_time)))
            self.assertEqual(undone, [(0,)])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_revoke_simple(self):
        """
        SELF gives NODE1 permission to undo, SELF revokes this permission.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node1 = DebugNode(community)
        node1.init_socket()
        node1.init_my_member()

        # SELF grants undo permission to NODE1
        community.create_authorize([(node1.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # SELF revoke undo permission from NODE1
        community.create_revoke([(node1.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_revoke_causing_undo(self):
        """
        SELF gives NODE1 permission to undo, SELF created a message, NODE1 undoes the message, SELF
        revokes the undo permission AFTER the message was undone -> the message is not re-done.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node1 = DebugNode(community)
        node1.init_socket()
        node1.init_my_member()

        # SELF grants undo permission to NODE1
        community.create_authorize([(node1.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])

        # SELF creates a message
        message = community.create_full_sync_text("will be undone")
        self.assert_message_stored(community, community.my_member, message.distribution.global_time)

        # NODE1 undoes the message
        sequence_number = 1
        node1.give_message(node1.create_dispersy_undo_other(message, message.distribution.global_time + 1, sequence_number))
        self.assert_message_stored(community, community.my_member, message.distribution.global_time, undone="undone")

        # SELF revoke undo permission from NODE1
        community.create_revoke([(node1.my_member, community.get_meta_message(u"full-sync-text"), u"undo")])
        self.assert_message_stored(community, community.my_member, message.distribution.global_time, undone="undone")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    def assert_message_stored(self, community, member, global_time, undone="done"):
        self.assertIsInstance(undone, str)
        self.assertIn(undone, ("done", "undone"))

        try:
            actual_undone, = community.dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?", (community.database_id, member.database_id, global_time)).next()
        except StopIteration:
            self.fail("Message must be stored in the database")

        self.assertIsInstance(actual_undone, int)
        self.assertGreaterEqual(actual_undone, 0)
        self.assertTrue((undone == "done" and actual_undone == 0) or undone == "undone" and 0 < actual_undone,)
