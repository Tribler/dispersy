from ..logger import get_logger
from ..message import Message
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)

from unittest.case import skip

class TestUndo(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_self_undo_own(self):
        """
        NODE generates a few messages and then undoes them.

        This is always allowed.  In fact, no check is made since only externally received packets
        will be checked.
        """

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        # create messages
        messages = [node.create_full_sync_text("Should undo #%d" % i, i + 10) for i in xrange(10)]
        node.give_messages(messages, node)

        # check that they are in the database and are NOT undone
        self.assert_is_stored(messages=messages)

        # undo all messages
        undoes = [node.create_dispersy_undo_own(message, i + 100, i + 1) for i, message in enumerate(messages)]

        node.give_messages(undoes, node)

        # check that they are in the database and ARE undone
        self.assert_is_undone(messages=messages)
        self.assert_is_stored(messages=undoes)

    @call_on_dispersy_thread
    def test_self_undo_other(self):
        """
        NODE generates a few messages and then MM undoes them.

        This is always allowed.  In fact, no check is made since only externally received packets
        will be checked.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        # create messages
        messages = [node.create_full_sync_text("Should undo #%d" % i, i + 10) for i in xrange(10)]
        node.give_messages(messages, node)

        # check that they are in the database and are NOT undone
        self.assert_is_stored(messages=messages)

        # MM undoes all messages
        undoes = [self._community.create_undo(message, forward=False) for message in messages]
        node.give_messages(undoes, node)

        # check that they are in the database and ARE undone
        self.assert_is_undone(messages=messages)
        self.assert_is_stored(messages=undoes)

    @call_on_dispersy_thread
    def test_node_undo_other(self):
        """
        SELF gives NODE permission to undo, OTHER generates a few messages and then NODE undoes
        them.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # SELF grants undo permission to NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

        # OTHER creates messages
        messages = [other.create_full_sync_text("Should undo #%d" % i, i + 10) for i in xrange(10)]
        self._dispersy._store(messages)

        # check that they are in the database and are NOT undone
        self.assert_is_stored(messages=messages)

        # NODE undoes all messages
        undoes = [node.create_dispersy_undo_other(message, message.distribution.global_time + 100, 1 + i) for i, message in enumerate(messages)]
        node.give_messages(undoes, node)

        # check that they are in the database and ARE undone
        self.assert_is_undone(messages=messages)
        self.assert_is_stored(messages=undoes)

    @skip("TODO: niels")
    @call_on_dispersy_thread
    def test_self_attempt_undo_twice(self):
        """
        NODE generated a message and then undoes it twice. The dispersy core should ensure that
        that the second undo is refused and the first undo message should be returned instead.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        # create message
        message = node.create_full_sync_text("Should undo @%d" % 1, 1)
        self._dispersy._store([message])

        # undo once
        undo1 = node._community.create_undo(message)
        self.assertIsInstance(undo1, Message.Implementation)

        # attempt to undo for the second time
        undo2 = node._community.create_undo(message)
        self.assertIsInstance(undo2, Message.Implementation)
        self.assertEqual(undo1.packet, undo2.packet)

    @call_on_dispersy_thread
    def test_node_resolve_undo_twice(self):
        """
        Make sure that in the event of receiving two undo messages from the same member, only the highest one will be kept,
        and in case of receiving a lower one, that we will send the higher one back to the sender.

        SELF gives NODE permission to undo, NODE generates a message and then undoes it twice.  Only one of the two undo messages should be kept.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # SELF grants undo permission to NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

        # create message
        message = node.create_full_sync_text("Should undo @%d" % 10, 10)
        node.give_message(message, node)

        # undo once
        undo1 = node.create_dispersy_undo_own(message, 11, 1)
        node.give_message(undo1, node)

        # undo twice
        undo2 = node.create_dispersy_undo_own(message, 12, 2)
        node.give_message(undo2, node)

        # Only one of the packets should be on the DB (+ identity message and the full-sync-text) = 3
        packets = list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ?",
                                                       (self._community.database_id, node.my_member.database_id)))
        self.assertEqual(len(packets), 3)


        low_message, high_message = sorted([undo1, undo2], key=lambda message: message.packet)
        other.give_message(message, node)
        other.give_message(high_message, node)
        other.give_message(low_message, node)

        # OTHER should send the first message back when receiving the second one (its "higher" than the one just received)
        undo_packets = [packet for _, packet in node.receive_packets()]
        self.assertEqual(undo_packets, [high_message.packet])

    @call_on_dispersy_thread
    def test_missing_message(self):
        """
        SELF gives NODE permission to undo, NODE generates a few messages without sending them to
        OTHER. Following, NODE undoes the messages and sends the undo messages to OTHER. OTHER must
        now use a dispersy-missing-message to request the messages that are about to be undone. The
        messages need to be processed and subsequently undone.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # SELF grants undo permission to NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

        # create messages
        messages = [node.create_full_sync_text("Should undo @%d" % i, i + 10) for i in xrange(10)]

        # undo all messages
        sequence_number = 1
        undoes = [node.create_dispersy_undo_own(message, message.distribution.global_time + 100, i + sequence_number) for i, message in enumerate(messages)]

        # send undoes to OTHER
        other.give_messages(undoes, node)

        # receive the dispersy-missing-message messages
        global_times = [message.distribution.global_time for message in messages]
        global_time_requests = []
        for _ in xrange(len(messages)):
            _, message = node.receive_message(names=[u"dispersy-missing-message"])
            self.assertEqual(message.payload.member.public_key, node.my_member.public_key)
            global_time_requests.extend(message.payload.global_times)
        self.assertEqual(sorted(global_times), sorted(global_time_requests))

        # give all 'delayed' messages
        other.give_messages(messages, node)

        # check that they are in the database and ARE undone
        self.assert_is_undone(messages=messages)
        self.assert_is_stored(messages=undoes)

    @call_on_dispersy_thread
    def test_revoke_simple(self):
        """
        SELF gives NODE permission to undo, SELF revokes this permission.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        # SELF grants undo permission to NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

        # SELF revoke undo permission from NODE
        self._community.create_revoke([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

    @call_on_dispersy_thread
    def test_revoke_causing_undo(self):
        """
        SELF gives NODE permission to undo, OTHER created a message, NODE undoes the message, SELF
        revokes the undo permission AFTER the message was undone -> the message is not re-done.
        """

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # SELF grants undo permission to NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])

        # OTHER creates a message
        message = other.create_full_sync_text("will be undone", 42)
        other.give_message(message, other)
        self.assert_is_stored(message)

        # NODE undoes the message
        undo = node.create_dispersy_undo_other(message, message.distribution.global_time + 1, 1)
        other.give_message(undo, node)
        self.assert_is_undone(message)
        self.assert_is_stored(undo)

        # SELF revoke undo permission from NODE
        self._community.create_revoke([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])
        self.assert_is_undone(message)
