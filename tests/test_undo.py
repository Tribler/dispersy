from .dispersytestclass import DispersyTestFunc


class TestUndo(DispersyTestFunc):

    def test_self_undo_own(self):
        """
        NODE generates a few messages and then undoes them.

        This is always allowed.  In fact, no check is made since only externally received packets
        will be checked.
        """
        node, = self.create_nodes(1)

        # create messages
        messages = [node.create_full_sync_text("Should undo #%d" % i, i + 10) for i in xrange(10)]
        node.give_messages(messages, node)

        # check that they are in the database and are NOT undone
        node.assert_is_stored(messages=messages)

        # undo all messages
        undoes = [node.create_undo_own(message, i + 100, i + 1) for i, message in enumerate(messages)]

        node.give_messages(undoes, node)

        # check that they are in the database and ARE undone
        node.assert_is_undone(messages=messages)
        node.assert_is_stored(messages=undoes)

    def test_node_undo_other(self):
        """
        MM gives NODE permission to undo, OTHER generates a few messages and then NODE undoes
        them.
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # MM grants undo permission to NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")], self._mm.claim_global_time())
        node.give_message(authorize, self._mm)
        other.give_message(authorize, self._mm)

        # OTHER creates messages
        messages = [other.create_full_sync_text("Should undo #%d" % i, i + 10) for i in xrange(10)]
        node.give_messages(messages, other)

        # check that they are in the database and are NOT undone
        node.assert_is_stored(messages=messages)

        # NODE undoes all messages
        undoes = [node.create_undo_other(message, message.distribution.global_time + 100, 1 + i) for i, message in enumerate(messages)]
        node.give_messages(undoes, node)

        # check that they are in the database and ARE undone
        node.assert_is_undone(messages=messages)
        node.assert_is_stored(messages=undoes)

    def test_self_attempt_undo_twice(self):
        """
        NODE generated a message and then undoes it twice. The dispersy core should ensure that
        that the second undo is refused and the first undo message should be returned instead.
        """
        node, = self.create_nodes(1)

        # create message
        message = node.create_full_sync_text("Should undo @%d" % 1, 1)
        node.give_message(message, node)

        # undo twice
        def create_undoes():
            return node._community.create_undo(message), node._community.create_undo(message)
        undo1, undo2 = node.call(create_undoes)

        self.assertEqual(undo1.packet, undo2.packet)

    def test_node_resolve_undo_twice(self):
        """
        Make sure that in the event of receiving two undo messages from the same member, both will be stored,
        and in case of receiving a lower one, that we will send the higher one back to the sender.

        MM gives NODE permission to undo, NODE generates a message and then undoes it twice.
        Both messages should be kept and the lowest one should be undone.

        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # MM grants undo permission to NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")], self._mm.claim_global_time())
        node.give_message(authorize, self._mm)
        other.give_message(authorize, self._mm)

        # create message
        message = node.create_full_sync_text("Should undo @%d" % 10, 10)

        # create undoes
        undo1 = node.create_undo_own(message, 11, 1)
        undo2 = node.create_undo_own(message, 12, 2)
        low_message, high_message = sorted([undo1, undo2], key=lambda message: message.packet)
        other.give_message(message, node)
        other.give_message(low_message, node)
        other.give_message(high_message, node)
        # OTHER should send the first message back when receiving
        # the second one (its "higher" than the one just received)
        undo_packets = []

        for candidate, b in node.receive_packets():
            self._logger.debug(candidate)
            self._logger.debug(type(b))
            self._logger.debug("%d", len(b))
            self._logger.debug("before %d", len(undo_packets))
            undo_packets.append(b)
            self._logger.debug("packets amount: %d", len(undo_packets))
            self._logger.debug("first undo %d", len(undo_packets[0]))
            self._logger.debug("%d", len(b))

            for x in undo_packets:
                self._logger.debug("loop%d", len(x))

        def fetch_all_messages():
            for row in  list(other._dispersy.database.execute(u"SELECT * FROM sync")):
                self._logger.debug("_______ %s", row)
        other.call(fetch_all_messages)

        self._logger.debug("%d", len(low_message.packet))

        self.assertEqual(undo_packets, [low_message.packet])

        # NODE should have both messages on the database and the lowest one should be undone by the highest.
        messages = other.fetch_messages((u"dispersy-undo-own",))
        self.assertEquals(len(messages), 2)
        other.assert_is_done(low_message)
        other.assert_is_undone(high_message)
        other.assert_is_undone(high_message, undone_by=low_message)
        other.assert_is_undone(message, undone_by=low_message)

    def test_missing_message(self):
        """
        NODE generates a few messages without sending them to OTHER. Following, NODE undoes the
        messages and sends the undo messages to OTHER. OTHER must now use a dispersy-missing-message
        to request the messages that are about to be undone. The messages need to be processed and
        subsequently undone.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # create messages
        messages = [node.create_full_sync_text("Should undo @%d" % i, i + 10) for i in xrange(10)]

        # undo all messages
        undoes = [node.create_undo_own(message, message.distribution.global_time + 100, i + 1) for i, message in enumerate(messages)]

        # send undoes to OTHER
        other.give_messages(undoes, node)

        # receive the dispersy-missing-message messages
        global_times = [message.distribution.global_time for message in messages]
        global_time_requests = []

        for _, message in node.receive_messages(names=[u"dispersy-missing-message"]):
            self.assertEqual(message.payload.member.public_key, node.my_member.public_key)
            global_time_requests.extend(message.payload.global_times)

        self.assertEqual(sorted(global_times), sorted(global_time_requests))

        # give all 'delayed' messages
        other.give_messages(messages, node)

        # check that they are in the database and ARE undone
        other.assert_is_undone(messages=messages)
        other.assert_is_stored(messages=undoes)

    def test_revoke_causing_undo(self):
        """
        SELF gives NODE permission to undo, OTHER created a message, NODE undoes the message, SELF
        revokes the undo permission AFTER the message was undone -> the message is re-done.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # MM grants undo permission to NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")], self._mm.claim_global_time())
        node.give_message(authorize, self._mm)
        other.give_message(authorize, self._mm)

        # OTHER creates a message
        message = other.create_full_sync_text("will be undone", 42)
        other.give_message(message, other)
        other.assert_is_stored(message)

        # NODE undoes the message
        undo = node.create_undo_other(message, message.distribution.global_time + 1, 1)
        other.give_message(undo, node)
        other.assert_is_undone(message)
        other.assert_is_stored(undo)

        # SELF revoke undo permission from NODE, as the globaltime of the mm is lower than 42 the message needs to be done
        revoke = self._mm.create_revoke([(node.my_member, self._community.get_meta_message(u"full-sync-text"), u"undo")])
        other.give_message(revoke, self._mm)
        other.assert_is_done(message)

    def test_revoke_causing_undo_permitted(self):
        """
        SELF gives NODE permission to undo, OTHER created a message, NODE undoes the message, SELF
        revokes the undo permission AFTER the message was undone -> the message is re-done.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # MM grants permit permission to OTHER
        authorize = self._mm.create_authorize([(other.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit")], self._mm.claim_global_time())
        node.give_message(authorize, self._mm)
        other.give_message(authorize, self._mm)

        # MM grants undo permission to NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"undo")], self._mm.claim_global_time())
        node.give_message(authorize, self._mm)
        other.give_message(authorize, self._mm)

        # OTHER creates a message
        message = other.create_protected_full_sync_text("will be undone", 42)
        other.give_message(message, other)
        other.assert_is_stored(message)

        # NODE undoes the message
        undo = node.create_undo_other(message, message.distribution.global_time + 1, 1)
        other.give_message(undo, node)
        other.assert_is_undone(message)
        other.assert_is_stored(undo)

        # SELF revoke undo permission from NODE, as the globaltime of the mm is lower than 42 the message needs to be done
        revoke = self._mm.create_revoke([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"undo")])
        other.give_message(revoke, self._mm)
        other.assert_is_done(message)
