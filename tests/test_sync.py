from .dispersytestclass import DispersyTestFunc


class TestSync(DispersyTestFunc):

    def _create_nodes_messages(self, messagetype="create_full_sync_text"):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # other creates messages
        messages = [getattr(other, messagetype)("Message %d" % i, i + 10) for i in xrange(30)]
        other.store(messages)

        return node, other, messages

    def test_modulo(self):
        """
        OTHER creates several messages, NODE asks for specific modulo to sync and only those modulo
        may be sent back.
        """
        node, other, messages = self._create_nodes_messages()

        for modulo in xrange(0, 10):
            for offset in xrange(0, modulo):
                # global times that we should receive
                global_times = [message.distribution.global_time for message in messages if (message.distribution.global_time + offset) % modulo == 0]

                sync = (1, 0, modulo, offset, [])
                other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42), node)

                responses = node.receive_messages(names=[u"full-sync-text"], return_after=len(global_times))
                response_times = [message.distribution.global_time for _, message in responses]

                self.assertEqual(sorted(global_times), sorted(response_times))


    def test_range(self):
        node, other, messages = self._create_nodes_messages()

        for time_low in xrange(1, 11):
            for time_high in xrange(20, 30):
                # global times that we should receive
                global_times = [message.distribution.global_time for message in messages if time_low <= message.distribution.global_time <= time_high]

                sync = (time_low, time_high, 1, 0, [])
                other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42), node)

                responses = node.receive_messages(names=[u"full-sync-text"], return_after=len(global_times))
                response_times = [message.distribution.global_time for _, message in responses]

                self.assertEqual(sorted(global_times), sorted(response_times))


    def test_in_order(self):
        node, other, messages = self._create_nodes_messages('create_in_order_text')
        global_times = [message.distribution.global_time for message in messages]

        # send an empty sync message to obtain all messages ASC order
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42), node)

        responses = node.receive_messages(names=[u"ASC-text"], return_after=len(global_times))
        response_times = [message.distribution.global_time for _, message in responses]

        self.assertEqual(sorted(global_times), sorted(response_times))


    def test_out_order(self):
        node, other, messages = self._create_nodes_messages('create_out_order_text')
        global_times = [message.distribution.global_time for message in messages]

        # send an empty sync message to obtain all messages DESC order
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42), node)

        responses = node.receive_messages(names=[u"DESC-text"], return_after=len(global_times))
        response_times = [message.distribution.global_time for _, message in responses]

        self.assertEqual(sorted(global_times), sorted(response_times))


    def test_random_order(self):
        node, other, messages = self._create_nodes_messages('create_random_order_text')
        global_times = [message.distribution.global_time for message in messages]

        # send an empty sync message to obtain all messages in RANDOM order
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42), node)

        responses = node.receive_messages(names=[u"RANDOM-text"], return_after=len(global_times))
        response_times = [message.distribution.global_time for _, message in responses]

        self.assertNotEqual(response_times, sorted(global_times))
        self.assertNotEqual(response_times, sorted(global_times, reverse=True))


    def test_mixed_order(self):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # OTHER creates messages
        in_order_messages = [other.create_in_order_text("Message %d" % i, i + 10) for i in xrange(0, 30, 3)]
        out_order_messages = [other.create_out_order_text("Message %d" % i, i + 10) for i in xrange(1, 30, 3)]
        random_order_messages = [other.create_random_order_text("Message %d" % i, i + 10) for i in xrange(2, 30, 3)]

        other.store(in_order_messages)
        other.store(out_order_messages)
        other.store(random_order_messages)

        # send an empty sync message to obtain all messages ALL messages
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (1, 0, 1, 0, []), 42), node)

        received = node.receive_messages(names=[u"ASC-text", u"DESC-text", u"RANDOM-text"], return_after=30)

        # all ASC-text must be received in-order of their global time (low to high)
        received_in_order = [message.distribution.global_time for _, message in received if message.name == u"ASC-text"]
        self.assertEqual(received_in_order, sorted(message.distribution.global_time for message in in_order_messages))

        # all DESC-text must be received in reversed order of their global time (high to low)
        received_out_order = [message.distribution.global_time for _, message in received if message.name == u"DESC-text"]
        self.assertEqual(received_out_order, sorted([message.distribution.global_time for message in out_order_messages], reverse=True))

        # all RANDOM-text must NOT be received in (reversed) order of their global time
        received_random_order = [message.distribution.global_time for _, message in received if message.name == u"RANDOM-text"]
        self.assertNotEqual(received_random_order, sorted([message.distribution.global_time for message in random_order_messages]))
        self.assertNotEqual(received_random_order, sorted([message.distribution.global_time for message in random_order_messages], reverse=True))

    def test_priority_order(self):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # OTHER creates messages
        high_priority_messages = [other.create_high_priority_text("Message %d" % i, i + 10) for i in xrange(0, 30, 3)]
        low_priority_messages = [other.create_low_priority_text("Message %d" % i, i + 10) for i in xrange(1, 30, 3)]
        medium_priority_messages = [other.create_medium_priority_text("Message %d" % i, i + 10) for i in xrange(2, 30, 3)]

        other.store(high_priority_messages)
        other.store(low_priority_messages)
        other.store(medium_priority_messages)

        # send an empty sync message to obtain all messages ALL messages
        other.give_message(node.create_introduction_request(other.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (1, 0, 1, 0, []), 42), node)

        received = node.receive_messages(names=[u"high-priority-text", u"low-priority-text", u"medium-priority-text"], return_after=30)

        # the first should be the high-priority-text
        offset = 0
        self.assertEqual([message.name for _, message in received[offset:offset + len(high_priority_messages)]],
                         ["high-priority-text"] * len(high_priority_messages))

        # the second should be the medium-priority-text
        offset += len(high_priority_messages)
        self.assertEqual([message.name for _, message in received[offset:offset + len(medium_priority_messages)]],
                         ["medium-priority-text"] * len(medium_priority_messages))

        # last should be the low-priority-text
        offset += len(medium_priority_messages)
        self.assertEqual([message.name for _, message in received[offset:offset + len(low_priority_messages)]],
                         ["low-priority-text"] * len(low_priority_messages))

    def test_last_1(self):
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # send a message
        message = other.create_last_1_test("should be accepted (1)", 10)
        node.give_message(message, other)
        node.assert_is_stored(message)

        # send a message, should replace current one
        new_message = other.create_last_1_test("should be accepted (2)", 11)
        node.give_message(new_message, other)
        node.assert_not_stored(message)
        node.assert_is_stored(new_message)

        # send a message (older: should be dropped)
        old_message = other.create_last_1_test("should be dropped (1)", 9)
        node.give_message(old_message, other)

        node.assert_not_stored(message)
        node.assert_is_stored(new_message)
        node.assert_not_stored(old_message)

        # as proof for the drop, the newest message should be sent back
        _, message = other.receive_message(names=[u"last-1-test"]).next()
        self.assertEqual(message.distribution.global_time, new_message.distribution.global_time)

    def test_last_9(self):
        message = self._community.get_meta_message(u"last-9-test")

        node, other = self.create_nodes(2)
        other.send_identity(node)

        all_messages = [21, 20, 28, 27, 22, 23, 24, 26, 25]
        messages_so_far = []
        for global_time in all_messages:
            # send a message
            message = other.create_last_9_test(str(global_time), global_time)
            node.give_message(message, other)

            messages_so_far.append((global_time, message))

        for _, message in messages_so_far:
            node.assert_is_stored(message)

        for global_time in [11, 12, 13, 19, 18, 17]:
            # send a message (older: should be dropped)
            node.give_message(other.create_last_9_test(str(global_time), global_time), other)

        for _, message in messages_so_far:
            node.assert_is_stored(message)

        messages_so_far.sort()
        for global_time in [30, 35, 37, 31, 32, 34, 33, 36, 38, 45, 44, 43, 42, 41, 40, 39]:
            # send a message (should be added and old one removed)
            message = other.create_last_9_test(str(global_time), global_time)
            node.give_message(message, other)

            messages_so_far.pop(0)
            messages_so_far.append((global_time, message))
            messages_so_far.sort()

        for _, message in messages_so_far:
            node.assert_is_stored(message)

    def test_last_1_doublemember(self):
        """
        Normally the LastSyncDistribution policy stores the last N messages for each member that
        created the message.  However, when the DoubleMemberAuthentication policy is used, there are
        two members.

        This can be handled in two ways:

         1. The first member who signed the message is still seen as the creator and hence the last
            N messages of this member are stored.

         2. Each member combination is used and the last N messages for each member combination is
            used.  For example: when member A and B sign a message it will not count toward the
            last-N of messages signed by A and C (which is another member combination.)

        Currently we only implement option #2.  There currently is no parameter to switch between
        these options.
        """
        message = self._community.get_meta_message(u"last-1-doublemember-text")
        nodeA, nodeB, nodeC = self.create_nodes(3)
        nodeA.send_identity(nodeB)
        nodeA.send_identity(nodeC)
        nodeB.send_identity(nodeC)

        def create_double_signed_message(origin, destination, message, global_time):
            origin_mid_pre = origin._community.my_member.mid
            destination_mid_pre = destination._community.my_member.mid
            assert origin_mid_pre != destination_mid_pre

            submsg = origin.create_last_1_doublemember_text(destination.my_member, message, global_time)

            assert origin_mid_pre == origin._community.my_member.mid
            assert destination_mid_pre == destination._community.my_member.mid

            destination.give_message(origin.create_signature_request(12345, submsg, global_time), origin)
            _, message = origin.receive_message(names=[u"dispersy-signature-response"]).next()
            return (global_time, message.payload.message)

        def check_database_contents():
            # TODO(emilon): This could be done better.
            def fetch_rows():
                return list(nodeA._dispersy.database.execute(
                    u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2, "
                    u"member1.mid as mid1, member2.mid as mid2 FROM sync "
                    u"JOIN double_signed_sync ON double_signed_sync.sync = sync.id "
                    u"JOIN member member1 ON double_signed_sync.member1 = member1.id "
                    u"JOIN member member2 ON double_signed_sync.member2 = member2.id "
                    u"WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?",
                    (nodeA._community.database_id, nodeA.my_member.database_id, message.database_id)))

            entries = []
            database_ids = {}
            for global_time, member, sync_member1, sync_member2, mid1, mid2 in nodeA.call(fetch_rows):
                entries.append((global_time, member, sync_member1, sync_member2))
                database_ids[str(mid1)] = sync_member1
                database_ids[str(mid2)] = sync_member2

            # We should only have two entries: AB and AC pairs
            self.assertEqual(len(entries), 2)

            # One should be A and B
            expectedAB = (current_global_timeB,
                          nodeA.my_member.database_id,
                          min(database_ids[nodeA.my_member.mid], database_ids[nodeB.my_member.mid]),
                          max(database_ids[nodeA.my_member.mid], database_ids[nodeB.my_member.mid])
                          )
            self.assertIn(expectedAB, entries)

            # The other should be A and C
            expectedAC = (current_global_timeC,
                          nodeA.my_member.database_id,
                          min(database_ids[nodeA.my_member.mid], database_ids[nodeC.my_member.mid]),
                          max(database_ids[nodeA.my_member.mid], database_ids[nodeC.my_member.mid])
                          )
            self.assertIn(expectedAC, entries)

        # Send a set of messages
        global_time = 10
        other_global_time = global_time + 1
        messages = []
        messages.append(create_double_signed_message(nodeA, nodeB, "Allow=True (1AB)", global_time))
        messages.append(create_double_signed_message(nodeA, nodeC, "Allow=True (1AC)", other_global_time))

        # Send a newer set, the previous ones should be dropped
        # Those two are the messages that we should have in the DB at the end of the test.
        global_time = 20
        other_global_time = global_time + 1
        messages.append(create_double_signed_message(nodeA, nodeB, "Allow=True (2AB) @%d" % global_time, global_time))
        messages.append(create_double_signed_message(nodeA, nodeC, "Allow=True (2AC) @%d" % other_global_time, other_global_time))

        # Send another message (same global time: should be droped)
        messages.append(create_double_signed_message(nodeA, nodeB, "Allow=True Duplicate global time (2ABbis) @%d" % global_time, global_time))
        messages.append(create_double_signed_message(nodeA, nodeC, "Allow=True Duplicate global time (2ACbis) @%d" % other_global_time, other_global_time))

        # send yet another message (older: should be dropped too)
        old_global_time = 8
        other_old_global_time = old_global_time + 1
        messages.append(create_double_signed_message(nodeA, nodeB, "Allow=True Should be dropped (1AB)", old_global_time))
        messages.append(create_double_signed_message(nodeA, nodeC, "Allow=True Should be dropped (1AC)", other_old_global_time))

        current_global_timeB = 0
        current_global_timeC = 0
        while messages:
            global_timeB, messageB = messages.pop(0)
            global_timeC, messageC = messages.pop(0)

            current_global_timeB = max(global_timeB, current_global_timeB)
            current_global_timeC = max(global_timeC, current_global_timeC)

            nodeA.give_messages([messageB, messageC], nodeB)
            check_database_contents()

        # as proof for the drop, the more recent messages should be sent back to nodeB
        times = []
        for _, message in nodeB.receive_message(names=[u"last-1-doublemember-text"]):
            times.append(message.distribution.global_time)

        self.assertEqual(sorted(times), [global_time, other_global_time])

        # send a message (older + different member combination: should be dropped)
        old_global_time = 9
        create_double_signed_message(nodeB, nodeA, "Allow=True (2BA)", old_global_time)
        create_double_signed_message(nodeC, nodeA, "Allow=True (2CA)", old_global_time)

        check_database_contents()
