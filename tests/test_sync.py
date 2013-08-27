import logging
logger = logging.getLogger(__name__)

from random import random

from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestSync(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_modulo(self):
        """
        SELF creates several messages, NODE asks for specific modulo to sync and only those modulo
        may be sent back.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF creates messages
        messages = [community.create_full_sync_text("foo-bar", forward=False) for _ in xrange(30)]

        for modulo in xrange(0, 10):
            for offset in xrange(0, modulo):
                # global times that we should receive
                global_times = [message.distribution.global_time for message in messages if (message.distribution.global_time + offset) % modulo == 0]

                sync = (1, 0, modulo, offset, [])
                node.drop_packets()
                node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, 110))

                responses = node.receive_messages(message_names=[u"full-sync-text"])
                response_times = [message.distribution.global_time for _, message in responses]

                self.assertEqual(sorted(global_times), sorted(response_times))
                logger.debug("%%%d+%d: %s -> OK", modulo, offset, sorted(global_times))

    @call_on_dispersy_thread
    def test_in_order(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"ASC-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        times = list(self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        self.assertEqual(times, [])

        # create some data
        global_times = range(10, 15)
        for global_time in global_times:
            node.give_message(node.create_in_order_text("Message #%d" % global_time, global_time))

        # send an empty sync message to obtain all messages ASC
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42, max(global_times)))
        yield 0.1

        for global_time in global_times:
            _, message = node.receive_message(message_names=[u"ASC-text"])
            self.assertEqual(message.distribution.global_time, global_time)

    @call_on_dispersy_thread
    def test_out_order(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"DESC-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        times = list(self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        self.assertEqual(times, [])

        # create some data
        global_times = range(10, 15)
        for global_time in global_times:
            node.give_message(node.create_out_order_text("Message #%d" % global_time, global_time))

        # send an empty sync message to obtain all messages DESC
        node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42, max(global_times)))
        yield 0.1

        for global_time in reversed(global_times):
            _, message = node.receive_message(message_names=[u"DESC-text"])
            self.assertEqual(message.distribution.global_time, global_time)

    @call_on_dispersy_thread
    def test_mixed_order(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        in_order_message = community.get_meta_message(u"ASC-text")
        out_order_message = community.get_meta_message(u"DESC-text")
        # random_order_message = community.get_meta_message(u"random-order-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        count, = self._dispersy.database.execute(u"SELECT COUNT(*) FROM sync WHERE sync.community = ? AND sync.meta_message IN (?, ?)", (community.database_id, in_order_message.database_id, out_order_message.database_id)).next()
        self.assertEqual(count, 0)

        # create some data
        global_times = range(10, 25, 2)
        in_order_times = []
        out_order_times = []
        # random_order_times = []
        for global_time in global_times:
            in_order_times.append(global_time)
            node.give_message(node.create_in_order_text("Message #%d" % global_time, global_time))
            global_time += 1
            out_order_times.append(global_time)
            node.give_message(node.create_out_order_text("Message #%d" % global_time, global_time))
            # global_time += 1
            # random_order_times.append(global_time)
            # node.give_message(node.create_random_order_text_message("Message #%d" % global_time, global_time))
        out_order_times.sort(reverse=True)
        logger.debug("Total ASC:%d; DESC:", len(in_order_times))

        def get_messages_back():
            received_times = []
            for _ in range(len(global_times) * 2):
                _, message = node.receive_message(message_names=[u"ASC-text", u"DESC-text"])
                #, u"random-order-text"])
                received_times.append(message.distribution.global_time)

            return received_times

        # lists = []
        for _ in range(5):
            # send an empty sync message to obtain all messages in random-order
            node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", (min(global_times), 0, 1, 0, []), 42, max(global_times)))
            yield 0.1

            received_times = get_messages_back()

            # followed by DESC
            received_out_times = received_times[0:len(out_order_times)]
            self.assertEqual(out_order_times, received_out_times)

            # the first items must be ASC
            received_in_times = received_times[len(out_order_times):len(in_order_times) + len(out_order_times)]
            self.assertEqual(in_order_times, received_in_times)

    @call_on_dispersy_thread
    def test_last_1(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"last-1-test")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        times = list(self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        self.assertEqual(times, [])

        # send a message
        global_time = 10
        node.give_message(node.create_last_1_test("should be accepted (1)", global_time))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # send a message
        global_time = 11
        node.give_message(node.create_last_1_test("should be accepted (2)", global_time))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # send a message (older: should be dropped)
        node.give_message(node.create_last_1_test("should be dropped (1)", global_time - 1))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # as proof for the drop, the newest message should be sent back
        yield 0.1
        _, message = node.receive_message(message_names=[u"last-1-test"])
        self.assertEqual(message.distribution.global_time, global_time)

        # send a message (duplicate: should be dropped)
        node.give_message(node.create_last_1_test("should be dropped (2)", global_time))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

        # send a message
        global_time = 12
        node.give_message(node.create_last_1_test("should be accepted (3)", global_time))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

    @call_on_dispersy_thread
    def test_last_9(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"last-9-test")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # should be no messages from NODE yet
        times = list(self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        self.assertEqual(times, [])

        all_messages = [21, 20, 28, 27, 22, 23, 24, 26, 25]
        messages_so_far = []
        for global_time in all_messages:
            # send a message
            message = node.create_last_9_test(str(global_time), global_time)
            messages_so_far.append(global_time)
            node.give_message(message)
            try:
                packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            except StopIteration:
                self.fail()
            self.assertEqual(str(packet), message.packet)
            times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            self.assertEqual(sorted(times), sorted(messages_so_far))
        self.assertEqual(sorted(all_messages), sorted(messages_so_far))

        logger.debug("Older: should be dropped")
        for global_time in [11, 12, 13, 19, 18, 17]:
            # send a message (older: should be dropped)
            node.give_message(node.create_last_9_test(str(global_time), global_time))
            times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            self.assertEqual(sorted(times), sorted(messages_so_far))

        logger.debug("Duplicate: should be dropped")
        for global_time in all_messages:
            # send a message (duplicate: should be dropped)
            message = node.create_last_9_test("wrong content!", global_time)
            node.give_message(message)
            try:
                packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            except StopIteration:
                self.fail()
            self.assertNotEqual(str(packet), message.packet)
            times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            self.assertEqual(sorted(times), sorted(messages_so_far))

        logger.debug("Should be added and old one removed")
        match_times = sorted(times[:])
        for global_time in [30, 35, 37, 31, 32, 34, 33, 36, 38, 45, 44, 43, 42, 41, 40, 39]:
            # send a message (should be added and old one removed)
            message = node.create_last_9_test(str(global_time), global_time)
            node.give_message(message)
            match_times.pop(0)
            match_times.append(global_time)
            match_times.sort()
            try:
                packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, global_time, message.database_id)).next()
            except StopIteration:
                self.fail()
            self.assertEqual(str(packet), message.packet)
            times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
            self.assertEqual(sorted(times), match_times)

    @call_on_dispersy_thread
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
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"last-1-doublemember-text")

        # create node and ensure that SELF knows the node address
        nodeA = DebugNode(community)
        nodeA.init_socket()
        nodeA.init_my_member()

        # create node and ensure that SELF knows the node address
        nodeB = DebugNode(community)
        nodeB.init_socket()
        nodeB.init_my_member()

        # create node and ensure that SELF knows the node address
        nodeC = DebugNode(community)
        nodeC.init_socket()
        nodeC.init_my_member()

        # dump some junk data, TODO: should not use this btw in actual test...
        # self._dispersy.database.execute(u"INSERT INTO sync (community, meta_message, member, global_time) VALUES (?, ?, 42, 9)", (community.database_id, message.database_id))
        # sync_id = self._dispersy.database.last_insert_rowid
        # self._dispersy.database.execute(u"INSERT INTO reference_member_sync (member, sync) VALUES (42, ?)", (sync_id,))
        # self._dispersy.database.execute(u"INSERT INTO reference_member_sync (member, sync) VALUES (43, ?)", (sync_id,))
        #
        # self._dispersy.database.execute(u"INSERT INTO sync (community, meta_message, member, global_time) VALUES (?, ?, 4, 9)", (community.database_id, message.database_id))
        # sync_id = self._dispersy.database.last_insert_rowid
        # self._dispersy.database.execute(u"INSERT INTO reference_member_sync (member, sync) VALUES (4, ?)", (sync_id,))
        # self._dispersy.database.execute(u"INSERT INTO reference_member_sync (member, sync) VALUES (43, ?)", (sync_id,))

        # send a message
        global_time = 10
        other_global_time = global_time + 1
        messages = []
        messages.append(nodeA.create_last_1_doublemember_text(nodeB.my_member, "should be accepted (1)", global_time, sign=True))
        messages.append(nodeA.create_last_1_doublemember_text(nodeC.my_member, "should be accepted (1)", other_global_time, sign=True))
        nodeA.give_messages(messages)
        entries = list(self._dispersy.database.execute(u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2 FROM sync JOIN double_signed_sync ON double_signed_sync.sync = sync.id WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id)))
        self.assertEqual(len(entries), 2)
        self.assertIn((global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeB.my_member.database_id), max(nodeA.my_member.database_id, nodeB.my_member.database_id)), entries)
        self.assertIn((other_global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeC.my_member.database_id), max(nodeA.my_member.database_id, nodeC.my_member.database_id)), entries)

        # send a message
        global_time = 20
        other_global_time = global_time + 1
        messages = []
        messages.append(nodeA.create_last_1_doublemember_text(nodeB.my_member, "should be accepted (2) @%d" % global_time, global_time, sign=True))
        messages.append(nodeA.create_last_1_doublemember_text(nodeC.my_member, "should be accepted (2) @%d" % other_global_time, other_global_time, sign=True))
        nodeA.give_messages(messages)
        entries = list(self._dispersy.database.execute(u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2 FROM sync JOIN double_signed_sync ON double_signed_sync.sync = sync.id WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id)))
        self.assertEqual(len(entries), 2)
        self.assertIn((global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeB.my_member.database_id), max(nodeA.my_member.database_id, nodeB.my_member.database_id)), entries)
        self.assertIn((other_global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeC.my_member.database_id), max(nodeA.my_member.database_id, nodeC.my_member.database_id)), entries)

        # send a message (older: should be dropped)
        old_global_time = 8
        messages = []
        messages.append(nodeA.create_last_1_doublemember_text(nodeB.my_member, "should be dropped (1)", old_global_time, sign=True))
        messages.append(nodeA.create_last_1_doublemember_text(nodeC.my_member, "should be dropped (1)", old_global_time, sign=True))
        nodeA.give_messages(messages)
        entries = list(self._dispersy.database.execute(u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2 FROM sync JOIN double_signed_sync ON double_signed_sync.sync = sync.id WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id)))
        self.assertEqual(len(entries), 2)
        self.assertIn((global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeB.my_member.database_id), max(nodeA.my_member.database_id, nodeB.my_member.database_id)), entries)
        self.assertIn((other_global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeC.my_member.database_id), max(nodeA.my_member.database_id, nodeC.my_member.database_id)), entries)

        yield 0.1
        nodeA.drop_packets()

        # send a message (older: should be dropped)
        old_global_time = 8
        messages = []
        messages.append(nodeB.create_last_1_doublemember_text(nodeA.my_member, "should be dropped (1)", old_global_time, sign=True))
        messages.append(nodeC.create_last_1_doublemember_text(nodeA.my_member, "should be dropped (1)", old_global_time, sign=True))
        nodeA.give_messages(messages)
        entries = list(self._dispersy.database.execute(u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2 FROM sync JOIN double_signed_sync ON double_signed_sync.sync = sync.id WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id)))
        self.assertEqual(len(entries), 2)
        self.assertIn((global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeB.my_member.database_id), max(nodeA.my_member.database_id, nodeB.my_member.database_id)), entries)
        self.assertIn((other_global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeC.my_member.database_id), max(nodeA.my_member.database_id, nodeC.my_member.database_id)), entries)

        # as proof for the drop, the newest message should be sent back
        yield 0.1
        times = []
        _, message = nodeA.receive_message(message_names=[u"last-1-doublemember-text"])
        times.append(message.distribution.global_time)
        _, message = nodeA.receive_message(message_names=[u"last-1-doublemember-text"])
        times.append(message.distribution.global_time)
        self.assertEqual(sorted(times), [global_time, other_global_time])

        # send a message (older + different member combination: should be dropped)
        old_global_time = 9
        messages = []
        messages.append(nodeB.create_last_1_doublemember_text(nodeA.my_member, "should be dropped (2)", old_global_time, sign=True))
        messages.append(nodeC.create_last_1_doublemember_text(nodeA.my_member, "should be dropped (2)", old_global_time, sign=True))
        nodeA.give_messages(messages)
        entries = list(self._dispersy.database.execute(u"SELECT sync.global_time, sync.member, double_signed_sync.member1, double_signed_sync.member2 FROM sync JOIN double_signed_sync ON double_signed_sync.sync = sync.id WHERE sync.community = ? AND sync.member = ? AND sync.meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id)))
        self.assertEqual(len(entries), 2)
        self.assertIn((global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeB.my_member.database_id), max(nodeA.my_member.database_id, nodeB.my_member.database_id)), entries)
        self.assertIn((other_global_time, nodeA.my_member.database_id, min(nodeA.my_member.database_id, nodeC.my_member.database_id), max(nodeA.my_member.database_id, nodeC.my_member.database_id)), entries)

    @call_on_dispersy_thread
    def test_last_1_doublemember_unique_member_global_time(self):
        """
        Even with double member messages, the first member is the creator and may only have one
        message for each global time.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"last-1-doublemember-text")

        # create node and ensure that SELF knows the node address
        nodeA = DebugNode(community)
        nodeA.init_socket()
        nodeA.init_my_member()

        # create node and ensure that SELF knows the node address
        nodeB = DebugNode(community)
        nodeB.init_socket()
        nodeB.init_my_member()

        # create node and ensure that SELF knows the node address
        nodeC = DebugNode(community)
        nodeC.init_socket()
        nodeC.init_my_member()

        # send two messages
        global_time = 10
        messages = []
        messages.append(nodeA.create_last_1_doublemember_text(nodeB.my_member, "should be accepted (1.1)", global_time, sign=True))
        messages.append(nodeA.create_last_1_doublemember_text(nodeC.my_member, "should be accepted (1.2)", global_time, sign=True))

        # we NEED the messages to be handled in one batch.  using the socket may change this
        nodeA.give_messages(messages)

        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, nodeA.my_member.database_id, message.database_id))]
        self.assertEqual(times, [global_time])

    @call_on_dispersy_thread
    def test_performance(self):
        """
        SELF creates 10k messages and NODE sends 100 sync requests.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # SELF creates 10k messages
        with self._dispersy.database:
            for i in xrange(10000):
                community.create_full_sync_text("test performance data #%d" % i, forward=False)

        # NODE creates 100 sync requests
        for i in xrange(100):
            m = int(random() * 10) + 1
            o = min(m - 1, int(random() * 10))
            sync = (1, 0, m, o, [])
            node.give_message(node.create_dispersy_introduction_request(community.my_candidate, node.lan_address, node.wan_address, False, u"unknown", sync, 42, 10))
            node.drop_packets()
