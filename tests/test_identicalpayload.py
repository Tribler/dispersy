from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestIdenticalPayload(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_drop_identical_payload(self):
        """
        NODE creates two messages with the same community/member/global-time.
        Sends both of them to OTHER, which should drop the "lowest" one.
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # create messages
        messages = []
        messages.append(node.create_full_sync_text("Identical payload message", 42))
        messages.append(node.create_full_sync_text("Identical payload message", 42))
        self.assertNotEqual(messages[0].packet, messages[1].packet, "the signature must make the messages unique")

        # sort. we now know that the first message must be dropped
        messages.sort(key=lambda x: x.packet)

        # give messages in different batches
        other.give_message(messages[0], node)
        other.give_message(messages[1], node)

        try:
            packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                      (self._community.database_id, node.my_member.database_id, 42)).next()
            packet = str(packet)
            self.assertEqual(packet, messages[1].packet)

        except StopIteration:
            self.fail("neither message is stored")

    @call_on_dispersy_thread
    def test_drop_identical(self):
        """
        NODE creates one message, sends it to OTHER twice
        """
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # create messages
        message = node.create_full_sync_text("Message", 42)

        # give messages to other
        other.give_message(message, node)
        other.give_message(message, node)

        nrpackets, = self._dispersy.database.execute(u"SELECT count(*) FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                      (self._community.database_id, node.my_member.database_id, 42)).next()
        self.assertGreater(nrpackets, 0, "message isn't stored")
