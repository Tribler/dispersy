from .dispersytestclass import DispersyTestFunc


class TestIdenticalPayload(DispersyTestFunc):

    def test_drop_identical_payload(self):
        """
        NODE creates two messages with the same community/member/global-time.
        Sends both of them to OTHER, which should drop the "lowest" one.
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

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

        other.assert_not_stored(messages[0])
        other.assert_is_stored(messages[1])

    def test_drop_identical(self):
        """
        NODE creates one message, sends it to OTHER twice
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        # create messages
        message = node.create_full_sync_text("Message", 42)

        # give messages to other
        other.give_message(message, node)
        other.give_message(message, node)

        other.assert_is_stored(message)
