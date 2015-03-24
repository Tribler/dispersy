from .dispersytestclass import DispersyTestFunc


class TestMissingIdentity(DispersyTestFunc):

    def test_incoming_missing_identity(self):
        """
        NODE generates a missing-identity message and OTHER responds.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # use NODE to fetch the identities for OTHER
        other.give_message(node.create_missing_identity(other.my_member, 10), node)

        # MISSING should reply with a dispersy-identity message
        responses = node.receive_messages()

        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-identity")
            self.assertEqual(response.authentication.member.public_key, other.my_member.public_key)

    def test_outgoing_missing_identity(self):
        """
        NODE generates data and sends it to OTHER, resulting in OTHER asking for the other identity.
        """
        node, other = self.create_nodes(2)

        # Give OTHER a message from NODE
        message = node.create_full_sync_text("Hello World", 10)
        other.give_message(message, node)

        # OTHER must not yet process the 'Hello World' message, as it hasnt received the identity message yet
        other.assert_not_stored(message)

        # OTHER must send a missing-identity to NODEs
        responses = node.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-missing-identity")
            self.assertEqual(response.payload.mid, node.my_member.mid)

        # NODE sends the identity to OTHER
        node.send_identity(other)

        # OTHER must now process and store the 'Hello World' message
        other.assert_is_stored(message)

    def test_outgoing_missing_identity_twice(self):
        """
        NODE generates data and sends it to OTHER twice, resulting in OTHER asking for the other identity once.
        """
        node, other = self.create_nodes(2)

        # Give OTHER a message from NODE
        message = node.create_full_sync_text("Hello World", 10)
        other.give_message(message, node)

        # OTHER must not yet process the 'Hello World' message, as it hasnt received the identity message yet
        other.assert_not_stored(message)

        # Give OTHER the message once again
        other.give_message(message, node)

        # OTHER must send a single missing-identity to NODE
        responses = node.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-missing-identity")
            self.assertEqual(response.payload.mid, node.my_member.mid)

        # NODE sends the identity to OTHER
        node.send_identity(other)

        # OTHER must now process and store the 'Hello World' message
        other.assert_is_stored(message)
