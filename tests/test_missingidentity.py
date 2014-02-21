from ..logger import get_logger
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestMissingIdentity(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_incoming_missing_identity(self):
        """
        NODE generates a other-identity message and OTHER responds.
        """
        node, other = self.create_nodes(2)

        # use NODE to fetch the identities for OTHER
        other.give_message(node.create_dispersy_missing_identity(other.my_member, 10), node)

        # MISSING should reply with a dispersy-identity message
        responses = node.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-identity")
            self.assertEqual(response.authentication.member.public_key, other.my_member.public_key)


    @call_on_dispersy_thread
    def test_outgoing_missing_identity(self):
        """
        NODE generates data and sends it to SELF, resulting in SELF asking for the other identity.
        """
        node, = self.create_nodes(1)
        other, = self.create_nodes(1, store_identity=False)

        # Give NODE a message from OTHER
        message = other.create_full_sync_text("Hello World", 10)
        node.give_message(message, other)

        # NODE must not yet process the 'Hello World' message, as it hasnt received the identity message yet
        self.assert_not_stored(message)

        # NODE must send a other-identity to OTHER
        responses = other.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-missing-identity")
            self.assertEqual(response.payload.mid, other.my_member.mid)

        # OTHER sends the identity to NODE
        node.give_message(other.create_dispersy_identity(2), other)

        # NODE must now process and store the 'Hello World' message
        self.assert_is_stored(message)
