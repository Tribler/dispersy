import logging
logger = logging.getLogger(__name__)

from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestMissingIdentity(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_incoming_missing_identity(self):
        """
        NODE generates a missing-identity message and SELF responds.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        missing = DebugNode(community)
        missing.init_socket()
        missing.init_my_member()

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # use NODE to fetch the identities for MISSING
        node.drop_packets()
        node.give_message(node.create_dispersy_missing_identity(missing.my_member, 10, community.my_candidate))
        responses = node.receive_messages()

        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-identity")
            self.assertEqual(response.authentication.member.public_key, missing.my_member.public_key)


    @call_on_dispersy_thread
    def test_outgoing_missing_identity(self):
        """
        NODE generates data and sends it to SELF, resulting in SELF asking for the missing identity.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False, identity=False)
        node.drop_packets()

        # NODE sends a message to SELF
        node.give_message(node.create_full_sync_text("Hello World", 10))

        # SELF must not yet process the 'Hello World' message
        self.assertEqual(community.fetch_messages(u"full-sync-text"), [])

        # SELF must send a missing-identity to NODE
        responses = node.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, response in responses:
            self.assertEqual(response.name, u"dispersy-missing-identity")
            self.assertEqual(response.payload.mid, node.my_member.mid)

        # NODE sends the identity to SELF
        node.give_message(node.create_dispersy_identity(2))

        # SELF must now process and store the 'Hello World' message
        messages = community.fetch_messages(u"full-sync-text")
        self.assertEqual(len(messages), 1)
        for message in messages:
            self.assertEqual(message.payload.text, "Hello World")
