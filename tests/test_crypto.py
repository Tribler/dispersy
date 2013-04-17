from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestClass, call_on_dispersy_thread

class TestCrypto(DispersyTestClass):
    @call_on_dispersy_thread
    def test_invalid_public_key(self):
        """
        SELF receives a dispersy-identity message containing an invalid public-key.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False, identity=False)

        # create dispersy-identity message
        global_time = 10
        message = node.create_dispersy_identity(global_time)

        # replace the valid public-key with an invalid one
        public_key = node.my_member.public_key
        self.assertIn(public_key, message.packet)
        invalid_packet = message.packet.replace(public_key, "I" * len(public_key))
        self.assertNotEqual(message.packet, invalid_packet)

        # give invalid message to SELF
        node.give_packet(invalid_packet)

        # ensure that the message was not stored in the database
        ids = list(self._dispersy.database.execute(u"SELECT id FROM sync WHERE community = ? AND packet = ?",
                                                   (community.database_id, buffer(invalid_packet))))
        self.assertEqual(ids, [])

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
