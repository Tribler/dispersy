from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestDestroyCommunity(DispersyTestFunc):
    # TODO: test that after a hard-kill, all new incoming messages are dropped.
    # TODO: test that after a hard-kill, nothing is added to the candidate table anymore

    @call_on_dispersy_thread
    def test_hard_kill(self):
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        message = community.get_meta_message(u"full-sync-text")

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        # should be no messages from NODE yet
        times = list(self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id)))
        self.assertEqual(times, [])

        # send a message
        global_time = 10
        node.give_message(node.create_full_sync_text("should be accepted (1)", global_time))
        times = [x for x, in self._dispersy.database.execute(u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?", (community.database_id, node.my_member.database_id, message.database_id))]
        self.assertEqual(len(times), 1)
        self.assertIn(global_time, times)

        # destroy the community
        community.create_destroy_community(u"hard-kill")
        yield 0.555

        # node should receive the dispersy-destroy-community message
        _, message = node.receive_message(message_names=[u"dispersy-destroy-community"])
        self.assertFalse(message.payload.is_soft_kill)
        self.assertTrue(message.payload.is_hard_kill)

        # the malicious_proof table must be empty
        self.assertEqual(list(self._dispersy.database.execute(u"SELECT * FROM malicious_proof WHERE community = ?", (community.database_id,))), [])

        # the database should have been cleaned
        # todo
