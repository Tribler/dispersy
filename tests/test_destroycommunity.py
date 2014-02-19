from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)

class TestDestroyCommunity(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_hard_kill(self):
        centralnode = DebugNode(self._community)
        centralnode.init_socket()
        centralnode.init_my_member()

        other = DebugNode(self._community, centralnode)
        other.init_socket()
        other.init_my_member()

        centralnode._community.create_destroy_community(u"hard-kill")

        # node should receive the dispersy-destroy-community message
        _, message = other.receive_message(names=[u"dispersy-destroy-community"])
        self.assertFalse(message.payload.is_soft_kill)
        self.assertTrue(message.payload.is_hard_kill)
