from time import sleep

from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_mm_thread
logger = get_logger(__name__)

class TestDestroyCommunity(DispersyTestFunc):

    def test_hard_kill(self):
        node, = self.create_nodes(1)

        message = node.create_full_sync_text("Should be remove" , 42)
        node.give_message(message, node)

        node.assert_count(message, 1)

        dmessage = self._mm.create_destroy_community(u"hard-kill")
        node.give_message(dmessage, self._mm)

        node.assert_count(message, 0)

    def test_hard_kill_without_permission(self):
        node, other = self.create_nodes(2)
        node.send_identity(other)

        message = node.create_full_sync_text("Should be remove" , 42)
        node.give_message(message, node)

        node.assert_count(message, 1)

        dmessage = other.create_destroy_community(u"hard-kill")
        node.give_message(dmessage, self._mm)

        node.assert_count(message, 1)
