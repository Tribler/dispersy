from unittest import TestCase
from .debugcommunity.node import DebugNode
from .debugcommunity.community import DebugCommunity

from ..callback import Callback
from ..dispersy import Dispersy
from ..endpoint import ManualEnpoint
from ..logger import get_logger

logger = get_logger(__name__)

def call_on_mm_thread(func):
    def helper(*args, **kargs):
        return args[0]._mm.call(func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper

class DispersyTestFunc(TestCase):

    # every Dispersy instance gets its own Callback thread with its own number.  this is useful in
    # some debugging scenarios.
    _thread_counter = 0

    def on_callback_exception(self, exception, is_fatal):
        return True

    def setUp(self):
        super(DispersyTestFunc, self).setUp()

        self.dispersy_objects = []

        self._mm = None
        self._mm, = self.create_nodes()

        self._dispersy = self._mm._dispersy
        self._community = self._mm._community

    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()

        for dispersy in self.dispersy_objects:
            dispersy.stop()

    def create_nodes(self, amount=1, store_identity=True, tunnel=False, communityclass=DebugCommunity):
        nodes = []
        for _ in range(amount):
            callback = Callback("Test-%d" % (self._thread_counter,))
            callback.attach_exception_handler(self.on_callback_exception)

            dispersy = Dispersy(callback, ManualEnpoint(0), u".", u":memory:")
            dispersy.start()

            self.dispersy_objects.append(dispersy)

            def create_node():
                node = DebugNode(self, dispersy, communityclass, c_master_member=self._mm)
                callback.call(node.init_my_member, kargs={'tunnel':tunnel, 'store_identity':store_identity})
                return node

            nodes.append(callback.call(create_node))
        return nodes
