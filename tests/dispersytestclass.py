from unittest import TestCase

# Do not remove the reactor import, even if we aren't using it (nose starts the reactor when importing this)
from nose.twistedtools import reactor, deferred


from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import blockingCallFromThread

# Kill bootstraping so it doesn't mess up with the tests
from ..bootstrap import Bootstrap
Bootstrap.enabled = False


from ..callback import TwistedCallback
from ..dispersy import Dispersy
from ..endpoint import ManualEnpoint
from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode

import sys

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
        @inlineCallbacks
        def _create_nodes(amount, store_identity, tunnel, communityclass):
            nodes = []
            for _ in range(amount):
                DispersyTestFunc._thread_counter += 1
                callback = TwistedCallback("Test-%d" % (self._thread_counter,))
                callback.attach_exception_handler(self.on_callback_exception)

                dispersy = Dispersy(callback, ManualEnpoint(0), u".", u":memory:")
                dispersy.start()

                self.dispersy_objects.append(dispersy)

                node = DebugNode(self, dispersy, communityclass, c_master_member=self._mm)
                yield node.init_my_member(tunnel=tunnel, store_identity=store_identity)

                nodes.append(node)
            logger.debug("create_nodes, nodes created: %s", nodes)
            returnValue(nodes)

        return blockingCallFromThread(reactor, _create_nodes, amount, store_identity, tunnel, communityclass)
