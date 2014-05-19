from unittest import TestCase

# Do not (re)move the reactor import, even if we aren't using it
# (nose starts the reactor in a separate thread when importing this)
from nose.twistedtools import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.threads import blockingCallFromThread

from ..discovery.bootstrap import Bootstrap
from ..dispersy import Dispersy
from ..endpoint import ManualEnpoint
from ..logger import get_logger
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode


# Kill bootstraping so it doesn't mess with the tests
Bootstrap.enabled = False


logger = get_logger(__name__)


class DispersyTestFunc(TestCase):

    def on_callback_exception(self, exception, is_fatal):
        return True

    def setUp(self):
        super(DispersyTestFunc, self).setUp()

        self.dispersy_objects = []

        self.assertFalse(reactor.getDelayedCalls())
        self._mm = None
        self._mm, = self.create_nodes()

        self._dispersy = self._mm._dispersy
        self._community = self._mm._community

    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()

        for dispersy in self.dispersy_objects:
            blockingCallFromThread(reactor, dispersy.stop)

        pending = reactor.getDelayedCalls()
        if pending:
            logger.warning("Found delayed calls in reactor:")
            for dc in pending:
                fun = dc.func
                logger.warning("    %s", fun)
            logger.warning("Failing")
        assert not pending, "The reactor was not clean after shutting down all dispersy instances."

    def create_nodes(self, amount=1, store_identity=True, tunnel=False, communityclass=DebugCommunity):
        @inlineCallbacks
        def _create_nodes(amount, store_identity, tunnel, communityclass):
            nodes = []
            for _ in range(amount):
                # TODO(emilon): do the log observer stuff instead
                # callback.attach_exception_handler(self.on_callback_exception)

                dispersy = Dispersy(ManualEnpoint(0), u".", u":memory:")
                dispersy.start()

                self.dispersy_objects.append(dispersy)

                node = DebugNode(self, dispersy, communityclass, c_master_member=self._mm)
                yield node.init_my_member(tunnel=tunnel, store_identity=store_identity)

                nodes.append(node)
            logger.debug("create_nodes, nodes created: %s", nodes)
            returnValue(nodes)

        return blockingCallFromThread(reactor, _create_nodes, amount, store_identity, tunnel, communityclass)
