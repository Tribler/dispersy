import os
import logging
from unittest import TestCase

# Do not (re)move the reactor import, even if we aren't using it
# (nose starts the reactor in a separate thread when importing this)
from nose.twistedtools import reactor
from twisted.internet.defer import inlineCallbacks, returnValue

from ..discovery.community import PEERCACHE_FILENAME
from ..dispersy import Dispersy
from ..endpoint import ManualEnpoint
from ..util import blockingCallFromThread
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode


# use logger.conf if it exists
if os.path.exists("logger.conf"):
    # will raise an exception when logger.conf is malformed
    logging.config.fileConfig("logger.conf")
# fallback to basic configuration when needed
logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s")


class DispersyTestFunc(TestCase):

    def __init__(self, *args, **kwargs):
        super(DispersyTestFunc, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(self.__class__.__name__)

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
            dispersy.stop()

            peercache = os.path.join(dispersy._working_directory, PEERCACHE_FILENAME)
            if os.path.isfile(peercache):
                os.unlink(peercache)

        pending = reactor.getDelayedCalls()
        if pending:
            self._logger.warning("Found delayed calls in reactor:")
            for dc in pending:
                fun = dc.func
                self._logger.warning("    %s", fun)
            self._logger.warning("Failing")
        assert not pending, "The reactor was not clean after shutting down all dispersy instances."

    def create_nodes(self, amount=1, store_identity=True, tunnel=False, communityclass=DebugCommunity, autoload_discovery=False):
        @inlineCallbacks
        def _create_nodes(amount, store_identity, tunnel, communityclass, autoload_discovery):
            nodes = []
            for _ in range(amount):
                # TODO(emilon): do the log observer stuff instead
                # callback.attach_exception_handler(self.on_callback_exception)

                dispersy = Dispersy(ManualEnpoint(0), u".", u":memory:")
                dispersy.start(autoload_discovery=autoload_discovery)

                self.dispersy_objects.append(dispersy)

                node = DebugNode(self, dispersy, communityclass, c_master_member=self._mm)
                yield node.init_my_member(tunnel=tunnel, store_identity=store_identity)

                nodes.append(node)
            self._logger.debug("create_nodes, nodes created: %s", nodes)
            returnValue(nodes)

        return blockingCallFromThread(reactor, _create_nodes, amount, store_identity, tunnel, communityclass, autoload_discovery)
