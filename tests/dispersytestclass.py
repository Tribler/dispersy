import os
import logging
import threading
from unittest import TestCase
from tempfile import mkdtemp

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.logger import formatEvent, globalLogPublisher, LogLevel

from ..discovery.community import PEERCACHE_FILENAME
from ..dispersy import Dispersy
from ..endpoint import ManualEnpoint
from ..util import blocking_call_on_reactor_thread
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode


# use logger.conf if it exists
if os.path.exists("logger.conf"):
    # will raise an exception when logger.conf is malformed
    logging.basicConfig(filename="logger.conf")
# fallback to basic configuration when needed
logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s")


class DispersyTestFunc(TestCase):

    def __init__(self, *args, **kwargs):
        super(DispersyTestFunc, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(self.__class__.__name__)
        self._fired_unhandled_exceptions = []
        self._starting_threads = []

    def on_callback_exception(self, exception, is_fatal):
        return True

    def failure_check(self, evt):
        if evt.get("failure", None):
            self._fired_unhandled_exceptions.append(formatEvent(evt))

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def setUp(self):
        self._starting_threads = [t.name for t in threading.enumerate()]

        super(DispersyTestFunc, self).setUp()

        self.dispersy_objects = []

        self.assertFalse(reactor.getDelayedCalls())
        """" Central node that is also used for master member. """
        self._mm = None
        self._mm, = yield self.create_nodes()

        self._dispersy = self._mm._dispersy
        self._community = self._mm._community

        self._fired_unhandled_exceptions = []

        globalLogPublisher.addObserver(self.failure_check)

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def tearDown(self):
        super(DispersyTestFunc, self).tearDown()

        for dispersy in self.dispersy_objects:
            yield dispersy.stop()

            peercache = os.path.join(dispersy._working_directory, PEERCACHE_FILENAME)
            if os.path.isfile(peercache):
                os.unlink(peercache)

        if self._dispersy.running:
            yield self._dispersy.stop()

        globalLogPublisher.removeObserver(self.failure_check)

        pending = reactor.getDelayedCalls()
        if pending:
            self._logger.warning("Found delayed calls in reactor:")
            for dc in pending:
                fun = dc.func
                self._logger.warning("    %s", fun)
            self._logger.warning("Failing")
        self.assertFalse(pending, "The reactor was not clean after shutting down all dispersy instances.")

        if self._fired_unhandled_exceptions:
            self._logger.error("Found %d unhandled exceptions on threads:", len(self._fired_unhandled_exceptions))
            for exception in self._fired_unhandled_exceptions:
                self._logger.error(exception)
        self.assertFalse(self._fired_unhandled_exceptions)

        # We should not have any rogue threads left.
        rogue_threads = False
        for thread in threading.enumerate():
            if thread.name not in self._starting_threads:
                rogue_threads = True
                self._logger.error("Found rogue thread: %s", thread)
        self.assertFalse(rogue_threads, "Rogue threads active, see log")

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def create_nodes(self, amount=1, store_identity=True, tunnel=False, community_class=DebugCommunity,
                     autoload_discovery=False, memory_database=True):
        """
        Creates dispersy nodes running a community.
        :param amount: The amount of nodes that need to be created.
        :param store_identity: If the identity is send to the central node.
        :param tunnel: If the nodes is behind a tunnel or not
        :param community_class: The class that the node will autoload.
        :param autoload_discovery: If the discovery community is autoloaded.
        :param memory_database: If a memory database is used.
        :return: [(DebugNode)]
        """

        """ Override this method in a subclass with a different community class to test communities. """
        nodes = []
        for _ in range(amount):
            # TODO(emilon): do the log observer stuff instead
            # callback.attach_exception_handler(self.on_callback_exception)
            memory_database_argument = {'database_filename': u":memory:"} if memory_database else {}
            working_directory = unicode(mkdtemp(suffix="_dispersy_test_session"))

            dispersy = Dispersy(ManualEnpoint(0), working_directory, **memory_database_argument)
            dispersy.start(autoload_discovery=autoload_discovery)

            self.dispersy_objects.append(dispersy)

            node = self._create_node(dispersy, community_class, self._mm)
            yield node.init_my_member(tunnel=tunnel, store_identity=store_identity)

            nodes.append(node)

        self._logger.debug("create_nodes, nodes created: %s", nodes)
        returnValue(nodes)

    def _create_node(self, dispersy, community_class, c_master_member):
        return DebugNode(self, dispersy, community_class, c_master_member)
