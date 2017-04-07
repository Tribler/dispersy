from ..taskmanager import TaskManager
from ..util import blocking_call_on_reactor_thread
from .dispersytestclass import DispersyTestFunc
from nose.tools import assert_raises
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.task import Clock, LoopingCall


class TaskManagerTestFunc(DispersyTestFunc):

    @blocking_call_on_reactor_thread
    def setUp(self):
        super(TaskManagerTestFunc, self).setUp()

        self.dispersy_objects = []
        self.tm = TaskManager()
        self.tm._reactor = Clock()

        self.counter = 0

    def tearDown(self):
        self.tm.cancel_all_pending_tasks()

        DispersyTestFunc.tearDown(self)

    @blocking_call_on_reactor_thread
    def test_call_later(self):
        self.tm.register_task("test", reactor.callLater(10, self.do_nothing))
        assert self.tm.is_pending_task_active("test")

    @blocking_call_on_reactor_thread
    def test_call_later_and_cancel(self):
        self.tm.register_task("test", reactor.callLater(10, self.do_nothing))
        self.tm.cancel_pending_task("test")
        assert not self.tm.is_pending_task_active("test")

    @blocking_call_on_reactor_thread
    def test_looping_call(self):
        self.tm.register_task("test", LoopingCall(self.do_nothing)).start(10, now=True)
        assert self.tm.is_pending_task_active("test")

    @blocking_call_on_reactor_thread
    def test_looping_call_and_cancel(self):
        self.tm.register_task("test", LoopingCall(self.do_nothing)).start(10, now=True)
        self.tm.cancel_pending_task("test")
        assert not self.tm.is_pending_task_active("test")

    @blocking_call_on_reactor_thread
    def test_delayed_looping_call_requires_interval(self):
        assert_raises(ValueError, self.tm.register_task, "test", LoopingCall(self.do_nothing), delay=1)

    @blocking_call_on_reactor_thread
    def test_delayed_deferred_requires_value(self):
        assert_raises(ValueError, self.tm.register_task, "test", LoopingCall(self.do_nothing), delay=1)

    @blocking_call_on_reactor_thread
    def test_delayed_looping_call_requires_LoopingCall_or_Deferred(self):
        assert_raises(ValueError, self.tm.register_task, "test not Deferred nor LoopingCall",
                      self.tm._reactor.callLater(0, self.do_nothing), delay=1)

    @blocking_call_on_reactor_thread
    def test_delayed_looping_call_register_and_cancel_pre_delay(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm.register_task("test", LoopingCall(self.do_nothing), delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))

    @blocking_call_on_reactor_thread
    def test_delayed_looping_call_register_wait_and_cancel(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        lc = LoopingCall(self.count)
        lc.clock = self.tm._reactor
        self.tm.register_task("test", lc, delay=1, interval=1)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the counter has increased by one and the task is still active.
        self.tm._reactor.advance(1)
        self.assertEquals(1, self.counter)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one more second, the counter should be 2
        self.tm._reactor.advance(1)
        self.assertEquals(2, self.counter)
        # After canceling the task the counter should stop increasing
        self.tm.cancel_pending_task("test")
        self.assertFalse(self.tm.is_pending_task_active("test"))
        self.tm._reactor.advance(10)
        self.assertEquals(2, self.counter)

    @blocking_call_on_reactor_thread
    def test_delayed_deferred(self):
        self.assertFalse(self.tm.is_pending_task_active("test"))
        d = Deferred()
        d.addCallback(self.set_counter)
        self.tm.register_task("test", d, delay=1, value=42)
        self.assertTrue(self.tm.is_pending_task_active("test"))
        # After one second, the deferred has fired
        self.tm._reactor.advance(1)
        self.assertEquals(42, self.counter)
        self.assertFalse(self.tm.is_pending_task_active("test"))

    def count(self):
        self.counter += 1

    def set_counter(self, value):
        self.counter = value

    def do_nothing(self):
        pass
