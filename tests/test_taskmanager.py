from .dispersytestclass import DispersyTestFunc
from ..taskmanager import TaskManager

from twisted.internet import reactor
from twisted.internet.task import LoopingCall

class TaskManagerTestFunc(DispersyTestFunc):

    def setUp(self):
        self.dispersy_objects = []
        self.tm = TaskManager()

    def tearDown(self):
        self.tm.cancel_all_pending_tasks()

        DispersyTestFunc.tearDown(self)

    def test_callLater(self):
        self.tm.register_task("test", reactor.callLater(10, self.do_nothing))
        assert self.tm.is_pending_task_active("test")

    def test_callLaterAndCancel(self):
        self.tm.register_task("test", reactor.callLater(10, self.do_nothing))
        self.tm.cancel_pending_task("test")
        assert not self.tm.is_pending_task_active("test")

    def test_loopingCall(self):
        self.tm.register_task("test", LoopingCall(self.do_nothing)).start(10, now=True)
        assert self.tm.is_pending_task_active("test")

    def test_loopingCallAndCancel(self):
        self.tm.register_task("test", LoopingCall(self.do_nothing)).start(10, now=True)
        self.tm.cancel_pending_task("test")
        assert not self.tm.is_pending_task_active("test")

    def do_nothing(self):
        pass
