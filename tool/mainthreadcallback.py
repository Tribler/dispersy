from thread import get_ident
from threading import currentThread

from ..callback import Callback
from ..logger import get_logger
logger = get_logger(__name__)


class MainThreadCallback(Callback):

    """
    MainThreadCallback must be used when Dispersy must run on the main process thread.
    """
    def __init__(self, name="Generic-Callback"):
        assert isinstance(name, str), type(name)
        super(MainThreadCallback, self).__init__(name)

        # we will be running on this thread
        self._thread_ident = get_ident()

        # set the thread name
        currentThread().setName(name)

    def start(self, *args, **kargs):
        with self._lock:
            self._state = "STATE_RUNNING"
            logger.debug("STATE_RUNNING")

        return self.is_running
