from thread import get_ident
from threading import currentThread

from ..callback import Callback

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
        return True

    def call(self, call, args=(), kargs=None, delay=0.0, priority=0, id_="", include_id=False, timeout=0.0, default=None):
        if kargs:
            return call(*args, **kargs)
        else:
            return call(*args)

