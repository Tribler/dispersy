from twisted.logger import LimitedHistoryLogObserver, globalLogPublisher

from .dispersytestclass import DispersyTestFunc
from ..tool.clean_observers import clean_twisted_observers


class TestCleanObservers(DispersyTestFunc):

    def check_leftover_observers(self, publisher):
        if not hasattr(publisher, "_observers"):
            return
        for o in publisher._observers:
            self.assertIsNot(o, LimitedHistoryLogObserver)
            self.check_leftover_observers(o)

    def test_clean_loggers(self):
        clean_twisted_observers(globalLogPublisher)
        self.check_leftover_observers(globalLogPublisher)
