from time import time, sleep
from threading import Thread, Event

from ..logger import get_logger
logger = get_logger(__name__)

from unittest import skip

from .dispersytestclass import DispersyTestFunc, call_on_mm_thread


class TestCallback(DispersyTestFunc):

    def test_register(self):

        def register_func():
            container[0] += 1
            if container[0] == 1000:
                event.set()

        event = Event()
        container = [0]
        register = self._dispersy.callback.register

        for _ in xrange(1000):
            register(register_func)

        assert event.wait(10)
        assert container[0] == 1000

    def test_register_delay(self):
        def register_delay_func():
            container[0] += 1
            if container[0] == 1000:
                event.set()

        event = Event()
        container = [0]
        register = self._dispersy.callback.register

        pre_time = time()
        for _ in xrange(1000):
            register(register_delay_func, delay=1.0)

        assert event.wait(10)
        run_time = time() - pre_time
        assert container[0] == 1000
        assert run_time > 1

    def test_generator(self):
        def generator_func():
            for _ in xrange(10):
                yield 0.01
            container[0] += 1
            if container[0] == 100:
                event.set()

        event = Event()
        container = [0]
        register = self._dispersy.callback.register

        pre_time = time()
        for _ in xrange(100):
            register(generator_func)

        assert event.wait(10)
        run_time = time() - pre_time
        assert container[0] == 100, container[0]
        assert run_time > 0.001 * 10

    def test_call_timeout(self):
        """
        Tests the timeout feature of Callback.call.

        The Callback.call method can be used from the same thread, or from another thread.  This
        unit-test tests both these cases.
        """
        def generator_func(count, soft_delay, hard_delay):
            for _ in xrange(count):
                yield soft_delay
                sleep(hard_delay)

        # add 'noise', i.e. something else the callback should be handling at the same time
        self._dispersy.callback.register(generator_func, (50, 0.1, 0.5))

        def timeout_function():
            begin = time()
            result = self._dispersy.callback.call(generator_func, (1, 2.0, 0.0), timeout=1.0, default="timeout")
            end = time()
            self.assertGreaterEqual(end - begin, 1.0)
            self.assertEqual(result, "timeout")

        # test on the same thread
        timeout_function()

        # test on a separate thread
        thread = Thread(target=timeout_function)
        thread.start()
        thread.join(2.0)
        self.assertFalse(thread.is_alive())
