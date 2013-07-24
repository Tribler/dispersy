import logging
logger = logging.getLogger(__name__)

from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread

def failure_to_success(exception_class, exception_message):
    def helper1(func):
        def helper2(*args, **kargs):
            try:
                func(*args, **kargs)
            except Exception as exception:
                if isinstance(exception, exception_class) and exception.message == exception_message:
                    return

                # not one of the pre-programmed exceptions, test should indicate failure
                raise

        helper2.__name__ = func.__name__
        return helper2
    return helper1

class TestUnittest(DispersyTestFunc):
    """
    Tests ensuring that an exception anywhere in _dispersy.callback is propagated to the unittest framework.
    """

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert(self):
        " Trivial assert. "
        self.assertTrue(False, "This must fail")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError(self):
        " Trivial KeyError. "
        raise KeyError("This must fail")

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback(self):
        " Assert within a registered task. "
        def task():
            self.assertTrue(False, "This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback(self):
        " KeyError within a registered task. "
        def task():
            raise KeyError("This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback_generator(self):
        " Assert within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback_generator(self):
        " KeyError within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback_call(self):
        " Assert within a 'call' task. "
        def task():
            self.assertTrue(False, "This must fail")
        self._dispersy.callback.call(task)
        yield 10.0

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback_call(self):
        " KeyError within a 'call' task. "
        def task():
            raise KeyError("This must fail")
        self._dispersy.callback.call(task)
        yield 10.0

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback_call_generator(self):
        " Assert within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must fail")
        self._dispersy.callback.call(task)
        yield 10.0

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback_call_generator(self):
        " KeyError within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self._dispersy.callback.call(task)
        yield 10.0
