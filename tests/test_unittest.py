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
                    # matches the pre-programmes exception, should not fail
                    return

                # not one of the pre-programmed exceptions, test should indicate failure
                raise

            # expected an exception, fail
            raise AssertionError("Expected an exception")

        helper2.__name__ = func.__name__
        return helper2
    return helper1

class TestUnittest(DispersyTestFunc):
    """
    Tests ensuring that an exception anywhere in _dispersy.callback is propagated to the unittest framework.

    The 'strict' tests will ensure that any exception results in an early shutdown.  Early shutdown
    causes the call_on_dispersy_thread generator to receive a Shutdown command, resulting in a
    RuntimeError("Early shutdown") exception on the caller.

    Non 'strict' tests will result in the Callback ignoring KeyError and AssertionError exceptions.
    """

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert(self):
        " Trivial assert. "
        self.assertTrue(False, "This must fail")
        self.fail("Should not reach this")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError(self):
        " Trivial KeyError. "
        raise KeyError("This must fail")

    @failure_to_success(RuntimeError, "Early shutdown")
    @call_on_dispersy_thread
    def test_assert_strict_callback(self):
        " Assert within a registered task. "
        def task():
            self.assertTrue(False, "This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.register(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(RuntimeError, "Early shutdown")
    @call_on_dispersy_thread
    def test_KeyError_strict_callback(self):
        " KeyError within a registered task with strict enabled. "
        def task():
            raise KeyError("This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.register(task)
        yield 1.0
        self.fail("Should not reach this")

    @call_on_dispersy_thread
    def test_KeyError_callback(self):
        " KeyError within a registered task. "
        def task():
            raise KeyError("This must be ignored")
        self.enable_strict = False
        self._dispersy.callback.register(task)
        yield 1.0
        self.assertTrue(True)

    @failure_to_success(RuntimeError, "Early shutdown")
    @call_on_dispersy_thread
    def test_assert_strict_callback_generator(self):
        " Assert within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.register(task)
        yield 1.0
        self.fail("Should not reach this")

    @call_on_dispersy_thread
    def test_assert_callback_generator(self):
        " Assert within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must be ignored")
        self.enable_strict = False
        self._dispersy.callback.register(task)
        yield 1.0
        self.assertTrue(True)

    @failure_to_success(RuntimeError, "Early shutdown")
    @call_on_dispersy_thread
    def test_KeyError_strict_callback_generator(self):
        " KeyError within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.register(task)
        yield 1.0
        self.fail("Should not reach this")

    @call_on_dispersy_thread
    def test_KeyError_callback_generator(self):
        " KeyError within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must be ignored")
        self.enable_strict = False
        self._dispersy.callback.register(task)
        yield 1.0
        self.assertTrue(True)

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_strict_callback_call(self):
        " Assert within a 'call' task. "
        def task():
            self.assertTrue(False, "This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback_call(self):
        " Assert within a 'call' task. "
        def task():
            self.assertTrue(False, "This must fail")
        self.enable_strict = False
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_strict_callback_call(self):
        " KeyError within a 'call' task. "
        def task():
            raise KeyError("This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback_call(self):
        " KeyError within a 'call' task. "
        def task():
            raise KeyError("This must fail")
        self.enable_strict = False
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_strict_callback_call_generator(self):
        " Assert within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(AssertionError, "This must fail")
    @call_on_dispersy_thread
    def test_assert_callback_call_generator(self):
        " Assert within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            self.assertTrue(False, "This must fail")
        self.enable_strict = False
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_strict_callback_call_generator(self):
        " KeyError within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self.assertTrue(self.enable_strict)
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")

    @failure_to_success(KeyError, "This must fail")
    @call_on_dispersy_thread
    def test_KeyError_callback_call_generator(self):
        " KeyError within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self.enable_strict = False
        self._dispersy.callback.call(task)
        yield 1.0
        self.fail("Should not reach this")
