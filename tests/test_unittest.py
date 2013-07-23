from unittest import expectedFailure
import logging
logger = logging.getLogger(__name__)

from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread

class TestUnittestFunc(DispersyTestFunc):
    """
    Tests ensuring that an exception anywhere in _dispersy.callback is propagated to the unittest framework.
    """

    def addExpectedFailure(self, test, err):
        if isinstance(err, KeyError) and err.message == "This must fail":
            return super(TestUnittestFunc, self).addExpectedFailure(test, err)

        if isinstance(err, AssertionError) and err.message == "This must fail":
            return super(TestUnittestFunc, self).addExpectedFailure(test, err)

        # unexpected error
        return super(TestUnittestFunc, self).addError(test, err)

    @expectedFailure
    @call_on_dispersy_thread
    def test_assert(self):
        " Trivial assert. "
        assert False, "This must fail"

    @expectedFailure
    @call_on_dispersy_thread
    def test_KeyError(self):
        " Trivial KeyError. "
        raise KeyError("This must fail")

    @expectedFailure
    @call_on_dispersy_thread
    def test_assert_callback(self):
        " Assert within a registered task. "
        def task():
            assert False, "This must fail"
        self._dispersy.callback.register(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_KeyError_callback(self):
        " KeyError within a registered task. "
        def task():
            raise KeyError("This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_assert_callback_generator(self):
        " Assert within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            assert False, "This must fail"
        self._dispersy.callback.register(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_KeyError_callback_generator(self):
        " KeyError within a registered generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self._dispersy.callback.register(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_assert_callback_call(self):
        " Assert within a 'call' task. "
        def task():
            assert False, "This must fail"
        self._dispersy.callback.call(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_KeyError_callback_call(self):
        " KeyError within a 'call' task. "
        def task():
            raise KeyError("This must fail")
        self._dispersy.callback.call(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_assert_callback_call_generator(self):
        " Assert within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            assert False, "This must fail"
        self._dispersy.callback.call(task)
        yield 10.0

    @expectedFailure
    @call_on_dispersy_thread
    def test_KeyError_callback_call_generator(self):
        " KeyError within a 'call' generator task. "
        def task():
            yield 0.1
            yield 0.1
            raise KeyError("This must fail")
        self._dispersy.callback.call(task)
        yield 10.0
