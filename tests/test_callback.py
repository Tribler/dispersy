from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestCallback(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_register(self):
        def register_func():
            container[0] += 1

        container = [0]
        register = self._dispersy.callback.register

        for _ in xrange(1000):
            register(register_func)

        while container[0] < 1000:
            yield 0.1

    @call_on_dispersy_thread
    def test_register_delay(self):
        def register_delay_func():
            container[0] += 1

        container = [0]
        register = self._dispersy.callback.register

        for _ in xrange(1000):
            register(register_delay_func, delay=1.0)

        while container[0] < 1000:
            yield 0.1

    @call_on_dispersy_thread
    def test_generator(self):
        def generator_func():
            for _ in xrange(10):
                yield 0.1
            container[0] += 1

        container = [0]
        register = self._dispersy.callback.register

        for _ in xrange(100):
            register(generator_func)

        while container[0] < 100:
            yield 0.1

    @call_on_dispersy_thread
    def test_priority(self):
        """
        A generator must retain its priority for every subsequent call.
        """
        def generator_func(priority):
            for _ in xrange(5):
                container.append("generator_func(%d)" % priority)
                yield 0.0

        def func(priority):
            container.append("func(%d)" % priority)

        container = []
        register = self._dispersy.callback.register

        register(generator_func, (-240,), priority=-240)
        register(generator_func, (-250,), priority=-250)
        register(func, (-225,), priority=-225)
        register(func, (-255,), priority=-255)
        register(generator_func, (240,), priority=240)
        register(generator_func, (250,), priority=250)
        register(func, (235,), priority=235)
        register(func, (-245,), priority=-245)
        register(func, (225,), priority=225)
        register(generator_func, (230,), priority=230)
        register(generator_func, (-230,), priority=-230)
        register(func, (255,), priority=255)
        register(func, (245,), priority=245)
        register(func, (-235,), priority=-235)
        self.assertEqual(container, [])

        # wait for a second for all calls to be made
        yield 1.0

        # we expect:
        expecting = []
        expecting.append("func(255)")
        expecting.extend(["generator_func(250)"] * 5)
        expecting.append("func(245)")
        expecting.extend(["generator_func(240)"] * 5)
        expecting.append("func(235)")
        expecting.extend(["generator_func(230)"] * 5)
        expecting.append("func(225)")
        expecting.append("func(-225)")
        expecting.extend(["generator_func(-230)"] * 5)
        expecting.append("func(-235)")
        expecting.extend(["generator_func(-240)"] * 5)
        expecting.append("func(-245)")
        expecting.extend(["generator_func(-250)"] * 5)
        expecting.append("func(-255)")
        self.assertEqual(container, expecting)

    @call_on_dispersy_thread
    def test_call_priority(self):
        """
        Using Callback.call on a generator task should still adhere to normal priorities.
        """
        def generator_func(priority):
            for _ in xrange(5):
                container.append("generator_func(%d)" % priority)
                self._dispersy.callback.register(func, (0,), priority=0)
                yield 0.0

        def func(priority):
            container.append("func(%d)" % priority)

        container = []
        self._dispersy.callback.call(generator_func, (-128,), priority=-128)

        # wait for a second for all calls to be made
        yield 1.0

        # we expect:
        expecting = []
        expecting.append("generator_func(-128)")
        expecting.append("func(0)")
        expecting.append("generator_func(-128)")
        expecting.append("func(0)")
        expecting.append("generator_func(-128)")
        expecting.append("func(0)")
        expecting.append("generator_func(-128)")
        expecting.append("func(0)")
        expecting.append("generator_func(-128)")
        expecting.append("func(0)")
        self.assertEqual(container, expecting)
