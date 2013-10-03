"""
A callback thread running Dispersy.
"""

from heapq import heappush, heappop
from thread import get_ident
from threading import Thread, Lock, Event
from time import sleep, time
from types import GeneratorType, TupleType
from sys import exc_info

from .decorator import attach_profiler
from .logger import get_logger
logger = get_logger(__name__)


if __debug__:
    from atexit import register as atexit_register
    from inspect import getsourcefile, getsourcelines


class Callback(object):
    if __debug__:
        @staticmethod
        def _debug_call_to_string(call):
            if isinstance(call, TupleType):
                call = call[0]

            elif isinstance(call, GeneratorType):
                pass

            else:
                assert call is None, type(call)
                return str(call)

            try:
                source_file = getsourcefile(call)[-25:]
            except (TypeError, IndexError):
                source_file = "<unknown>"

            try:
                line_number = getsourcelines(call)[1]
            except (TypeError, IOError, IndexError):
                line_number = -1

            if source_file == "<unknown>" and line_number == -1:
                return call.__name__
            else:
                return "%s@%s:%d" % (call.__name__, source_file, line_number)

    def __init__(self, name="Generic-Callback"):
        assert isinstance(name, str), type(name)

        # _name will be given to the thread when it is started
        self._name = name

        # _event is used to wakeup the thread when new actions arrive
        self._event = Event()
        self._event_set = self._event.set
        self._event_is_set = self._event.isSet

        # _lock is used to protect variables that are written to on multiple threads
        self._lock = Lock()

        # _thread contains the actual Thread object
        self._thread = Thread(target=self.loop, name=self._name)
        self._thread.daemon = True

        # _thread_ident is used to detect when methods are called from the same thread
        self._thread_ident = 0

        # _state contains the current state of the thread.  it is protected by _lock and follows the
        # following states:
        #
        #                                              --> fatal-exception -> STATE_EXCEPTION
        #                                             /
        # STATE_INIT -> start() -> PLEASE_RUN -> STATE_RUNNING
        #                                \            \
        #                                 --------------> stop() -> PLEASE_STOP -> STATE_FINISHED
        #
        self._state = "STATE_INIT"
        logger.debug("STATE_INIT")

        # _exception is set to SystemExit, KeyboardInterrupt, GeneratorExit, or AssertionError when
        # any of the registered callbacks raises any of these exceptions.  in this case _state will
        # be set to STATE_EXCEPTION.  it is protected by _lock
        self._exception = None
        self._exception_traceback = None

        # _exception_handlers contains a list with callable functions of methods.  all handlers are
        # called whenever an exception occurs.  first parameter is the exception, second parameter
        # is a boolean indicating if the exception is fatal (i.e. True indicates SystemExit,
        # KeyboardInterrupt, GeneratorExit, or AssertionError)
        self._exception_handlers = []

        # _id contains a running counter to ensure that every scheduled callback has its own unique
        # identifier.  it is protected by _lock.  tasks will get u"dispersy-#<ID>" assigned
        self._id = 0

        # _requests are ordered by deadline and moved to -expired- when they need to be handled
        # (deadline, priority, root_id, (call, args, kargs), callback)
        self._requests = []

        # expired requests are ordered and handled by priority
        # (priority, deadline, root_id, (call, args, kargs), callback)
        self._expired = []

        # _requests_mirror and _expired_mirror contains the same list as _requests and _expired,
        # respectively.  when the callback closes _requests is set to a new empty list while
        # _requests_mirror continues to point to the existing one.  because all task 'deletes' are
        # done on the _requests_mirror list, these actions will still be allowed while no new tasks
        # will be accepted.
        self._requests_mirror = self._requests
        self._expired_mirror = self._expired

        if __debug__:
            def must_close(callback):
                assert callback.is_finished
            atexit_register(must_close, self)
            self._debug_call_name = None

    @property
    def ident(self):
        return self._thread_ident

    @property
    def is_current_thread(self):
        """
        Returns True when called on this Callback thread.
        """
        return self._thread_ident == get_ident()

    @property
    def is_running(self):
        """
        Returns True when the state is STATE_RUNNING.
        """
        return self._state == "STATE_RUNNING"

    @property
    def is_finished(self):
        """
        Returns True when the state is either STATE_FINISHED, STATE_EXCEPTION or STATE_INIT.  In either case the
        thread is no longer running.
        """
        return self._state == "STATE_FINISHED" or self._state == "STATE_EXCEPTION" or self._state == "STATE_INIT"

    @property
    def exception(self):
        """
        Returns the exception that caused the thread to exit when when any of the registered callbacks
        raises either SystemExit, KeyboardInterrupt, GeneratorExit, or AssertionError.
        """
        return self._exception

    @property
    def exception_traceback(self):
        """
        Returns the traceback of the exception that caused the thread to exit when when any of the registered callbacks
        """
        return self._exception_traceback

    def attach_exception_handler(self, func):
        """
        Attach a new exception notifier.

        FUNC will be called whenever a registered call raises an exception.  The first parameter will be the raised
        exception, the second parameter will be a boolean indicating if the exception was fatal.  FUNC should return a
        boolean, if any of the attached exception handlers returns True the exception is considered fatal.

        Fatal exceptions are SystemExit, KeyboardInterrupt, GeneratorExit, or AssertionError.  These exceptions will
        cause the Callback thread to exit.  The Callback thread will continue to function on all other exceptions.
        """
        assert callable(func), "handler must be callable"
        with self._lock:
            assert not func in self._exception_handlers, "handler was already attached"
            self._exception_handlers.append(func)

    def detach_exception_handler(self, func):
        """
        Detach an existing exception notifier.
        """
        assert callable(func), "handler must be callable"
        with self._lock:
            assert func in self._exception_handlers, "handler is not attached"
            self._exception_handlers.remove(func)

    def _call_exception_handlers(self, exception, fatal):
        with self._lock:
            exception_handlers = self._exception_handlers[:]

        force_fatal = False
        for exception_handler in exception_handlers:
            try:
                if exception_handler(exception, fatal):
                    force_fatal = True
            except Exception as exception:
                logger.exception("%s", exception)
                assert False, "the exception handler should not cause an exception"

        if fatal or force_fatal:
            with self._lock:
                self._state = "STATE_EXCEPTION"
                self._exception = exception
                self._exception_traceback = exc_info()[2]


            if fatal:
                logger.exception("attempting proper shutdown [%s]", exception)

            else:
                # one or more of the exception handlers returned True, we will consider this
                # exception to be fatal and quit
                logger.exception("reassessing as fatal exception, attempting proper shutdown [%s]", exception)

        else:
            logger.exception("keep running regardless of exception [%s]", exception)

        return fatal

    def register(self, call, args=(), kargs=None, delay=0.0, priority=0, id_=u"", callback=None, callback_args=(), callback_kargs=None, include_id=False):
        """
        Register CALL to be called.

        The call will be made with ARGS and KARGS as arguments and keyword arguments, respectively.
        ARGS must be a tuple and KARGS must be a dictionary.

        CALL may return a generator object that will be repeatedly called until it raises the
        StopIteration exception.  The generator can yield floating point values to reschedule the
        generator after that amount of seconds counted from the scheduled start of the call.  It is
        possible to yield other values, however, these are currently undocumented.

        The call will be made after DELAY seconds.  DELAY must be a floating point value.

        When multiple calls should be, or should have been made, the PRIORITY will decide the order
        at which the calls are made.  Calls with a higher PRIORITY will be handled before calls with
        a lower PRIORITY.  PRIORITY must be an integer.  The default PRIORITY is 0.  The order will
        be undefined for calls with the same PRIORITY.

        Each call is identified with an ID_.  A unique unicode identifier, based on an auto
        increment counter, will be assigned when no ID_ is specified.  Specified id's must be
        unicode strings.  Registering multiple calls with the same ID_ is allowed, all calls will be
        handled normally, however, all these calls will be removed if the associated ID_ is
        unregistered.

        Once the call is performed the optional CALLBACK is registered to be called immediately.
        The first parameter of the CALLBACK will always be either the returned value or the raised
        exception.  If CALLBACK_ARGS is given it will be appended to the first argument.  If
        CALLBACK_KARGS is given it is added to the callback as keyword arguments.

        When INCLUDE_ID is True then the assigned identifier is given as the first argument to CALL.

        Returns the assigned identifier.

        Example:
         > callback.register(my_func, delay=10.0)
         > -> my_func() will be called after 10.0 seconds

        Example:
         > def my_generator():
         >    while True:
         >       print "foo"
         >       yield 1.0
         > callback.register(my_generator)
         > -> my_generator will be called immediately printing "foo", subsequently "foo" will be
              printed at 1.0 second intervals
        """
        assert callable(call), "CALL must be callable"
        assert isinstance(args, tuple), "ARGS has invalid type: %s" % type(args)
        assert kargs is None or isinstance(kargs, dict), "KARGS has invalid type: %s" % type(kargs)
        assert isinstance(delay, float), "DELAY has invalid type: %s" % type(delay)
        assert isinstance(priority, int), "PRIORITY has invalid type: %s" % type(priority)
        assert isinstance(id_, unicode), "ID_ has invalid type: %s" % type(id_)
        assert callback is None or callable(callback), "CALLBACK must be None or callable"
        assert isinstance(callback_args, tuple), "CALLBACK_ARGS has invalid type: %s" % type(callback_args)
        assert callback_kargs is None or isinstance(callback_kargs, dict), "CALLBACK_KARGS has invalid type: %s" % type(callback_kargs)
        assert isinstance(include_id, bool), "INCLUDE_ID has invalid type: %d" % type(include_id)
        logger.debug("register %s after %.2f seconds", call, delay)

        with self._lock:
            if not id_:
                self._id += 1
                id_ = u"dispersy-#%d" % self._id

            if delay <= 0.0:
                heappush(self._expired,
                         (-priority,
                          time(),
                          id_,
                          (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                          None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))
            else:
                heappush(self._requests,
                         (delay + time(),
                          -priority,
                          id_,
                          (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                          None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))

            # wakeup if sleeping
            if not self._event_is_set():
                self._event_set()
            return id_

    def persistent_register(self, id_, call, args=(), kargs=None, delay=0.0, priority=0, callback=None, callback_args=(), callback_kargs=None, include_id=False):
        """
        Register CALL to be called only if ID_ has not already been registered.

        Aside from the different behavior of ID_, all parameters behave as in register(...).

        Example:
         > callback.persistent_register(u"my-id", my_func, ("first",), delay=60.0)
         > callback.persistent_register(u"my-id", my_func, ("second",))
         > -> my_func("first") will be called after 60 seconds, my_func("second") will not be called at all

        Example:
         > callback.register(my_func, ("first",), delay=60.0, id_=u"my-id")
         > callback.persistent_register(u"my-id", my_func, ("second",))
         > -> my_func("first") will be called after 60 seconds, my_func("second") will not be called at all
        """
        assert isinstance(id_, unicode), "ID_ has invalid type: %s" % type(id_)
        assert id_, "ID_ may not be empty"
        assert callable(call), "CALL must be callable"
        assert isinstance(args, tuple), "ARGS has invalid type: %s" % type(args)
        assert kargs is None or isinstance(kargs, dict), "KARGS has invalid type: %s" % type(kargs)
        assert isinstance(delay, float), "DELAY has invalid type: %s" % type(delay)
        assert isinstance(priority, int), "PRIORITY has invalid type: %s" % type(priority)
        assert callback is None or callable(callback), "CALLBACK must be None or callable"
        assert isinstance(callback_args, tuple), "CALLBACK_ARGS has invalid type: %s" % type(callback_args)
        assert callback_kargs is None or isinstance(callback_kargs, dict), "CALLBACK_KARGS has invalid type: %s" % type(callback_kargs)
        assert isinstance(include_id, bool), "INCLUDE_ID has invalid type: %d" % type(include_id)
        logger.debug("persistent register %s after %.2f seconds", call, delay)

        with self._lock:
            for tup in self._requests:
                if tup[2] == id_:
                    break

            else:
                # not found in requests
                for tup in self._expired:
                    if tup[2] == id_:
                        break

                else:
                    # not found in expired
                    if delay <= 0.0:
                        heappush(self._expired,
                                 (-priority,
                                  time(),
                                  id_,
                                  (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                                  None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))

                    else:
                        heappush(self._requests,
                                 (delay + time(),
                                  -priority,
                                  id_,
                                  (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                                  None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))

                    # wakeup if sleeping
                    if not self._event_is_set():
                        self._event_set()

            return id_

    def replace_register(self, id_, call, args=(), kargs=None, delay=0.0, priority=0, callback=None, callback_args=(), callback_kargs=None, include_id=False):
        """
        Replace (if present) the currently registered call ID_ with CALL.

        This is a faster way to handle an unregister and register call.  All parameters behave as in
        register(...).
        """
        assert isinstance(id_, unicode), "ID_ has invalid type: %s" % type(id_)
        assert id_, "ID_ may not be empty"
        assert callable(call), "CALL must be callable"
        assert isinstance(args, tuple), "ARGS has invalid type: %s" % type(args)
        assert kargs is None or isinstance(kargs, dict), "KARGS has invalid type: %s" % type(kargs)
        assert isinstance(delay, float), "DELAY has invalid type: %s" % type(delay)
        assert isinstance(priority, int), "PRIORITY has invalid type: %s" % type(priority)
        assert callback is None or callable(callback), "CALLBACK must be None or callable"
        assert isinstance(callback_args, tuple), "CALLBACK_ARGS has invalid type: %s" % type(callback_args)
        assert callback_kargs is None or isinstance(callback_kargs, dict), "CALLBACK_KARGS has invalid type: %s" % type(callback_kargs)
        assert isinstance(include_id, bool), "INCLUDE_ID has invalid type: %d" % type(include_id)
        logger.debug("replace register %s after %.2f seconds", call, delay)

        with self._lock:
            # un-register
            for index, tup in enumerate(self._requests_mirror):
                if tup[2] == id_:
                    self._requests_mirror[index] = (tup[0], tup[1], id_, None, None)
                    logger.debug("in _requests: %s", id_)

            for index, tup in enumerate(self._expired_mirror):
                if tup[2] == id_:
                    self._expired_mirror[index] = (tup[0], tup[1], id_, None, None)
                    logger.debug("in _expired: %s", id_)

            # register
            if delay <= 0.0:
                heappush(self._expired,
                         (-priority,
                          time(),
                          id_,
                          (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                          None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))

            else:
                heappush(self._requests,
                         (delay + time(),
                          -priority,
                          id_,
                          (call, args + (id_,) if include_id else args, {} if kargs is None else kargs),
                          None if callback is None else (callback, callback_args, {} if callback_kargs is None else callback_kargs)))

            # wakeup if sleeping
            if not self._event_is_set():
                self._event_set()
            return id_

    def unregister(self, id_):
        """
        Unregister a callback using the ID_ obtained from the register(...) method
        """
        assert isinstance(id_, unicode), "ROOT_ID has invalid type: %s" % type(id_)
        assert id_, "ID_ may not be empty"
        logger.debug("unregister %s", id_)

        with self._lock:
            # un-register
            for index, tup in enumerate(self._requests_mirror):
                if tup[2] == id_:
                    self._requests_mirror[index] = (tup[0], tup[1], id_, None, None)
                    logger.debug("in _requests: %s", id_)

            for index, tup in enumerate(self._expired_mirror):
                if tup[2] == id_:
                    self._expired_mirror[index] = (tup[0], tup[1], id_, None, None)
                    logger.debug("in _expired: %s", id_)

    def call(self, call, args=(), kargs=None, delay=0.0, priority=0, id_=u"", include_id=False, timeout=0.0, default=None):
        """
        Register a blocking CALL to be made, waits for the call to finish, and returns or raises the
        result.

        TIMEOUT gives the maximum amount of time to wait before un-registering CALL.  No timeout
        will occur when TIMEOUT is 0.0.  When a timeout occurs the DEFAULT value is returned.
        TIMEOUT is unused when called from the same thread.

        DEFAULT can be anything.  The DEFAULT value is returned when a TIMEOUT occurs.  Note: as of 24/05/13 when
        DEFAULT is an Exception instance it will no longer be raised.

        For the arguments CALL, ARGS, KARGS, DELAY, PRIORITY, ID_, and INCLUDE_ID: see the register(...) method.
        """
        assert isinstance(timeout, float)
        assert 0.0 <= timeout
        assert self._thread_ident

        def callback(result):
            if isinstance(result, Exception):
                container[1] = result
                container[2] = exc_info()

            else:
                container[0] = result

            event.set()

        # result container with [RETURN-VALUE, EXCEPTION-INSTANCE, EXC_INFO-TUPLE]
        container = [default, None, None]
        event = Event()

        # register the call
        self.register(call, args, kargs, delay, priority, id_, callback, include_id=include_id)

        if self._thread_ident == get_ident():
            # TODO timeout is not taken into account right now
            while self._one_task():
                # wait for call to finish
                if event.is_set():
                    break

        else:
            # wait for call to finish
            event.wait(None if timeout == 0.0 else timeout)

        if container[1]:
            if container[2][0] is None:
                raise container[1]

            else:
                type_, value, traceback = container[2]
                raise type_, value, traceback

        else:
            return container[0]

    def start(self, wait=True):
        """
        Start the asynchronous thread.

        Creates a new thread and calls the loop() method.
        """
        assert self._state == "STATE_INIT", "Already (done) running"
        assert isinstance(wait, bool), "WAIT has invalid type: %s" % type(wait)
        with self._lock:
            self._state = "STATE_PLEASE_RUN"
            logger.debug("STATE_PLEASE_RUN")

        self._thread.start()

        if wait:
            # Wait until the thread has started
            while self._state == "STATE_PLEASE_RUN":
                sleep(0.01)

        return self.is_running

    def stop(self, timeout=10.0, exception=None):
        """
        Stop the asynchronous thread.

        When called from the same thread this method will return immediately.  When called from a
        different thread the method will wait at most TIMEOUT seconds before returning.

        Returns True when the callback thread is finished, otherwise returns False.
        """
        assert isinstance(timeout, float)
        if self._state == "STATE_RUNNING":
            with self._lock:
                if exception:
                    self._exception = exception
                    self._exception_traceback = exc_info()[2]
                self._state = "STATE_PLEASE_STOP"
                logger.debug("STATE_PLEASE_STOP")

                # wakeup if sleeping
                self._event.set()

        # 05/04/13 Boudewijn: we must also wait when self._state != RUNNING.  This can occur when
        # stop() has already been called from SELF._THREAD_IDENT, changing the state to PLEASE_STOP.
        if self._thread_ident == get_ident():
            logger.debug("using callback.stop from the same thread will not allow us to wait until the callback has finished")

        else:
            while self._state == "STATE_PLEASE_STOP" and timeout > 0.0:
                sleep(0.01)
                timeout -= 0.01

            if not self.is_finished:
                logger.warning("unable to stop the callback within the allowed time")

        return self.is_finished

    def join(self, timeout=0.0):
        assert isinstance(timeout, float), type(timeout)
        assert timeout >= 0.0, timeout
        self._thread.join(None if timeout == 0.0 else timeout)
        return self.is_finished

    def _one_task(self):
        if __debug__:
            time_since_expired = 0

        actual_time = time()

        with self._lock:
            # check if we should continue to run
            if self._state != "STATE_RUNNING":
                # break
                return False

            # move expired requests from self._REQUESTS to self._EXPIRED
            while self._requests and self._requests[0][0] <= actual_time:
                # notice that the deadline and priority entries are switched, hence, the entries in
                # the self._EXPIRED list are ordered by priority instead of deadline
                deadline, priority, root_id, call, callback = heappop(self._requests)
                heappush(self._expired, (priority, deadline, root_id, call, callback))

            if self._expired:
                if __debug__ and len(self._expired) > 10:
                    if not time_since_expired:
                        time_since_expired = actual_time

                # we need to handle the next call in line
                priority, deadline, root_id, call, callback = heappop(self._expired)
                wait = 0.0

                if __debug__:
                    self._debug_call_name = self._debug_call_to_string(call)

                # ignore removed tasks
                if call is None:
                    # continue
                    return True

            else:
                # there is nothing to handle
                wait = self._requests[0][0] - actual_time if self._requests else 300.0
                if __debug__:
                    logger.debug("nothing to handle, wait %.2f seconds", wait)
                    if time_since_expired:
                        diff = actual_time - time_since_expired
                        if diff > 1.0:
                            logger.warning("took %.2f to process expired queue", diff)
                        time_since_expired = 0

            if self._event.is_set():
                self._event.clear()

        if wait:
            logger.debug("wait at most %.3fs before next call, still have %d calls in queue", wait, len(self._requests))
            self._event.wait(wait)

        else:
            if __debug__:
                logger.debug("---- call %s (priority:%d, id:%s)", self._debug_call_name, priority, root_id)
                debug_call_start = time()

            # call can be either:
            # 1. a generator
            # 2. a (callable, args, kargs) tuple

            try:
                if isinstance(call, TupleType):
                    # callback
                    result = call[0](*call[1], **call[2])
                    if isinstance(result, GeneratorType):
                        # we only received the generator, no actual call has been made to the
                        # function yet, therefore we call it again immediately
                        call = result

                    elif callback:
                        with self._lock:
                            heappush(self._expired, (priority, actual_time, root_id, (callback[0], (result,) + callback[1], callback[2]), None))

                if isinstance(call, GeneratorType):
                    # start next generator iteration
                    result = call.next()
                    assert isinstance(result, float), [type(result), call]
                    assert result >= 0.0, [result, call]
                    with self._lock:
                        heappush(self._requests, (time() + result, priority, root_id, call, callback))

            except StopIteration:
                if callback:
                    with self._lock:
                        heappush(self._expired, (priority, actual_time, root_id, (callback[0], (None,) + callback[1], callback[2]), None))

            except (SystemExit, KeyboardInterrupt, GeneratorExit) as exception:
                self._call_exception_handlers(exception, True)

            except Exception as exception:
                if callback:
                    with self._lock:
                        heappush(self._expired, (priority, actual_time, root_id, (callback[0], (exception,) + callback[1], callback[2]), None))

                self._call_exception_handlers(exception, False)

            if __debug__:
                debug_call_duration = time() - debug_call_start
                if debug_call_duration > 1.0:
                    logger.warning("%.2f call %s (priority:%d, id:%s)", debug_call_duration, self._debug_call_name, priority, root_id)
                else:
                    logger.debug("%.2f call %s (priority:%d, id:%s)", debug_call_duration, self._debug_call_name, priority, root_id)

        return True

    @attach_profiler
    def loop(self):
        # from now on we will assume GET_IDENT() is the running thread
        self._thread_ident = get_ident()

        with self._lock:
            if self._state == "STATE_PLEASE_RUN":
                self._state = "STATE_RUNNING"
                logger.debug("STATE_RUNNING")

        # handle tasks as long as possible
        while self._one_task():
            pass

        with self._lock:
            # allowing us to refuse any new tasks.  _requests_mirror and _expired_mirror will still
            # allow tasks to be removed
            self._requests = []
            self._expired = []

        # call all expired tasks and send GeneratorExit exceptions to expired generators, note that
        # new tasks will not be accepted
        logger.debug("there are %d expired tasks", len(self._expired_mirror))
        while self._expired_mirror:
            _, _, _, call, callback = heappop(self._expired_mirror)
            if isinstance(call, TupleType):
                try:
                    result = call[0](*call[1], **call[2])
                except Exception as exception:
                    logger.exception("%s", exception)
                else:
                    if isinstance(result, GeneratorType):
                        # we only received the generator, no actual call has been made to the
                        # function yet, therefore we call it again immediately
                        call = result

                    elif callback:
                        try:
                            callback[0](result, *callback[1], **callback[2])
                        except Exception as exception:
                            logger.exception("%s", exception)

            if isinstance(call, GeneratorType):
                logger.debug("raise Shutdown in %s", call)
                try:
                    call.close()
                except Exception as exception:
                    logger.exception("%s", exception)

                if callback:
                    logger.debug("inform callback for %s", call)
                    try:
                        callback[0](RuntimeError("Early shutdown"), *callback[1], **callback[2])
                    except Exception as exception:
                        logger.exception("%s", exception)

        # send GeneratorExit exceptions to scheduled generators
        logger.debug("there are %d scheduled tasks", len(self._requests_mirror))
        while self._requests_mirror:
            _, _, _, call, callback = heappop(self._requests_mirror)
            if isinstance(call, GeneratorType):
                logger.debug("raise Shutdown in %s", call)
                try:
                    call.close()
                except Exception as exception:
                    logger.exception("%s", exception)

            if callback:
                logger.debug("inform callback for %s", call)
                try:
                    callback[0](RuntimeError("Early shutdown"), *callback[1], **callback[2])
                except Exception as exception:
                    logger.exception("%s", exception)

        # set state to finished
        with self._lock:
            logger.debug("STATE_FINISHED")
            self._state = "STATE_FINISHED"
