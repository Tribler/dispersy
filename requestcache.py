from random import random

from .logger import get_logger
logger = get_logger(__name__)


class Cache(object):

    @staticmethod
    def create_identifier():
        """
        Create an identifier, preferably unique for each outstanding request cache.
        """
        raise NotImplementedError()

    def __init__(self, identifier):
        assert isinstance(identifier, unicode), type(identifier)
        self._identifier = identifier
        self._callback_identifier = u""

    @property
    def identifier(self):
        """
        Returns the identifier.

        The identifier is typically created using the static method Cache.create_identifier() which
        returns a unicode string.  This string should be unique for each outstanding request cache.
        """
        assert isinstance(self._identifier, unicode), type(self._identifier)
        return self._identifier

    @property
    def callback_identifier(self):
        """
        Returns the callback identifier.

        The callback identifier is typically set when this Cache is added to a RequestCache using
        RequestCache.add().  It is a unicode string that is unique to the Callback instance that is
        assigned to the RequestCache.

        The callback identifier is used to register _on_timeout and _on_cleanup tasks.
        """
        assert isinstance(self._callback_identifier, unicode), type(self._callback_identifier)
        return self._callback_identifier

    @callback_identifier.setter
    def callback_identifier(self, callback_identifier):
        """
        Sets the callback identifier, see the callback_identifier getter.
        """
        assert isinstance(callback_identifier, unicode), type(callback_identifier)
        self._callback_identifier = callback_identifier

    @property
    def timeout_delay(self):
        return 10.0

    def on_timeout(self):
        raise NotImplementedError()

    def __str__(self):
        return "<%s identifier:%s>" % (self.__class__.__name__, self.identifier)


class NumberCache(Cache):

    @staticmethod
    def create_identifier(number):
        raise NotImplementedError()

    @staticmethod
    def create_number():
        return int(random() * 2 ** 16)

    def __init__(self, request_cache, *create_identifier_args):
        # find an unclaimed identifier
        for _ in xrange(1000):
            number = self.create_number(*create_identifier_args)
            assert isinstance(number, (int, long)), type(number)

            identifier = self.create_identifier(number, *create_identifier_args)
            if not request_cache.has(identifier):
                super(NumberCache, self).__init__(identifier)
                self._number = number
                break
        else:
            raise RuntimeError("Could not find an identifier that isn't in use")

    @property
    def number(self):
        return self._number


class FixedNumberCache(NumberCache):

    def __init__(self, request_cache, *create_identifier_args):
        number = self.create_number(*create_identifier_args)
        assert isinstance(number, (int, long)), type(number)

        identifier = self.create_identifier(number, *create_identifier_args)
        if request_cache.has(identifier):
            raise RuntimeError("This identifier is already in use '%s'" % identifier)

        super(NumberCache, self).__init__(identifier)
        self._number = number


class RequestCache(object):

    def __init__(self, callback):
        """
        Creates a new RequestCache instance.
        """
        if __debug__:
            from .callback import Callback
            assert isinstance(callback, Callback), type(callback)
            assert callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        self._callback = callback
        self._identifiers = dict()

    def add(self, cache):
        """
        Add CACHE into this RequestCache instance.

        Returns CACHE when CACHE.identifier was not yet added, otherwise returns None.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(cache, Cache), type(cache)
        assert isinstance(cache.identifier, unicode), type(cache.identifier)
        assert isinstance(cache.timeout_delay, float), type(cache.timeout_delay)
        assert cache.timeout_delay > 0.0, cache.timeout_delay

        if cache.identifier in self._identifiers:
            logger.error("add with duplicate identifier \"%s\"", cache.identifier)
            return None

        else:
            logger.debug("add %s", cache)
            self._identifiers[cache.identifier] = cache
            cache.callback_identifier = self._callback.register(self._on_timeout, (cache,), delay=cache.timeout_delay)
            return cache

    def replace(self, cache):
        """
        Replaces an existing Cache (if it exists) with CACHE.

        Returns CACHE.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(cache, Cache), type(cache)
        assert isinstance(cache.identifier, unicode), type(cache.identifier)
        assert isinstance(cache.timeout_delay, float), type(cache.timeout_delay)
        assert cache.timeout_delay > 0.0, cache.timeout_delay

        logger.debug("replace %s with %s", self._identifiers.get(cache.identifier), cache)
        self._identifiers[cache.identifier] = cache
        # 2013/07/23 Boudewijn: there appeared to be a bug with the delay parameter, it was using cleanup_delay instead
        # of timeout_delay
        self._callback.replace_register(cache.callback_identifier, self._on_timeout, (cache,), delay=cache.timeout_delay)
        return cache

    def has(self, identifier):
        """
        Returns True when IDENTIFIER is part of this RequestCache.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(identifier, unicode), type(identifier)
        return identifier in self._identifiers

    def get(self, identifier):
        """
        Returns the Cache associated with IDENTIFIER when it exists, otherwise returns None.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(identifier, unicode), type(identifier)
        return self._identifiers.get(identifier)

    def pop(self, identifier):
        """
        Returns the Cache associated with IDENTIFIER, and removes it from this RequestCache, when it exists, otherwise
        returns None.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(identifier, unicode), type(identifier)

        cache = self._identifiers.get(identifier)
        if cache:
            logger.debug("cancel timeout for %s", cache)

            self._callback.unregister(cache.callback_identifier)
            del self._identifiers[identifier]

            return cache

    def _on_timeout(self, cache):
        """
        Called CACHE.timeout_delay seconds after CACHE was added to this RequestCache.

        _on_timeout is called for every Cache, except when it has been popped before the timeout expires.  When called
        _on_timeout will:
        - call CACHE.on_timeout().
        - when CACHE.cleanup_delay == 0.0: removes CACHE, freeing CACHE.identifier to be used again.
        - when CACHE.cleanup_delay > 0.0: schedules _on_cleanup to be called after CACHE.cleanup_delay seconds.
        """
        # if not cache.identifier in self._identifiers:
        #     logger.error("_on_timeout with unknown identifier \"%s\"", cache.identifier)
        #     return

        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(cache, Cache), type(cache)
        assert cache.identifier in self._identifiers, cache

        logger.debug("timeout on %s", cache)
        cache.on_timeout()

        # the on_timeout call could have already removed the identifier from the cache using pop
        if cache.identifier in self._identifiers:
            del self._identifiers[cache.identifier]
