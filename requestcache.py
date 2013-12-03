from random import random

from .logger import get_logger
logger = get_logger(__name__)


class Cache(object):

    @staticmethod
    def create_identifier():
        raise NotImplementedError()

    def __init__(self, identifier):
        assert isinstance(identifier, unicode), type(identifier)
        self._identifier = identifier

    @property
    def identifier(self):
        assert isinstance(self._identifier, unicode), type(self._identifier)
        return self._identifier

    @property
    def timeout_delay(self):
        return 10.0

    @property
    def cleanup_delay(self):
        return 10.0

    def on_timeout(self):
        raise NotImplementedError()

    def on_cleanup(self):
        pass

    def __str__(self):
        return "<%s identifier:%s>" % (self.__class__.__name__, self.identifier)


class NumberCache(Cache):

    @staticmethod
    def create_identifier(number):
        assert isinstance(number, int), type(number)
        raise NotImplementedError()

    @staticmethod
    def create_number():
        return int(random() * 2 ** 16)

    def __init__(self, request_cache, *create_identifier_args):
        # find an unclaimed identifier
        while True:
            number = self.create_number()
            identifier = self.create_identifier(number, *create_identifier_args)
            if not request_cache.has(identifier):
                super(NumberCache, self).__init__(identifier)
                self._number = number
                break

    @property
    def number(self):
        assert isinstance(self._number, int), type(self._number)
        return self._number


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
            self._callback.register(self._on_timeout, (cache,), id_=cache.identifier, delay=cache.timeout_delay)
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
        self._callback.replace_register(cache.identifier, self._on_timeout, (cache,), delay=cache.timeout_delay)
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
            assert isinstance(cache.cleanup_delay, float)
            assert cache.cleanup_delay >= 0.0
            logger.debug("cancel timeout for %s", cache)

            if cache.cleanup_delay:
                self._callback.replace_register(identifier, self._on_cleanup, (cache,), delay=cache.cleanup_delay)

            else:
                self._callback.unregister(identifier)
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

        if cache.cleanup_delay:
            self._callback.replace_register(cache.identifier, self._on_cleanup, (cache,), delay=cache.cleanup_delay)

        # the on_timeout call could have already removed the identifier from the cache using pop
        elif cache.identifier in self._identifiers:
            del self._identifiers[cache.identifier]

    def _on_cleanup(self, cache):
        """
        Called CACHE.cleanup_delay seconds after CACHE had either a timeout or was popped.

        _on_cleanup is called for every Cache that has CAHCHE.cleanup_delay > 0.0.  When called _on_cleanup will:
        - call CACHE.on_cleanup().
        - removes CACHE, freeing CACHE.identifier to be used again.
        """
        # if not cache.identifier in self._identifiers:
        #     logger.error("_on_cleanup with unknown identifier \"%s\"", cache.identifier)
        #     return

        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert cache.identifier in self._identifiers, cache

        logger.debug("cleanup on %s", cache)
        cache.on_cleanup()

        # the on_cleanup call could have already removed the identifier from the cache using pop
        if cache.identifier in self._identifiers:
            del self._identifiers[cache.identifier]

