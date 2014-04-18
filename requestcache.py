from random import random

from .logger import get_logger
logger = get_logger(__name__)


class NumberCache(object):

    def __init__(self, request_cache, prefix=u""):
        assert isinstance(prefix, unicode), type(prefix)
        
        # find an unclaimed identifier
        for _ in xrange(1000):
            number = int(random() * 2 ** 16)
            if not request_cache.has(number, prefix):
                self._number = number
                break
        else:
            raise RuntimeError("Could not find a number that isn't in use")
        
        self._prefix = prefix
        self._callback_identifier = u""

    @property
    def prefix(self):
        return self._prefix

    @property
    def number(self):
        return self._number
    
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
        return "<%s %s-%d>" % (self.__class__.__name__, self.prefix, self.number)


class FixedNumberCache(NumberCache):

    def __init__(self, request_cache, number, prefix = u""):
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)
        
        if request_cache.has(number, prefix):
            raise RuntimeError("This number is already in use '%s'" % number)

        self._number = number
        self._prefix = prefix
        self._callback_identifier = u""
        

class RequestCache(object):

    def __init__(self, callback):
        """
        Creates a new RequestCache instance.
        """
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
        assert isinstance(cache, NumberCache), type(cache)
        assert isinstance(cache.number, (int, long)), type(cache.number)
        assert isinstance(cache.prefix, unicode), type(cache.prefix)
        assert isinstance(cache.timeout_delay, float), type(cache.timeout_delay)
        assert cache.timeout_delay > 0.0, cache.timeout_delay
        
        identifier = self._create_identifier(cache.number, cache.prefix)
        if identifier in self._identifiers:
            logger.error("add with duplicate identifier \"%s\"", identifier)
            return None

        else:
            logger.debug("add %s", cache)
            self._identifiers[identifier] = cache
            cache.callback_identifier = self._callback.register(self._on_timeout, (cache,), delay=cache.timeout_delay)
            return cache

    def has(self, number, prefix = u""):
        """
        Returns True when IDENTIFIER is part of this RequestCache.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)
        return self._create_identifier(number, prefix) in self._identifiers

    def get(self, number, prefix = u""):
        """
        Returns the Cache associated with IDENTIFIER when it exists, otherwise returns None.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)
        return self._identifiers.get(self._create_identifier(number, prefix))

    def pop(self, number, prefix = u""):
        """
        Returns the Cache associated with IDENTIFIER, and removes it from this RequestCache, when it exists, otherwise
        returns None.
        """
        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(number, (int, long)), type(number)
        assert isinstance(prefix, unicode), type(prefix)

        identifier = self._create_identifier(number, prefix)
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
        _on_timeout will CACHE.on_timeout().
        """

        assert self._callback.is_current_thread, "RequestCache must be used on the Dispersy.callback thread"
        assert isinstance(cache, NumberCache), type(cache)

        logger.debug("timeout on %s", cache)
        cache.on_timeout()

        # the on_timeout call could have already removed the identifier from the cache using pop
        identifier = self._create_identifier(cache.number, cache.prefix) 
        if identifier in self._identifiers:
            del self._identifiers[identifier]

    def _create_identifier(self, number, prefix):
        return u"%s:%d"%(prefix, number)