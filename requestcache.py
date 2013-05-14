import logging
logger = logging.getLogger(__name__)

from random import random


def identifier_to_string(identifier):
    return identifier.encode("HEX") if isinstance(identifier, str) else identifier


class Cache(object):
    timeout_delay = 10.0
    cleanup_delay = 10.0

    def on_timeout(self):
        raise NotImplementedError()

    def on_cleanup(self):
        pass

    def __str__(self):
        return "<%s>" % self.__class__.__name__


class RequestCache(object):

    def __init__(self, callback):
        self._callback = callback
        self._identifiers = dict()

    def generate_identifier(self):
        while True:
            identifier = int(random() * 2 ** 16)
            if not identifier in self._identifiers:
                logger.debug("claiming on %s", identifier_to_string(identifier))
                return identifier

    def claim(self, cache):
        identifier = self.generate_identifier()
        logger.debug("claiming on %s for %s", identifier_to_string(identifier), cache)
        self.set(identifier, cache)
        return identifier

    def set(self, identifier, cache):
        assert isinstance(identifier, (int, long, str)), type(identifier)
        assert not identifier in self._identifiers, identifier
        assert isinstance(cache, Cache)
        assert isinstance(cache.timeout_delay, float)
        assert cache.timeout_delay > 0.0

        # TODO we are slowly making all Dispersy identifiers unicode strings.  currently the request
        # cache using stings instead, hence the conversion to HEX before giving them to _CALLBACK.
        # once the request cache identifiers are also unicode, this HEX conversion should be removed

        logger.debug("set %s for %s (%fs timeout)", identifier_to_string(identifier), cache, cache.timeout_delay)
        self._callback.register(self._on_timeout, (identifier,), id_=u"requestcache-%s" % str(identifier).encode("HEX"), delay=cache.timeout_delay)
        self._identifiers[identifier] = cache
        cache.identifier = identifier

    def replace(self, identifier, cache):
        assert isinstance(identifier, (int, long, str)), type(identifier)
        assert identifier in self._identifiers, identifier
        assert isinstance(cache, Cache)
        assert isinstance(cache.timeout_delay, float)
        assert cache.timeout_delay > 0.0

        logger.debug("replace %s for %s (%fs timeout)", identifier_to_string(identifier), cache, cache.timeout_delay)
        self._callback.replace_register(u"requestcache-%s" % str(identifier).encode("HEX"), self._on_timeout, (identifier,), delay=cache.cleanup_delay)
        self._identifiers[identifier] = cache
        cache.identifier = identifier

    def has(self, identifier, cls):
        assert isinstance(identifier, (int, long, str)), type(identifier)
        assert issubclass(cls, Cache), cls

        logger.debug("cache contains %s? %s", identifier_to_string(identifier), identifier in self._identifiers)
        return isinstance(self._identifiers.get(identifier), cls)

    def get(self, identifier, cls):
        assert isinstance(identifier, (int, long, str)), type(identifier)
        assert issubclass(cls, Cache), cls

        cache = self._identifiers.get(identifier)
        if cache and isinstance(cache, cls):
            return cache

    def pop(self, identifier, cls):
        assert isinstance(identifier, (int, long, str)), type(identifier)
        assert issubclass(cls, Cache), cls

        cache = self._identifiers.get(identifier)
        if cache and isinstance(cache, cls):
            assert isinstance(cache.cleanup_delay, float)
            assert cache.cleanup_delay >= 0.0
            logger.debug("canceling timeout on %s for %s", identifier_to_string(identifier), cache)

            if cache.cleanup_delay:
                self._callback.replace_register(u"requestcache-%s" % str(identifier).encode("HEX"), self._on_cleanup, (identifier,), delay=cache.cleanup_delay)

            elif identifier in self._identifiers:
                self._callback.unregister(u"requestcache-%s" % str(identifier).encode("HEX"))
                del self._identifiers[identifier]

            return cache

    def _on_timeout(self, identifier):
        assert identifier in self._identifiers, identifier
        cache = self._identifiers[identifier]
        logger.debug("timeout on %s for %s", identifier_to_string(identifier), cache)
        cache.on_timeout()

        if cache.cleanup_delay:
            self._callback.replace_register(u"requestcache-%s" % str(identifier).encode("HEX"), self._on_cleanup, (identifier,), delay=cache.cleanup_delay)

        elif identifier in self._identifiers:
            del self._identifiers[identifier]

    def _on_cleanup(self, identifier):
        assert identifier in self._identifiers
        cache = self._identifiers[identifier]
        logger.debug("cleanup on %s for %s", identifier_to_string(identifier), cache)
        cache.on_cleanup()

        if identifier in self._identifiers:
            del self._identifiers[identifier]
