from ..requestcache import RequestCache, NumberCache
from .dispersytestclass import DispersyTestFunc, call_on_mm_thread

class TestRequestCache(DispersyTestFunc):

    @call_on_mm_thread
    def test_single_cache(self):
        """
        Tests standard add, has, get, and pop behaviour.
        """
        class Cache(NumberCache):
            @staticmethod
            def create_identifier(number):
                return u"request-cache:test:%d" % (number,)

        request_cache = RequestCache(self._dispersy.callback)
        cache = Cache(request_cache)
        self.assertIsNotNone(cache)
        self.assertFalse(request_cache.has(cache.identifier))
        self.assertIsNone(request_cache.get(cache.identifier))
        self.assertIsNone(request_cache.pop(cache.identifier))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.identifier))
        self.assertEqual(request_cache.get(cache.identifier), cache)
        # remove
        self.assertEqual(request_cache.pop(cache.identifier), cache)
        # has, get, and pop fail because cache.cleanup_delay == 0.0
        self.assertFalse(request_cache.has(cache.identifier))
        self.assertIsNone(request_cache.get(cache.identifier))
        self.assertIsNone(request_cache.pop(cache.identifier))

    @call_on_mm_thread
    def test_multiple_caches(self):
        """
        Tests standard add, has, get, and pop behaviour.
        """
        class Cache(NumberCache):
            @staticmethod
            def create_identifier(number):
                return u"request-cache:test:%d" % (number,)

        request_cache = RequestCache(self._dispersy.callback)

        caches = []
        for _ in xrange(100):
            cache = Cache(request_cache)
            self.assertIsNotNone(cache)
            self.assertFalse(request_cache.has(cache.identifier))
            self.assertIsNone(request_cache.get(cache.identifier))
            self.assertIsNone(request_cache.pop(cache.identifier))
            # add cache (must be done before generating the next cache, otherwise number clashes can occur)
            self.assertEqual(request_cache.add(cache), cache)
            caches.append(cache)

        # all identifiers must be unique
        self.assertEqual(len(caches), len(set(cache.identifier for cache in caches)))
        # all numbers must be unique
        self.assertEqual(len(caches), len(set(cache.number for cache in caches)))

        for cache in caches:
            self.assertTrue(request_cache.has(cache.identifier))
            self.assertEqual(request_cache.get(cache.identifier), cache)

        for cache in caches:
            # remove
            self.assertEqual(request_cache.pop(cache.identifier), cache)
            # has, get, and pop fail because cache.cleanup_delay == 0.0
            self.assertFalse(request_cache.has(cache.identifier))
            self.assertIsNone(request_cache.get(cache.identifier))
            self.assertIsNone(request_cache.pop(cache.identifier))

    @call_on_mm_thread
    def test_request_cache_double_pop_bug(self):
        """
        Test that the "unexpected pop behavior when Cache.cleanup_delay > 0.0" bug is fixed.
        """
        class Cache(NumberCache):
            @staticmethod
            def create_identifier(number):
                return u"request-cache:test:%d" % (number,)

        request_cache = RequestCache(self._dispersy.callback)
        cache = Cache(request_cache)
        self.assertIsNotNone(cache)
        self.assertFalse(request_cache.has(cache.identifier))
        self.assertIsNone(request_cache.get(cache.identifier))
        self.assertIsNone(request_cache.pop(cache.identifier))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.identifier))
        self.assertEqual(request_cache.get(cache.identifier), cache)
        # remove
        self.assertEqual(request_cache.pop(cache.identifier), cache)

        # pop() used to still work after the first pop()
        self.assertFalse(request_cache.has(cache.identifier))
        self.assertIsNone(request_cache.get(cache.identifier))
        self.assertIsNone(request_cache.pop(cache.identifier))

    @call_on_dispersy_thread
    def test_force_number(self):
        """
        Tests numbercache with force_number
        """
        class Cache(NumberCache):
            @staticmethod
            def create_number(force_number= -1):
                return force_number

            @staticmethod
            def create_identifier(number, force_number= -1):
                return u"request-cache:test:%d" % (number,)

            def __init__(self, request_cache, force_number= -1):
                NumberCache.__init__(self, request_cache, force_number)

        request_cache = RequestCache(self._dispersy.callback)

        cache = Cache(request_cache, force_number=1)

        self.assertFalse(request_cache.has(cache.identifier))
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.identifier))

        self.assertRaises(RuntimeError, Cache, request_cache, force_number=1)
