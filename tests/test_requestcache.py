from ..requestcache import RequestCache, NumberCache, FixedNumberCache
from .dispersytestclass import DispersyTestFunc, call_on_mm_thread

class TestRequestCache(DispersyTestFunc):

    @call_on_mm_thread
    def test_single_cache(self):
        """
        Tests standard add, has, get, and pop behaviour.
        """
        request_cache = RequestCache(self._dispersy.callback)
        cache = NumberCache(request_cache, u"test")
        self.assertIsNotNone(cache)
        self.assertFalse(request_cache.has(cache.number, u"test"))
        self.assertIsNone(request_cache.get(cache.number, u"test"))
        self.assertIsNone(request_cache.pop(cache.number, u"test"))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.number, u"test"))
        self.assertEqual(request_cache.get(cache.number, u"test"), cache)
        # remove
        self.assertEqual(request_cache.pop(cache.number, u"test"), cache)
        # has, get, and pop fail because cache.cleanup_delay == 0.0
        self.assertFalse(request_cache.has(cache.number, u"test"))
        self.assertIsNone(request_cache.get(cache.number, u"test"))
        self.assertIsNone(request_cache.pop(cache.number, u"test"))

    @call_on_mm_thread
    def test_multiple_caches(self):
        """
        Tests standard add, has, get, and pop behaviour.
        """
        request_cache = RequestCache(self._dispersy.callback)
        
        caches = []
        for _ in xrange(100):
            cache = NumberCache(request_cache, u"test")
            self.assertIsNotNone(cache)
            self.assertFalse(request_cache.has(cache.number, u"test"))
            self.assertIsNone(request_cache.get(cache.number, u"test"))
            self.assertIsNone(request_cache.pop(cache.number, u"test"))
            # add cache (must be done before generating the next cache, otherwise number clashes can occur)
            self.assertEqual(request_cache.add(cache), cache)
            caches.append(cache)

        # all numbers must be unique
        self.assertEqual(len(caches), len(set(cache.number for cache in caches)))

        for cache in caches:
            self.assertTrue(request_cache.has(cache.number, u"test"))
            self.assertEqual(request_cache.get(cache.number, u"test"), cache)

        for cache in caches:
            # remove
            self.assertEqual(request_cache.pop(cache.number, u"test"), cache)
            # has, get, and pop fail because cache.cleanup_delay == 0.0
            self.assertFalse(request_cache.has(cache.number, u"test"))
            self.assertIsNone(request_cache.get(cache.number, u"test"))
            self.assertIsNone(request_cache.pop(cache.number, u"test"))

    @call_on_mm_thread
    def test_request_cache_double_pop_bug(self):
        request_cache = RequestCache(self._dispersy.callback)
        cache = NumberCache(request_cache, u"test")
        self.assertIsNotNone(cache)
        self.assertFalse(request_cache.has(cache.number, u"test"))
        self.assertIsNone(request_cache.get(cache.number, u"test"))
        self.assertIsNone(request_cache.pop(cache.number, u"test"))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.number, u"test"))
        self.assertEqual(request_cache.get(cache.number, u"test"), cache)
        # remove
        self.assertEqual(request_cache.pop(cache.number, u"test"), cache)

        # pop() used to still work after the first pop()
        self.assertFalse(request_cache.has(cache.number, u"test"))
        self.assertIsNone(request_cache.get(cache.number, u"test"))
        self.assertIsNone(request_cache.pop(cache.number, u"test"))

    @call_on_mm_thread
    def test_fixed_number(self):
        """
        Tests fixednumbercache
        """
        request_cache = RequestCache(self._dispersy.callback)
        cache = FixedNumberCache(request_cache, 1, u"test")

        self.assertFalse(request_cache.has(cache.number, u"test"))
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(cache.number, u"test"))

        self.assertRaises(RuntimeError, FixedNumberCache, request_cache, 1, u"test")
