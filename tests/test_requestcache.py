from ..requestcache import RequestCache, NumberCache, RandomNumberCache
from .dispersytestclass import DispersyTestFunc, call_on_mm_thread

class TestRequestCache(DispersyTestFunc):

    @call_on_mm_thread
    def test_single_cache(self):
        """
        Tests standard add, has, get, and pop behavior.
        """
        request_cache = RequestCache(self._dispersy.callback)
        cache = RandomNumberCache(request_cache, u"test")
        self.assertFalse(request_cache.has(u"test", cache.number))
        self.assertIsNone(request_cache.get(u"test", cache.number))
        self.assertIsNone(request_cache.pop(u"test", cache.number))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(u"test", cache.number))
        self.assertEqual(request_cache.get(u"test", cache.number), cache)
        # remove
        self.assertEqual(request_cache.pop(u"test", cache.number), cache)
        # has, get, and pop fail because we popped the cache
        self.assertFalse(request_cache.has(u"test", cache.number))
        self.assertIsNone(request_cache.get(u"test", cache.number))
        self.assertIsNone(request_cache.pop(u"test", cache.number))

    @call_on_mm_thread
    def test_multiple_caches(self):
        """
        Tests standard add, has, get, and pop behavior.
        """
        request_cache = RequestCache(self._dispersy.callback)

        caches = []
        for _ in xrange(100):
            cache = RandomNumberCache(request_cache, u"test")
            self.assertFalse(request_cache.has(u"test", cache.number))
            self.assertIsNone(request_cache.get(u"test", cache.number))
            self.assertIsNone(request_cache.pop(u"test", cache.number))
            # add cache (must be done before generating the next cache, otherwise number clashes can occur)
            self.assertEqual(request_cache.add(cache), cache)
            caches.append(cache)

        # all numbers must be unique
        self.assertEqual(len(caches), len(set(cache.number for cache in caches)))

        for cache in caches:
            self.assertTrue(request_cache.has(u"test", cache.number))
            self.assertEqual(request_cache.get(u"test", cache.number), cache)

        for cache in caches:
            # remove
            self.assertEqual(request_cache.pop(u"test", cache.number), cache)
            # has, get, and pop fail because we popped the cache
            self.assertFalse(request_cache.has(u"test", cache.number))
            self.assertIsNone(request_cache.get(u"test", cache.number))
            self.assertIsNone(request_cache.pop(u"test", cache.number))

    @call_on_mm_thread
    def test_request_cache_double_pop_bug(self):
        request_cache = RequestCache(self._dispersy.callback)
        cache = RandomNumberCache(request_cache, u"test")

        self.assertFalse(request_cache.has(u"test", cache.number))
        self.assertIsNone(request_cache.get(u"test", cache.number))
        self.assertIsNone(request_cache.pop(u"test", cache.number))
        # add cache
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(u"test", cache.number))
        self.assertEqual(request_cache.get(u"test", cache.number), cache)
        # remove
        self.assertEqual(request_cache.pop(u"test", cache.number), cache)

        # pop() used to still work after the first pop()
        self.assertFalse(request_cache.has(u"test", cache.number))
        self.assertIsNone(request_cache.get(u"test", cache.number))
        self.assertIsNone(request_cache.pop(u"test", cache.number))

    @call_on_mm_thread
    def test_fixed_number(self):
        """
        Tests NumberCache
        """
        request_cache = RequestCache(self._dispersy.callback)
        cache = NumberCache(request_cache, u"test", 1)

        self.assertFalse(request_cache.has(u"test", cache.number))
        self.assertEqual(request_cache.add(cache), cache)
        self.assertTrue(request_cache.has(u"test", cache.number))

        self.assertRaises(RuntimeError, NumberCache, request_cache, u"test", 1)
