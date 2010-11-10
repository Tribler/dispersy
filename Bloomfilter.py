"""
Bloomfilter implementation based on pybloom by Jay Baird
<jay@mochimedia.com> and Bob Ippolito <bob@redivi.com>.

Simplified, and optimized to use just python code by Boudewijn Schoon.
"""

import hashlib
import math
from array import array
from struct import unpack_from, unpack, pack

from Decorator import Constructor, constructor

if __debug__:
    from Print import dprint
    from time import time

def _make_hashfuncs(num_slices, num_bits):
    if num_bits >= (1 << 31):
        fmt_code, chunk_size = 'Q', 8
    elif num_bits >= (1 << 15):
        fmt_code, chunk_size = 'L', 4
    else:
        fmt_code, chunk_size = 'H', 2
    total_hash_bits = 8 * num_slices * chunk_size
    if total_hash_bits > 384:
        hashfn = hashlib.sha512
    elif total_hash_bits > 256:
        hashfn = hashlib.sha384
    elif total_hash_bits > 160:
        hashfn = hashlib.sha256
    elif total_hash_bits > 128:
        hashfn = hashlib.sha1
    else:
        hashfn = hashlib.md5
    fmt = fmt_code * (hashfn().digest_size // chunk_size)
    num_salts, extra = divmod(num_slices, len(fmt))
    if extra:
        num_salts += 1
    salts = [hashfn(hashfn(pack('L', i)).digest()) for i in xrange(num_salts)]
    def _make_hashfuncs_helper(key):
        assert isinstance(key, str), "KEY must be a binary string"
        rval = []
        for salt in salts:
            h = salt.copy()
            h.update(key)
            rval.extend(uint % num_bits for uint in unpack(fmt, h.digest()))

        # if __debug__:
        #     if len(rval) > num_slices:
        #         print "Wasted", len(rval) - num_slices, "cycles"

        del rval[num_slices:]
        return rval
    return _make_hashfuncs_helper

class BloomFilter(Constructor):
    """
    Implements a space-efficient probabilistic data structure.

    There are two overloaded constructors:
     - __init__(CAPACITY, ERROR_RATE)
     - __init__(DATA, OFFSET)

    CAPACITY: this BloomFilter must be able to store at least CAPACITY
    elements while maintaining no more than ERROR_RATE chance of false
    positives.

    ERROR_RATE: the error_rate of the filter returning false
    positives. This determines the filters capacity. Inserting more
    than capacity elements greatly increases the chance of false
    positives.

    DATA: the stream contains binary data for a BloomFilter.

    OFFSET: the start of the bloomfiter in DATA

    >>> # use CAPACITY, ERROR_RATE constructor
    >>> b = BloomFilter(100000, 0.001)
    >>> b.add("test")
    True
    >>> "test" in b
    True

    >>> # use DATA, OFFSET constructor
    >>> b = BloomFilter(100000, 0.001)
    >>> b.add("test")
    >>> data = str(b)
    >>> c = BloomFilter(data, 0)
    >>> "test" in c
    True
    """

    @constructor((int, long), float)
    def _init_new(self, capacity, error_rate):
        assert isinstance(capacity, (int, long))
        assert isinstance(error_rate, float)
        assert 0 < error_rate < 1, "Error_Rate must be between 0 and 1"
        assert capacity > 0, "Capacity must be > 0"
        # given M = num_bits, k = num_slices, p = error_rate, n = capacity
        # solving for m = bits_per_slice
        # n ~= M * ((ln(2) ** 2) / abs(ln(P)))
        # n ~= (k * m) * ((ln(2) ** 2) / abs(ln(P)))
        # m ~= n * abs(ln(P)) / (k * (ln(2) ** 2))
        self._num_slices = int(math.ceil(math.log(1 / error_rate, 2)))
        # the error_rate constraint assumes a fill rate of 1/2
        # so we double the capacity to simplify the API
        self._bits_per_slice = int(((capacity * math.log(error_rate)) / math.log(1.0 / (math.pow(2.0, math.log(2.0)))) ) / self._num_slices)
        self._make_hashes = _make_hashfuncs(self._num_slices, self._bits_per_slice)
        self._bytes = array("B", (0 for _ in xrange(int(math.ceil(self._num_slices * self._bits_per_slice / 8.0)))))

    @constructor(str, (int, long))
    def _init_load(self, data, offset):
        assert isinstance(data, str)
        if len(data) < offset + 8:
            raise ValueError("Insufficient bytes")

        self._num_slices, self._bits_per_slice = unpack_from("!LL", data, offset)
        size = int(math.ceil(self._num_slices * self._bits_per_slice / 8.0))
        if len(data) < offset + 8 + size:
            raise ValueError("Insufficient bytes")

        self._make_hashes = _make_hashfuncs(self._num_slices, self._bits_per_slice)
        self._bytes = array("B", data[offset+8:offset+8+size])

    def __contains__(self, key):
        """
        Tests a key's membership in this bloom filter.

        >>> b = BloomFilter(capacity=100)
        >>> b.add("hello")
        >>> "hello" in b
        True
        """
        assert isinstance(key, str), "Key must be a binary string"
        bits_per_slice = self._bits_per_slice
        bytes = self._bytes
        offset = 0
        for i in self._make_hashes(key):
            if not bytes[(offset + i) / 8] & 1<<(offset + i) % 8:
                return False
            offset += bits_per_slice
        return True

    def add(self, key):
        """
        Adds a key to this bloom filter. 

        >>> b = BloomFilter(capacity=100)
        >>> b.add("hello")
        >>> b.add("hello")
        """
        assert isinstance(key, str), "Key must be a binary string"
        bytes = self._bytes
        bits_per_slice = self._bits_per_slice
        offset = 0
        for i in self._make_hashes(key):
            bytes[(offset + i) / 8] |=  1<<(offset + i) % 8
            offset += bits_per_slice

    def __and__(self, other):
        assert isinstance(other, BloomFilter)
        if not (self._num_slices == other._num_slices and self._bits_per_slice == other._bits_per_slice):
            raise ValueError("Both bloom filters need to be the same size")
        return BloomFilter(pack("!LL", self._num_slices, self._bits_per_slice) + array("B", [i&j for i, j in zip(self._bytes, other._bytes)]).tostring(), 0)

    def __or__(self, other):
        raise NotImplementedError()

    def __xor__(self, other):
        assert isinstance(other, BloomFilter)
        if not (self._num_slices == other._num_slices and self._bits_per_slice == other._bits_per_slice):
            raise ValueError("Both bloom filters need to be the same size")
        return BloomFilter(pack("!LL", self._num_slices, self._bits_per_slice) + array("B", [i^j for i, j in zip(self._bytes, other._bytes)]).tostring(), 0)
        
    def __str__(self):
        """
        Create a string representation of the BloomFilter.
        """
        return pack("!LL", self._num_slices, self._bits_per_slice) + self._bytes.tostring()

    def __len__(self):
        """
        Returns the size of the bloom filter and its adminitration
        value in bytes.  Note that this is the same as
        len(str(bloom_filter)), only faster.
        """
        return 8 + len(self._bytes)

if __debug__:
    def _performance_test():
        def test2(bits, count):
            generate_begin = time()
            ok = 0
            sha1 = hashlib.sha1
            data = [(i, sha1(str(i)).digest()) for i in xrange(count)]
            create_begin = time()
            bloom = BloomFilter(bits, 0.0001)
            fill_begin = time()
            for i, h in data:
                if i % 2 == 0:
                    bloom.add(h)
            check_begin = time()
            for i, h in data:
                if (h in bloom) == (i % 2 == 0):
                    ok += 1
            write_begin = time()
            string = str(bloom)
            write_end = time()

            print "generate: {generate:.1f}; create: {create:.1f}; fill: {fill:.1f}; check: {check:.1f}; write: {write:.1f}".format(generate=create_begin-generate_begin, create=fill_begin-create_begin, fill=check_begin-fill_begin, check=write_begin-check_begin, write=write_end-write_begin)
            print string.encode("HEX")[:100], "{len} bytes; ({ok}/{total} ~{part:.0%})".format(len=len(string), ok=ok, total=count, part=1.0*ok/count)

        def test(bits, count):
            ok = 0
            create_begin = time()
            bloom = BloomFilter(bits, 0.0001)
            fill_begin = time()
            for i in xrange(count):
                if i % 2 == 0:
                    bloom.add(str(i))
            check_begin = time()
            for i in xrange(count):
                if (str(i) in bloom) == (i % 2 == 0):
                    ok += 1
            write_begin = time()
            string = str(bloom)
            write_end = time()

            print "create: {create:.1f}; fill: {fill:.1f}; check: {check:.1f}; write: {write:.1f}".format(create=fill_begin-create_begin, fill=check_begin-fill_begin, check=write_begin-check_begin, write=write_end-write_begin)
            print string.encode("HEX")[:100], "{len} bytes; ({ok}/{total} ~{part:.0%})".format(len=len(string), ok=ok, total=count, part=1.0*ok/count)

        b = BloomFilter(100, 0.0001)
        b.add("Hello")
        data = str(b)

        c = BloomFilter(data, 0)
        assert "Hello" in c
        assert not "Bye" in c

        test2(10, 10)
        test2(10, 100)

# generate: 0.0; create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000001d000000241400480001840684024080408012800008012424018008a0401001080280008500241000 45 bytes; (10/10 ~100%)
# generate: 0.0; create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000001d000000bfbedf7fbafff4bffff7fdb7efdffe8df74f9fff6dbffb7bed7fdaf9ae76dfefffebffdb03 45 bytes; (90/100 ~90%)

        test2(100, 100)
        test2(100, 1000)

# generate: 0.0; create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000002001000002050100400001820008020388084422108050c0b41440804a003044204020082804000049820c880420 368 bytes; (100/100 ~100%)
# generate: 0.0; create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a000000200100009eedefcc77df2fff1feffe5fdeeefebffefe7fddffb77bf1cff574ddbedffafdbffffdf6fdef7f9ebf7f 368 bytes; (919/1000 ~92%)

        test2(1000, 1000)
        test2(1000, 10000)

# generate: 0.0; create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000003c0b0000a203040502001140c0000010840900420a06152400042000004222010090000022861000824010102001 3603 bytes; (1000/1000 ~100%)
# generate: 0.0; create: 0.0; fill: 0.1; check: 0.1; write: 0.0
# 0a0000003c0b0000fad3ffeffffdfb7efb5efffcfefffceffb7fffb7df3ffff99f7bffd5fdd7f65d76e7ff2f9feffcda7fff 3603 bytes; (9279/10000 ~93%)

        test2(10000, 10000)
        test2(10000, 100000)

# generate: 0.0; create: 0.0; fill: 0.1; check: 0.1; write: 0.0
# 0a00000054700000205286262400208041034085040005524802d8667048204220001214805020502002600408060080d009 35953 bytes; (10000/10000 ~100%)
# generate: 0.2; create: 0.0; fill: 0.7; check: 1.3; write: 0.0
# 0a00000054700000fbfffffeffffffbbfffffff7edbfffffff7fdffff7dbffffffffffbf9efafffbfffff5dddbdfffffd7ff 35953 bytes; (92622/100000 ~93%)

        test(10, 10)
        test(10, 100)

# create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000001d00000081012001030240322100040400440c510024402060400100010410088c0005020a18020100 45 bytes; (10/10 ~100%)
# create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000001d000000ebfff7fbefdedfbbeffffdeee7ddbf7fb7fdff77ffff77f5d74dff9efdffffffef7f9e3f03 45 bytes; (92/100 ~92%)

        test(100, 100)
        test(100, 1000)

# create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000002001000000108007008010210218120a0802824800806a20911008424200a00a0000114000100009466002820916 368 bytes; (100/100 ~100%)
# create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a000000200100007ff7f777fabadfffd7fddfdf29dfdefe77fc7bedfffc7df37e7ff9ffbbfff57fb7feffcfdffd7ffffdbf 368 bytes; (915/1000 ~92%)

        test(1000, 1000)
        test(1000, 10000)

# create: 0.0; fill: 0.0; check: 0.0; write: 0.0
# 0a0000003c0b00000146869100238482200450100090040002000010000006244000000c4a0141040402210802000c208010 3603 bytes; (1000/1000 ~100%)
# create: 0.0; fill: 0.1; check: 0.1; write: 0.0
# 0a0000003c0b0000f7ffffbbdbfbefffeffff7ff5cffff27f6defffadff76ef5fbfbecffdfd7fdee77f7ffdffea07dfebbdf 3603 bytes; (9279/10000 ~93%)

        test(10000, 10000)
        test(10000, 100000)

# create: 0.0; fill: 0.1; check: 0.1; write: 0.0
# 0a00000054700000130050403102c002410c410200a100700200cc0c0007620100142c408c4a82080082000a866d1818a211 35953 bytes; (10000/10000 ~100%)
# create: 0.0; fill: 0.8; check: 1.4; write: 0.0
# 0a000000547000009ffefff7fdffecff7dffffbeeefffffefffdffeef9efffffebff7ffdffffbfffd7ffeeefff7ffdfbffff 35953 bytes; (92520/100000 ~93%)

        test(100000, 100000)
        test(100000, 1000000)

# create: 0.1; fill: 1.2; check: 2.0; write: 0.0
# 0a00000040630400a4910840004240c0000220402010202000e003004101140003300180100400050422016004a005188084 359448 bytes; (100000/100000 ~100%)
# create: 0.1; fill: 12.3; check: 21.7; write: 0.0
# 0a00000040630400ffdffc5d45fff7ddcdaff6fffff57f3f3ffff77bfd7fbf5eb7b9f7ffff96f63fcefbcbefcfef2dff9ff5 359448 bytes; (927286/1000000 ~93%)
# create: 0.1; fill: 122.8; check: 237.7; write: 0.0

    def _taste_test():
        def pri(f, m):
            set_bits = 0
            for c in f._bytes.tostring():
                s = "{0:08d}".format(int(bin(ord(c))[2:]))
                for bit in s:
                    if bit == "1":
                        set_bits += 1
                print s,
            print "= {0:2d}:".format(set_bits), m

        def gen(l, m):
            for e in l:
                f = BloomFilter(CAPACITY, ERROR_RATE)
                f.add(e)
                pri(f, e)
            f = BloomFilter(CAPACITY, ERROR_RATE)
            map(f.add, l)
            pri(f, m + ": " + ", ".join(l))
            return f

        CAPACITY, ERROR_RATE = 10, 0.1

        a = gen(["kittens", "puppies"], "User A")
        b = gen(["beer", "bars"], "User B")
        c = gen(["puppies", "beer"], "User C")

        pri(a&b, "A AND B")
        pri(a&c, "A AND C")
        pri(b&c, "B AND C")

        # t1 = ["cake", "lemonade", "kittens", "puppies"]
        # b1 = BloomFilter(10, 0.8)
        # map(b1.add, t1)

        # t2 = ["beer", "booze", "women", "pubs"]
        # b2 = BloomFilter(10, 0.8)
        # map(b2.add, t2)

        # dprint(t1)
        # dprint(str(b1), binary=1)

        # dprint(t2)
        # dprint(str(b2), binary=1)

    if __name__ == "__main__":
        #_performance_test()
        _taste_test()
