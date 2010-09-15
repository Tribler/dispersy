"""
Each Privilege can be distributed, usualy through the transfer of a
message, in different ways.  These ways are defined by
DistributionMeta object that is associated to the Privilege.

The DistributionMeta associated to the Privilege is used to create a
Distribution object that is assigned to the Message.

Example: A community has a permission called 'user-name'.  This
Permission has the LastSyncDistributionMeta object assigned to it.
The LastSyncDistributionMeta object dictates some values such as the
size and stepping used for the BloomFilter.

Whenever a the 'user-name' Permission is used, a LastSyncDistribution
object is created.  The LastSyncDistribution object holds additional
information for this specific message, such as the global_time.
"""

class DistributionBase(object):
    class Implementation(object):
        def __init__(self, meta, global_time):
            assert isinstance(meta, DistributionBase)
            assert isinstance(global_time, (int, long))
            # the associated distribution
            self._meta = meta
            # the last known global time + 1 (from the user who signed the
            # message)
            self._global_time = global_time

        @property
        def meta(self):
            return self._meta

        @property
        def global_time(self):
            return self._global_time

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__} global_time:{0.global_time}>".format(self)

    def __str__(self):
        return "<{0.__class__.__name__}>".format(self)

    def implement(self, *args, **kargs):
        return self.Implementation(self, *args, **kargs)

class SyncDistribution(DistributionBase):
    class Implementation(DistributionBase.Implementation):
        pass
    
    def __init__(self, stepping, capacity, error_rate):
        """
        Sync using a BloomFilter.

        A seperate BloomFilter is created to hash all messages in one
        STEPPING range.  The first BloomFilter will hash all messages
        with 0 <= global_time < STEPPING, the second BloomFilter will
        hash all messages with STEPPING <= global_time < 2*STEPPING,
        etc.

        Each BloomFilter will have CAPACITY and ERROR_RATE.  These two
        values directly reflect the size of the BloomFilter.  Given an
        ERROR_RATE of 0.0001, a CAPACITY of 100 can store 1000 unique
        hashes with 93% recall rate.
        """
        assert isinstance(stepping, int)
        assert isinstance(capacity, int)
        assert isinstance(error_rate, float)
        self._stepping = stepping
        self._capacity = capacity
        self._error_rate = error_rate

    @property
    def stepping(self):
        return self._stepping

    @property
    def capacity(self):
        return self._capacity

    @property
    def error_rate(self):
        return self._error_rate

    def __str__(self):
        return "<{0.__class__.__name__} stepping:{0.stepping} capacity:{0.capacity} error_rate:{0.error_rate}>".format(self)

class FullSyncDistribution(SyncDistribution):
    class Implementation(SyncDistribution.Implementation):
        def __init__(self, meta, global_time, sequence_number):
            assert isinstance(meta, FullSyncDistribution)
            assert isinstance(global_time, (int, long))
            assert isinstance(sequence_number, (int, long))
            super(FullSyncDistribution.Implementation, self).__init__(meta, global_time)
            # the sequence number (from the user who signed the messaged)
            self._sequence_number = sequence_number

        @property
        def sequence_number(self):
            return self._sequence_number

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__} global_time:{0.global_time} sequence_number:{0.sequence_number}>".format(self)

class LastSyncDistribution(SyncDistribution):
    class Implementation(SyncDistribution.Implementation):
        if __debug__:
            def __init__(self, meta, global_time):
                assert isinstance(meta, LastSyncDistribution)
                assert isinstance(global_time, (int, long))
                super(LastSyncDistribution.Implementation, self).__init__(meta, global_time)

# class MinimalSyncDistribution(SyncDistribution):
#     class Implementation(SyncDistribution.Implementation):
#         def __init__(self, meta, global_time, minimal_count):
#             assert isinstance(meta, MinimalSyncDistribution)
#             assert isinstance(global_time, (int, long))
#             assert isinstance(sequence_number, (int, long))
#             assert isinstance(minimal_count, (int, long))
#             super(MinimalSyncDistribution.Implementation, self).__init__(meta, sequence_number)

#             # the minimal number of nodes online that should have the
#             # message
#             self._minimal_count = minimal_count

#         @property
#         def minimal_count(self):
#             return self._minimal_count

#         def __str__(self):
#             return "<{0} {1}:- {2}>".format(self.__class__.__name__, self._global_time, self._minimal_count)

class DirectDistribution(DistributionBase):
    class Implementation(DistributionBase.Implementation):
        pass

class RelayDistribution(DistributionBase):
    class Implementation(DistributionBase.Implementation):
        pass
        
if __debug__:
    def main():
        meta = DistributionBase()
        print meta, meta.implement(42)

        meta = SyncDistribution(100, 100, 0.001)
        print meta, meta.implement(42)

        meta = FullSyncDistribution(100, 100, 0.001)
        print meta, meta.implement(42, 8)

        meta = LastSyncDistribution(100, 100, 0.001)
        print meta, meta.implement(42)

        meta = DirectDistribution()
        print meta, meta.implement(42)

        meta = RelayDistribution()
        print meta, meta.implement(42)


    if __name__ == "__main__":
        main()



