from Meta import MetaObject

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

class Distribution(MetaObject):
    class Implementation(MetaObject.Implementation):
        def __init__(self, meta, global_time):
            assert isinstance(meta, Distribution)
            assert isinstance(global_time, (int, long))
            super(Distribution.Implementation, self).__init__(meta)
            # the last known global time + 1 (from the user who signed the
            # message)
            self._global_time = global_time

        @property
        def global_time(self):
            return self._global_time

class SyncDistribution(Distribution):
    class Implementation(Distribution.Implementation):
        pass

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

class DirectDistribution(Distribution):
    class Implementation(Distribution.Implementation):
        pass

class RelayDistribution(Distribution):
    class Implementation(Distribution.Implementation):
        pass
        
# if __debug__:
#     def main():
#         meta = Distribution()
#         print meta, meta.implement(42)

#         meta = SyncDistribution(100, 100, 0.001)
#         print meta, meta.implement(42)

#         meta = FullSyncDistribution(100, 100, 0.001)
#         print meta, meta.implement(42, 8)

#         meta = LastSyncDistribution(100, 100, 0.001)
#         print meta, meta.implement(42)

#         meta = DirectDistribution()
#         print meta, meta.implement(42)

#         meta = RelayDistribution()
#         print meta, meta.implement(42)


#     if __name__ == "__main__":
#         main()



