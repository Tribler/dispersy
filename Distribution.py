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
            assert global_time > 0
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

class LastSyncDistribution(SyncDistribution):
    class Implementation(SyncDistribution.Implementation):
        if __debug__:
            def __init__(self, meta, global_time):
                assert isinstance(meta, LastSyncDistribution)
                assert isinstance(global_time, (int, long))
                super(LastSyncDistribution.Implementation, self).__init__(meta, global_time)

        @property
        def cluster(self):
            return self._meta._cluster

        @property
        def history_size(self):
            return self._meta._history_size

    def __init__(self, cluster, history_size):
        assert isinstance(cluster, int)
        assert 0 <= cluster <= 255
        assert isinstance(history_size, int)
        self._cluster = cluster
        self._history_size = history_size

    @property
    def cluster(self):
        return self._cluster

    @property
    def history_size(self):
        return self._history_size

class DirectDistribution(Distribution):
    class Implementation(Distribution.Implementation):
        pass

class RelayDistribution(Distribution):
    class Implementation(Distribution.Implementation):
        pass



