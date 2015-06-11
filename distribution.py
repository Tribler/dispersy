"""
Each Privilege can be distributed, usually through the transfer of a message, in different ways.
These ways are defined by DistributionMeta object that is associated to the Privilege.

The DistributionMeta associated to the Privilege is used to create a Distribution object that is
assigned to the Message.

Example: A community has a permission called 'user-name'.  This Permission has the
LastSyncDistributionMeta object assigned to it.  The LastSyncDistributionMeta object dictates some
values such as the size and stepping used for the BloomFilter.

Whenever a the 'user-name' Permission is used, a LastSyncDistribution object is created.  The
LastSyncDistribution object holds additional information for this specific message, such as the
global_time.
"""

from abc import ABCMeta, abstractmethod
from .meta import MetaObject


class Pruning(MetaObject):

    class Implementation(MetaObject.Implementation):

        __metaclass__ = ABCMeta

        def __init__(self, meta, distribution):
            assert isinstance(distribution, SyncDistribution.Implementation), type(distribution)
            super(Pruning.Implementation, self).__init__(meta)
            self._distribution = distribution

        def get_state(self):
            if self.is_active():
                return "active"
            if self.is_inactive():
                return "inactive"
            if self.is_pruned():
                return "pruned"
            raise RuntimeError("Unable to obtain pruning state")

        @abstractmethod
        def is_active(self):
            pass

        @abstractmethod
        def is_inactive(self):
            pass

        @abstractmethod
        def is_pruned(self):
            pass


class NoPruning(Pruning):

    class Implementation(Pruning.Implementation):

        def is_active(self):
            return True

        def is_inactive(self):
            return False

        def is_pruned(self):
            return False


class GlobalTimePruning(Pruning):

    class Implementation(Pruning.Implementation):

        @property
        def inactive_threshold(self):
            return self._meta.inactive_threshold

        @property
        def prune_threshold(self):
            return self._meta.prune_threshold

        def is_active(self):
            return self._distribution.community.global_time - self._distribution.global_time < self._meta.inactive_threshold

        def is_inactive(self):
            return self._meta.inactive_threshold <= self._distribution.community.global_time - self._distribution.global_time < self._meta.prune_threshold

        def is_pruned(self):
            return self._meta.prune_threshold <= self._distribution.community.global_time - self._distribution.global_time

    def __init__(self, inactive, pruned):
        """
        Construct a new GlobalTimePruning object.

        INACTIVE is the number at which the message goes from state active to inactive.
        PRUNED is the number at which the message goes from state inactive to pruned.

        A message has the following states:
        - active:   current_global_time - message_global_time < INACTIVE
        - inactive: INACTIVE <= current_global_time - message_global_time < PRUNED
        - pruned:  PRUNED <= current_global_time - message_global_time
        """
        assert isinstance(inactive, int), type(inactive)
        assert isinstance(pruned, int), type(pruned)
        assert 0 < inactive < pruned, [inactive, pruned]
        super(GlobalTimePruning, self).__init__()
        self._inactive_threshold = inactive
        self._prune_threshold = pruned

    @property
    def inactive_threshold(self):
        return self._inactive_threshold

    @property
    def prune_threshold(self):
        return self._prune_threshold


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

    def setup(self, message):
        """
        Setup is called after the meta message is initially created.
        """
        from .message import Message
        assert isinstance(message, Message)


class SyncDistribution(Distribution):

    """
    Allows gossiping and synchronization of messages throughout the community.

    The PRIORITY value ranges [0:255] where the 0 is the lowest priority and 255 the highest.  Any
    messages that have a priority below 32 will not be synced.  These messages require a mechanism
    to request missing messages whenever they are needed.

    The PRIORITY was introduced when we found that the dispersy-identity messages are the majority
    of gossiped messages while very few are actually required.  The dispersy-missing-identity
    message is used to retrieve an identity whenever it is needed.
    """

    class Implementation(Distribution.Implementation):

        def __init__(self, meta, global_time):
            super(SyncDistribution.Implementation, self).__init__(meta, global_time)
            self._pruning = meta.pruning.Implementation(meta.pruning, self)

        @property
        def community(self):
            return self._meta._community

        @property
        def synchronization_direction(self):
            return self._meta._synchronization_direction

        @property
        def synchronization_direction_id(self):
            return self._meta._synchronization_direction_id

        @property
        def priority(self):
            return self._meta._priority

        @property
        def database_id(self):
            return self._meta._database_id

        @property
        def pruning(self):
            return self._pruning

    def __init__(self, synchronization_direction, priority, pruning=NoPruning()):
        # note: messages with a high priority value are synced before those with a low priority
        # value.
        # note: the priority has precedence over the global_time based ordering.
        # note: the default priority should be 127, use higher or lowe values when needed.
        assert isinstance(synchronization_direction, unicode)
        assert synchronization_direction in (u"ASC", u"DESC", u"RANDOM")
        assert isinstance(priority, int)
        assert 0 <= priority <= 255
        assert isinstance(pruning, Pruning), type(pruning)
        self._synchronization_direction = synchronization_direction
        self._priority = priority
        self._current_sequence_number = 0
        self._pruning = pruning
#        self._database_id = 0

    @property
    def community(self):
        return self._community

    @property
    def synchronization_direction(self):
        return self._synchronization_direction

    @property
    def synchronization_direction_value(self):
        return {u"ASC":1, u"DESC":-1, u"RANDOM":0}[self._synchronization_direction]

    @property
    def priority(self):
        return self._priority

    @property
    def pruning(self):
        return self._pruning

    # @property
    # def database_id(self):
    #     return self._database_id

    def setup(self, message):
        """
        Setup is called after the meta message is initially created.

        It is used to determine the current sequence number, based on
        which messages are already in the database.
        """
        from .message import Message
        assert isinstance(message, Message)

        # pruning requires information from the community
        self._community = message.community

        # use cache to avoid database queries
        cache = message.community.meta_message_cache[message.name]
        cache["priority"] = self._priority
        cache["direction"] = self.synchronization_direction_value


class FullSyncDistribution(SyncDistribution):

    """
    Allows gossiping and synchronization of messages throughout the community.

    Sequence numbers can be enabled or disabled per meta-message.  When disabled the sequence number
    is always zero.  When enabled the claim_sequence_number method can be called to obtain the next
    sequence number in sequence.

    Currently there is one situation where disabling sequence numbers is required.  This is when the
    message will be signed by multiple members.  In this case the sequence number is claimed but may
    not be used (if the other members refuse to add their signature).  This causes a missing
    sequence message.  This in turn could be solved by creating a placeholder message, however, this
    is not currently, and my never be, implemented.
    """
    class Implementation(SyncDistribution.Implementation):

        def __init__(self, meta, global_time, sequence_number=0):
            assert isinstance(sequence_number, (int, long))
            assert (meta._enable_sequence_number and sequence_number > 0) or (not meta._enable_sequence_number and sequence_number == 0), (meta._enable_sequence_number, sequence_number)
            super(FullSyncDistribution.Implementation, self).__init__(meta, global_time)
            self._sequence_number = sequence_number

        @property
        def enable_sequence_number(self):
            return self._meta._enable_sequence_number

        @property
        def sequence_number(self):
            return self._sequence_number

    def __init__(self, synchronization_direction, priority, enable_sequence_number, pruning=NoPruning()):
        assert isinstance(enable_sequence_number, bool)
        super(FullSyncDistribution, self).__init__(synchronization_direction, priority, pruning)
        self._enable_sequence_number = enable_sequence_number

    @property
    def enable_sequence_number(self):
        return self._enable_sequence_number

    def claim_sequence_number(self):
        assert self._enable_sequence_number
        self._current_sequence_number += 1
        return self._current_sequence_number


class LastSyncDistribution(SyncDistribution):

    class Implementation(SyncDistribution.Implementation):

        @property
        def history_size(self):
            return self._meta._history_size

    def __init__(self, synchronization_direction, priority, history_size, pruning=NoPruning(), custom_callback=None):
        assert isinstance(history_size, int)
        assert history_size > 0
        assert not custom_callback or isinstance(custom_callback, tuple), u"callback should tuple of two methods (0) check (1) delete."
        super(LastSyncDistribution, self).__init__(synchronization_direction, priority, pruning)
        self._history_size = history_size
        self._custom_callback = custom_callback

    @property
    def history_size(self):
        return self._history_size

    @property
    def custom_callback(self, ):
        return self._custom_callback


class DirectDistribution(Distribution):

    class Implementation(Distribution.Implementation):
        pass


class RelayDistribution(Distribution):

    class Implementation(Distribution.Implementation):
        pass
