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
from .authentication import DoubleMemberAuthentication, MemberAuthentication
from .candidate import WalkCandidate
from .meta import MetaObject
from .util import attach_runtime_statistics


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

    def check_batch(self, dispersy, messages):
        """
        Returns the messages in the correct processing order.
        """
        return messages


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

    def _is_duplicate_sync_message(self, dispersy, message):
        """
        Returns True when this message is a duplicate, otherwise the message must be processed.

        === Problem: duplicate message ===
        The simplest reason to drop an incoming message is when we already have it, based on the
        community, member, and global time.  No further action is performed.

        === Problem: duplicate message, but that message is undone ===
        When a message is undone it should no longer be synced.  Hence, someone who syncs an undone
        message must not be aware of the undo message yet.  We will drop this message, but we will
        also send the appropriate undo message as a response.

        === Problem: same payload, different signature ===
        There is a possibility that a message is created that contains exactly the same payload but
        has a different signature.  This can occur when a message is created, forwarded, and for
        some reason the database is reset.  The next time that the client starts the exact same
        message may be generated.  However, because EC signatures contain a random element the
        signature will be different.

        This results in continued transfers because the bloom filters identify the two messages
        as different while the community/member/global_time triplet is the same.

        To solve this, we will silently replace one message with the other.  We choose to keep
        the message with the highest binary value while destroying the one with the lower binary
        value.

        === Optimization: temporarily modify the bloom filter ===
        Note: currently we generate bloom filters on the fly, therefore, we can not use this
        optimization.

        To further optimize, we will add both messages to our bloom filter whenever we detect
        this problem.  This will ensure that we do not needlessly receive the 'invalid' message
        until the bloom filter is synced with the database again.
        """
        community = message.community
        # fetch the duplicate binary packet from the database
        try:
            have_packet, undone = dispersy._database.execute(u"SELECT packet, undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                        (community.database_id, message.authentication.member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            dispersy._logger.debug("this message is not a duplicate")
            return False

        else:
            have_packet = str(have_packet)
            if have_packet == message.packet:
                # exact binary duplicate, do NOT process the message
                dispersy._logger.warning("received identical message %s %d@%d from %s %s",
                                     message.name,
                                     message.authentication.member.database_id,
                                     message.distribution.global_time,
                                     message.candidate,
                                     "(this message is undone)" if undone else "")

                if undone:
                    try:
                        proof, = dispersy._database.execute(u"SELECT packet FROM sync WHERE id = ?", (undone,)).next()
                    except StopIteration:
                        pass
                    else:
                        dispersy._send_packets([message.candidate], [str(proof)], community, "-caused by duplicate-undo-")

            else:
                signature_length = message.authentication.member.signature_length
                if have_packet[:signature_length] == message.packet[:signature_length]:
                    # the message payload is binary unique (only the signature is different)
                    dispersy._logger.warning("received identical message %s %d@%d with different signature from %s %s",
                                         message.name,
                                         message.authentication.member.database_id,
                                         message.distribution.global_time,
                                         message.candidate,
                                         "(this message is undone)" if undone else "")

                    if have_packet < message.packet:
                        # replace our current message with the other one
                        dispersy._database.execute(u"UPDATE sync SET packet = ? WHERE community = ? AND member = ? AND global_time = ?",
                                               (buffer(message.packet), community.database_id, message.authentication.member.database_id, message.distribution.global_time))

                        # notify that global times have changed
                        # community.update_sync_range(message.meta, [message.distribution.global_time])

                else:
                    dispersy._logger.warning("received message with duplicate community/member/global-time triplet from %s."
                                         "  possibly malicious behaviour", message.candidate)

            # this message is a duplicate
            return True


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

    @attach_runtime_statistics(u"{0.__class__.__name__}._check_distribution full_sync")
    def check_batch(self, dispersy, messages):
        """
        Ensure that we do not yet have the messages and that, if sequence numbers are enabled, we
        are not missing any previous messages.

        This method is called when a batch of messages with the FullSyncDistribution policy is
        received.  Duplicate messages will yield DropMessage.  And if enable_sequence_number is
        True, missing messages will yield the DelayMessageBySequence exception.

        @param messages: The messages that are to be checked.
        @type message: [Message.Implementation]

        @return: A generator with messages, DropMessage, or DelayMessageBySequence instances
        @rtype: [Message.Implementation|DropMessage|DelayMessageBySequence]
        """
        from .message import DelayMessageBySequence, DropMessage, Message

        assert isinstance(messages, list)
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)

        # a message is considered unique when (creator, global-time),
        # i.e. (authentication.member.database_id, distribution.global_time), is unique.
        unique = set()
        execute = dispersy._database.execute
        enable_sequence_number = messages[0].meta.distribution.enable_sequence_number

        # sort the messages by their (1) global_time and (2) binary packet
        messages = sorted(messages,
                          lambda a, b: cmp(a.distribution.global_time, b.distribution.global_time) or cmp(a.packet,
                                                                                                          b.packet))

        # refuse messages where the global time is unreasonably high
        acceptable_global_time = messages[0].community.acceptable_global_time

        if enable_sequence_number:
            # obtain the highest sequence_number from the database
            highest = {}
            for message in messages:
                if not message.authentication.member.database_id in highest:
                    last_global_time, last_seq, count = execute(
                        u"SELECT MAX(global_time), MAX(sequence), COUNT(*) FROM sync WHERE member = ? AND meta_message = ?",
                        (message.authentication.member.database_id, message.database_id)).next()
                    highest[message.authentication.member.database_id] = (last_global_time or 0, last_seq or 0)
                    assert last_seq or 0 == count, [last_seq, count, message.name]

            # all messages must follow the sequence_number order
            for message in messages:
                if message.distribution.global_time > acceptable_global_time:
                    yield DropMessage(message, "global time is not within acceptable range (%d, we accept %d)" % (
                    message.distribution.global_time, acceptable_global_time))
                    continue

                if not message.distribution.pruning.is_active():
                    yield DropMessage(message, "message has been pruned")
                    continue

                key = (message.authentication.member.database_id, message.distribution.global_time)
                if key in unique:
                    yield DropMessage(message, "duplicate message by member^global_time (1)")
                    continue

                unique.add(key)
                last_global_time, seq = highest[message.authentication.member.database_id]

                if seq >= message.distribution.sequence_number:
                    # we already have this message (drop)

                    # fetch the corresponding packet from the database (it should be binary identical)
                    global_time, packet = execute(
                        u"SELECT global_time, packet FROM sync WHERE member = ? AND meta_message = ? ORDER BY global_time, packet LIMIT 1 OFFSET ?",
                        (message.authentication.member.database_id, message.database_id,
                         message.distribution.sequence_number - 1)).next()
                    packet = str(packet)
                    if message.packet == packet:
                        yield DropMessage(message, "duplicate message by binary packet")
                        continue

                    else:
                        # we already have a message with this sequence number, but apparently both
                        # are signed/valid.  we need to discard one of them
                        if (global_time, packet) < (message.distribution.global_time, message.packet):
                            # we keep PACKET (i.e. the message that we currently have in our database)
                            # reply with the packet to let the peer know
                            dispersy._send_packets([message.candidate], [packet],
                                               message.community, "-caused by check_full_sync-")
                            yield DropMessage(message, "duplicate message by sequence number (1)")
                            continue

                        else:
                            # TODO we should undo the messages that we are about to remove (when applicable)
                            execute(u"DELETE FROM sync WHERE member = ? AND meta_message = ? AND global_time >= ?",
                                    (message.authentication.member.database_id, message.database_id, global_time))

                            # by deleting messages we changed SEQ and the HIGHEST cache
                            last_global_time, last_seq, count = execute(
                                u"SELECT MAX(global_time), MAX(sequence), COUNT(*) FROM sync WHERE member = ? AND meta_message = ?",
                                (message.authentication.member.database_id, message.database_id)).next()
                            highest[message.authentication.member.database_id] = (last_global_time or 0, last_seq or 0)
                            assert last_seq or 0 == count, [last_seq, count, message.name]
                            # we can allow MESSAGE to be processed

                elif seq + 1 != message.distribution.sequence_number:
                    # we do not have the previous message (delay and request)
                    yield DelayMessageBySequence(message, seq + 1, message.distribution.sequence_number - 1)
                    continue

                # we have the previous message, check for duplicates based on community,
                # member, and global_time
                if self._is_duplicate_sync_message(dispersy, message):
                    # we have the previous message (drop)
                    yield DropMessage(message, "duplicate message by global_time (1)")
                    continue

                # ensure that MESSAGE.distribution.global_time > LAST_GLOBAL_TIME
                if last_global_time and message.distribution.global_time <= last_global_time:
                    dispersy._logger.debug("last_global_time: %d  message @%d",
                                       last_global_time, message.distribution.global_time)
                    yield DropMessage(message, "higher sequence number with lower global time than most recent message")
                    continue

                # we accept this message
                highest[message.authentication.member.database_id] = (message.distribution.global_time, seq + 1)
                yield message

        else:
            for message in messages:
                if message.distribution.global_time > acceptable_global_time:
                    yield DropMessage(message, "global time is not within acceptable range")
                    continue

                if not message.distribution.pruning.is_active():
                    yield DropMessage(message, "message has been pruned")
                    continue

                key = (message.authentication.member.database_id, message.distribution.global_time)
                if key in unique:
                    yield DropMessage(message, "duplicate message by member^global_time (2)")
                    continue

                unique.add(key)

                # check for duplicates based on community, member, and global_time
                if self._is_duplicate_sync_message(dispersy, message):
                    # we have the previous message (drop)
                    yield DropMessage(message, "duplicate message by global_time (2)")
                    continue

                # we accept this message
                yield message


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

    @attach_runtime_statistics(u"{0.__class__.__name__}._check_distribution last_sync")
    def check_batch(self, dispersy, messages):
        """
        Check that the messages do not violate any database consistency rules.

        This method is called when a batch of messages with the LastSyncDistribution policy is
        received.  An iterator will be returned where each element is either: DropMessage (for
        duplicate and old messages), DelayMessage (for messages that requires something before they
        can be processed), or Message.Implementation when the message does not violate any rules.

        The rules:

         - The combination community, member, global_time must be unique.

         - When the MemberAuthentication policy is used: the message owner may not have more than
           history_size messages in the database at any one time.  Hence, if this limit is reached
           and the new message is older than the older message that is already available, it is
           dropped.

         - When the DoubleMemberAuthentication policy is used: the members that signed the message
           may not have more than history_size messages in the database at any one time.  Hence, if
           this limit is reached and the new message is older than the older message that is already
           available, it is dropped.  Note that the signature order is not important.

        @param messages: The messages that are to be checked.
        @type message: [Message.Implementation]

        @return: A generator with Message.Implementation or DropMessage instances
        @rtype: [Message.Implementation|DropMessage]
        """
        from .message import DropMessage, Message

        assert isinstance(messages, list)
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)
        assert all(isinstance(message.authentication,
                              (MemberAuthentication.Implementation, DoubleMemberAuthentication.Implementation)) for
                   message in messages)

        def check_member_and_global_time(unique, times, message):
            """
            The member + global_time combination must always be unique in the database
            """
            assert isinstance(unique, set)
            assert isinstance(times, dict)
            assert isinstance(message, Message.Implementation)
            assert isinstance(message.distribution, LastSyncDistribution.Implementation)

            key = (message.authentication.member.database_id, message.distribution.global_time)
            if key in unique:
                return DropMessage(message, "already processed message by member^global_time")

            else:
                unique.add(key)

                if not message.authentication.member.database_id in times:
                    times[message.authentication.member.database_id] = [global_time for global_time, in
                                                                        dispersy._database.execute(
                                                                            u"SELECT global_time FROM sync WHERE community = ? AND member = ? AND meta_message = ?",
                                                                            (message.community.database_id,
                                                                             message.authentication.member.database_id,
                                                                             message.database_id))]
                    assert len(times[message.authentication.member.database_id]) <= message.distribution.history_size, [
                        message.packet_id, message.distribution.history_size,
                        times[message.authentication.member.database_id]]
                tim = times[message.authentication.member.database_id]

                if message.distribution.global_time in tim and self._is_duplicate_sync_message(dispersy, message):
                    return DropMessage(message, "duplicate message by member^global_time (3)")

                elif len(tim) >= message.distribution.history_size and min(tim) > message.distribution.global_time:
                    # we have newer messages (drop)

                    # if the history_size is one, we can send that on message back because
                    # apparently the sender does not have this message yet
                    if message.distribution.history_size == 1:
                        try:
                            packet, = dispersy._database.execute(
                                u"SELECT packet FROM sync WHERE community = ? AND member = ? ORDER BY global_time DESC LIMIT 1",
                                (message.community.database_id, message.authentication.member.database_id)).next()
                        except StopIteration:
                            # TODO can still fail when packet is in one of the received messages
                            # from this batch.
                            pass
                        else:
                            dispersy._send_packets([message.candidate], [str(packet)],
                                               message.community, "-caused by check_last_sync:check_member-")

                    return DropMessage(message, "old message by member^global_time")

                else:
                    # we accept this message
                    tim.append(message.distribution.global_time)
                    return message

        def check_double_member_and_global_time(unique, times, message):
            """
            No other message may exist with this message.authentication.members / global_time
            combination, regardless of the ordering of the members
            """
            assert isinstance(unique, set)
            assert isinstance(times, dict)
            assert isinstance(message, Message.Implementation)
            assert isinstance(message.authentication, DoubleMemberAuthentication.Implementation)

            key = (message.authentication.member.database_id, message.distribution.global_time)
            if key in unique:
                dispersy._logger.debug("drop %s %d@%d (in unique)",
                                   message.name, message.authentication.member.database_id,
                                   message.distribution.global_time)
                return DropMessage(message, "already processed message by member^global_time")

            else:
                unique.add(key)

                members = tuple(sorted(member.database_id for member in message.authentication.members))
                key = members + (message.distribution.global_time,)
                if key in unique:
                    dispersy._logger.debug("drop %s %s@%d (in unique)",
                                       message.name, members, message.distribution.global_time)
                    return DropMessage(message, "already processed message by members^global_time")

                else:
                    unique.add(key)

                    if self._is_duplicate_sync_message(dispersy, message):
                        # we have the previous message (drop)
                        dispersy._logger.debug("drop %s %s@%d (_is_duplicate_sync_message)",
                                           message.name, members, message.distribution.global_time)
                        return DropMessage(message, "duplicate message by member^global_time (4)")

                    if not members in times:
                        # the next query obtains a list with all global times that we have in the
                        # database for all message.meta messages that were signed by
                        # message.authentication.members where the order of signing is not taken
                        # into account.
                        times[members] = dict((global_time, (packet_id, str(packet)))
                                              for global_time, packet_id, packet
                                              in dispersy._database.execute(u"""
    SELECT sync.global_time, sync.id, sync.packet
    FROM sync
    JOIN double_signed_sync ON double_signed_sync.sync = sync.id
    WHERE sync.meta_message = ? AND double_signed_sync.member1 = ? AND double_signed_sync.member2 = ?
    """,
                                                                        (message.database_id,) + members))
                        assert len(times[members]) <= message.distribution.history_size, [len(times[members]),
                                                                                          message.distribution.history_size]
                    tim = times[members]

                    if message.distribution.global_time in tim:
                        packet_id, have_packet = tim[message.distribution.global_time]

                        if message.packet == have_packet:
                            # exact binary duplicate, do NOT process the message
                            dispersy._logger.debug("received identical message %s %s@%d from %s",
                                               message.name,
                                               members,
                                               message.distribution.global_time,
                                               message.candidate)
                            return DropMessage(message, "duplicate message by binary packet (1)")

                        else:
                            signature_length = sum(member.signature_length for member in message.authentication.members)
                            member_authentication_begin = 23  # version, version, community-id, message-type
                            member_authentication_end = member_authentication_begin + 20 * len(
                                message.authentication.members)
                            if (have_packet[:member_authentication_begin] == message.packet[
                                                                             :member_authentication_begin] and
                                        have_packet[member_authentication_end:signature_length] == message.packet[
                                                                                                   member_authentication_end:signature_length]):
                                # the message payload is binary unique (only the member order or signatures are different)
                                dispersy._logger.debug("received identical message with different member-order"
                                                   " or signatures %s %s@%d from %s",
                                                   message.name, members, message.distribution.global_time,
                                                   message.candidate)

                                if have_packet < message.packet:
                                    # replace our current message with the other one
                                    dispersy._database.execute(u"UPDATE sync SET member = ?, packet = ? WHERE id = ?",
                                                           (message.authentication.member.database_id,
                                                            buffer(message.packet), packet_id))

                                    return DropMessage(message,
                                                       "replaced existing packet with other packet with the same payload")

                                return DropMessage(message,
                                                   "not replacing existing packet with other packet with the same payload")

                            else:
                                dispersy._logger.warning("received message with duplicate community/members/global-time"
                                                     " triplet from %s.  possibly malicious behavior",
                                                     message.candidate)
                                return DropMessage(message, "duplicate message by binary packet (2)")

                    elif len(tim) >= message.distribution.history_size and min(tim) > message.distribution.global_time:
                        # we have newer messages (drop)

                        # if the history_size is one, we can sent that on message back because
                        # apparently the sender does not have this message yet
                        if message.distribution.history_size == 1:
                            packet_id, have_packet = tim.values()[0]
                            dispersy._send_packets([message.candidate], [have_packet],
                                               message.community, "-caused by check_last_sync:check_double_member-")

                        dispersy._logger.debug("drop %s %s@%d (older than %s)",
                                           message.name, members, message.distribution.global_time, min(tim))
                        return DropMessage(message, "old message by members^global_time")

                    else:
                        # we accept this message
                        dispersy._logger.debug("accept %s %s@%d", message.name, members, message.distribution.global_time)
                        tim[message.distribution.global_time] = (0, message.packet)
                        return message

        # meta message
        meta = messages[0].meta

        # sort the messages by their (1) global_time and (2) binary packet
        messages = sorted(messages,
                          lambda a, b: cmp(a.distribution.global_time, b.distribution.global_time) or cmp(a.packet,
                                                                                                          b.packet))

        # refuse messages where the global time is unreasonably high
        acceptable_global_time = meta.community.acceptable_global_time
        messages = [message if message.distribution.global_time <= acceptable_global_time else DropMessage(message,
                                                                                                           "global time is not within acceptable range")
                    for message in messages]

        # refuse messages that have been pruned (or soon will be)
        messages = [DropMessage(message, "message has been pruned") if isinstance(message,
                                                                                  Message.Implementation) and not message.distribution.pruning.is_active() else message
                    for message in messages]

        # for meta data messages
        if meta.distribution.custom_callback:
            unique = set()
            times = {}
            messages = [
                message if isinstance(message, DropMessage) else meta.distribution.custom_callback[0](unique, times,
                                                                                                      message) for
                message in messages]

        # default behaviour
        elif isinstance(meta.authentication, MemberAuthentication):
            # a message is considered unique when (creator, global-time), i.r. (authentication.member,
            # distribution.global_time), is unique.  UNIQUE is used in the check_member_and_global_time
            # function
            unique = set()
            times = {}
            messages = [
                message if isinstance(message, DropMessage) else check_member_and_global_time(unique, times, message)
                for message in messages]

        # instead of storing HISTORY_SIZE messages for each authentication.member, we will store
        # HISTORY_SIZE messages for each combination of authentication.members.
        else:
            assert isinstance(meta.authentication, DoubleMemberAuthentication)
            unique = set()
            times = {}
            messages = [
                message if isinstance(message, DropMessage) else check_double_member_and_global_time(unique, times,
                                                                                                     message) for
                message in messages]

        return messages


class DirectDistribution(Distribution):

    class Implementation(Distribution.Implementation):
        pass

    @attach_runtime_statistics(u"{0.__class__.__name__}._check_distribution direct")
    def check_batch(self, dispersy, messages):
        """
        Returns the messages in the correct processing order.

        This method is called when a message with the DirectDistribution policy is received.  This
        message is not stored and hence we will not be able to see if we have already received this
        message.

        Receiving the same DirectDistribution multiple times indicates that the sending -wanted- to
        send this message multiple times.

        @param messages: Ignored.
        @type messages: [Message.Implementation]

        @return: All messages that are not dropped, i.e. all messages
        @rtype: [Message.Implementation]
        """
        # sort the messages by their (1) global_time and (2) binary packet
        messages = sorted(messages,
                          lambda a, b: cmp(a.distribution.global_time, b.distribution.global_time) or cmp(a.packet,
                                                                                                          b.packet))

        # direct messages tell us what other people believe is the current global_time
        for message in messages:
            if isinstance(message.candidate, WalkCandidate):
                message.candidate.global_time = message.distribution.global_time

            if isinstance(message.meta.authentication, MemberAuthentication):
                # until we implement a proper 3-way handshake we are going to assume that the creator of
                # this message is associated to this candidate
                message.candidate.associate(message.authentication.member)

        return messages


class RelayDistribution(Distribution):

    class Implementation(Distribution.Implementation):
        pass
