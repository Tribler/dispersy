from ...authentication import DoubleMemberAuthentication, MemberAuthentication
from ...candidate import Candidate
from ...community import Community, HardKilledCommunity
from ...conversion import DefaultConversion
from ...destination import CommunityDestination
from ...cache import MissingSequenceCache
from ...distribution import DirectDistribution, FullSyncDistribution, LastSyncDistribution, GlobalTimePruning
from ...logger import get_logger
from ...message import Message, DelayMessageByProof, BatchConfiguration
from ...resolution import PublicResolution, LinearResolution, DynamicResolution
logger = get_logger(__name__)

from .payload import TextPayload
from .conversion import DebugCommunityConversion


class DebugCommunity(Community):

    """
    DebugCommunity is used to debug Dispersy related messages and policies.
    """
    @property
    def my_candidate(self):
        return Candidate(self._dispersy.lan_address, False)

    def initiate_conversions(self):
        return [DefaultConversion(self), DebugCommunityConversion(self)]

    def take_step(self):
        pass

    def initiate_meta_messages(self):
        messages = super(DebugCommunity, self).initiate_meta_messages()
        messages.extend([
            Message(self, u"last-1-test",
                    MemberAuthentication(),
                    PublicResolution(),
                    LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1),
                    CommunityDestination(node_count=10),
                    TextPayload(),
                    self.check_text,
                    self.on_text),
            Message(self, u"last-9-test",
                    MemberAuthentication(),
                    PublicResolution(),
                    LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=9),
                    CommunityDestination(node_count=10),
                    TextPayload(),
                    self.check_text,
                    self.on_text),
                Message(self, u"last-1-doublemember-text",
                        DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text),
                        PublicResolution(),
                        LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"double-signed-text",
                        DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text),
                        PublicResolution(),
                        DirectDistribution(),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"full-sync-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text,
                        self.undo_text),
                Message(self, u"ASC-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"DESC-text", MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"DESC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"protected-full-sync-text",
                        MemberAuthentication(),
                        LinearResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"dynamic-resolution-text",
                        MemberAuthentication(),
                        DynamicResolution(PublicResolution(),
                                          LinearResolution()),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text,
                        self.undo_text),
                Message(self, u"sequence-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text,
                        self.undo_text),
                Message(self, u"full-sync-global-time-pruning-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128, pruning=GlobalTimePruning(10, 20)),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text,
                        self.undo_text),
                Message(self, u"high-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=200),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"low-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=100),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"medium-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=150),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"RANDOM-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"RANDOM", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text),
                Message(self, u"batched-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self.check_text,
                        self.on_text,
                        batch=BatchConfiguration(max_window=5.0)),
                ])
        return messages

    #
    # double-signed-text
    #
    def allow_double_signed_text(self, message):
        """
        Received a request to sign MESSAGE.

        Must return either: a. the same message, b. a modified version of message, or c. None.
        """
        logger.debug("%s \"%s\"", message, message.payload.text)
        assert message.payload.text.startswith("Allow=True") or message.payload.text.startswith("Allow=False")
        if message.payload.text.startswith("Allow=True"):
            return message

    def check_text(self, messages):
        for message in messages:
            allowed, proof = self._timeline.check(message)
            if allowed:
                yield message
            else:
                yield DelayMessageByProof(message)

    def on_text(self, messages):
        """
        Received a text message.
        """
        meta = messages[0].meta

        for message in messages:
            if not "Dprint=False" in message.payload.text:
                logger.debug("%s \"%s\" @%d", message, message.payload.text, message.distribution.global_time)

        if isinstance(meta.distribution, FullSyncDistribution) and meta.distribution.enable_sequence_number:
            self.handle_missing_messages(messages, MissingSequenceCache)

    def undo_text(self, descriptors):
        """
        Received an undo for a text message.
        """
        for member, global_time, packet in descriptors:
            message = packet.load_message()
            logger.debug("undo \"%s\" @%d", message.payload.text, global_time)

    def dispersy_cleanup_community(self, message):
        if message.payload.is_soft_kill:
            raise NotImplementedError()

        elif message.payload.is_hard_kill:
            return HardKilledDebugCommunity


class HardKilledDebugCommunity(DebugCommunity, HardKilledCommunity):
    pass
