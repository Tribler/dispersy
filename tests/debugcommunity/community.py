from ...authentication import DoubleMemberAuthentication, MemberAuthentication
from ...candidate import Candidate
from ...community import Community, HardKilledCommunity
from ...conversion import DefaultConversion
from ...destination import CommunityDestination, NHopCommunityDestination
from ...distribution import DirectDistribution, FullSyncDistribution, LastSyncDistribution, GlobalTimePruning
from ...message import Message, DelayMessageByProof, BatchConfiguration
from ...resolution import PublicResolution, LinearResolution, DynamicResolution

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

    @property
    def dispersy_enable_candidate_walker(self):
        # disable candidate walker
        return False

    @property
    def dispersy_enable_candidate_walker_responses(self):
        # enable walker responses
        return True

    def initiate_meta_messages(self):
        messages = super(DebugCommunity, self).initiate_meta_messages()
        messages.extend([
            Message(self, u"last-1-test",
                    MemberAuthentication(),
                    PublicResolution(),
                    LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1),
                    CommunityDestination(node_count=10),
                    TextPayload(),
                    self._generic_timeline_check,
                    self.on_text),
            Message(self, u"last-9-test",
                    MemberAuthentication(),
                    PublicResolution(),
                    LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=9),
                    CommunityDestination(node_count=10),
                    TextPayload(),
                    self._generic_timeline_check,
                    self.on_text),
                Message(self, u"last-1-doublemember-text",
                        DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text),
                        PublicResolution(),
                        LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1),
                        NHopCommunityDestination(node_count=10, depth=42),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"double-signed-text",
                        DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text),
                        PublicResolution(),
                        DirectDistribution(),
                        NHopCommunityDestination(node_count=10, depth=42),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"double-signed-text-split",
                        DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text, split_payload_func=self.split_double_payload),
                        PublicResolution(),
                        DirectDistribution(),
                        NHopCommunityDestination(node_count=10, depth=42),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"full-sync-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"n-hop-sync-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        NHopCommunityDestination(node_count=1, depth=1),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"bin-key-text",
                        MemberAuthentication(encoding="bin"),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"ASC-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"DESC-text", MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"DESC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"protected-full-sync-text",
                        MemberAuthentication(),
                        LinearResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"dynamic-resolution-text",
                        MemberAuthentication(),
                        DynamicResolution(PublicResolution(),
                                          LinearResolution()),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"sequence-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"full-sync-global-time-pruning-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128, pruning=GlobalTimePruning(10, 20)),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text,
                        self.undo_text),
                Message(self, u"high-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=200),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"low-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=100),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"medium-priority-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=150),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"RANDOM-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"RANDOM", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
                        self.on_text),
                Message(self, u"batched-text",
                        MemberAuthentication(),
                        PublicResolution(),
                        FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128),
                        CommunityDestination(node_count=10),
                        TextPayload(),
                        self._generic_timeline_check,
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
        self._logger.debug("%s \"%s\"", message, message.payload.text)
        allow_text = message.payload.text
        assert allow_text.startswith("Allow=True") or allow_text.startswith("Allow=False") or allow_text.startswith("Allow=Modify") or allow_text.startswith("Allow=Append")
        if allow_text.startswith("Allow=True"):
            return message

        if allow_text.startswith("Allow=Modify"):
            meta = message.meta
            return meta.impl(authentication=(message.authentication.members,),
                         distribution=(message.distribution.global_time,),
                         payload=("MODIFIED",))

        if allow_text.startswith("Allow=Append"):
            meta = message.meta
            return meta.impl(authentication=(message.authentication.members, message.authentication._signatures),
                         distribution=(message.distribution.global_time,),
                         payload=(allow_text + "MODIFIED",))

    def split_double_payload(self, payload):
        # alice signs until the ","
        # bob signs the complete payload
        return payload.rsplit(",", 1)[0], payload

    def on_text(self, messages):
        """
        Received a text message.
        """
        meta = messages[0].meta

        for message in messages:
            if not "Dprint=False" in message.payload.text:
                self._logger.debug("%s \"%s\" @%d", message, message.payload.text, message.distribution.global_time)

    def undo_text(self, descriptors):
        """
        Received an undo for a text message.
        """
        for member, global_time, packet in descriptors:
            message = packet.load_message()
            self._logger.debug("undo \"%s\" @%d", message.payload.text, global_time)

    def dispersy_cleanup_community(self, message):
        if message.payload.is_soft_kill:
            raise NotImplementedError()

        elif message.payload.is_hard_kill:
            return HardKilledDebugCommunity


class HardKilledDebugCommunity(DebugCommunity, HardKilledCommunity):
    pass
