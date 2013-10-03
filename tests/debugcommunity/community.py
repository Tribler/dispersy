from ...authentication import DoubleMemberAuthentication, MemberAuthentication
from ...candidate import Candidate
from ...community import Community, HardKilledCommunity
from ...conversion import DefaultConversion
from ...destination import CommunityDestination
from ...dispersy import MissingSequenceCache
from ...distribution import DirectDistribution, FullSyncDistribution, LastSyncDistribution, GlobalTimePruning
from ...logger import get_logger
from ...message import Message, DelayMessageByProof
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

    @property
    def dispersy_candidate_request_initial_delay(self):
        # disable candidate
        return 0.0

    @property
    def dispersy_sync_initial_delay(self):
        # disable sync
        return 0.0

    def initiate_conversions(self):
        return [DefaultConversion(self), DebugCommunityConversion(self)]

    #
    # helper methods to check database status
    #

    def fetch_packets(self, *message_names):
        return [str(packet) for packet, in list(self._dispersy.database.execute(u"SELECT packet FROM sync WHERE meta_message IN (" + ", ".join("?" * len(message_names)) + ") ORDER BY global_time, packet",
                                                                                [self.get_meta_message(name).database_id for name in message_names]))]

    def fetch_messages(self, *message_names):
        """
        Fetch all packets for MESSAGE_NAMES from the database and converts them into
        Message.Implementation instances.
        """
        return self._dispersy.convert_packets_to_messages(self.fetch_packets(*message_names), community=self, verify=False)

    def delete_messages(self, *message_names):
        """
        Deletes all packets for MESSAGE_NAMES from the database.  Returns the number of packets
        removed.
        """
        self._dispersy.database.execute(u"DELETE FROM sync WHERE meta_message IN (" + ", ".join("?" * len(message_names)) + ")",
                                        [self.get_meta_message(name).database_id for name in message_names])
        return self._dispersy.database.changes

    def initiate_meta_messages(self):
        return [Message(self, u"last-1-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"last-9-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=9), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"last-1-doublemember-text", DoubleMemberAuthentication(allow_signature_func=self.allow_signature_func), PublicResolution(), LastSyncDistribution(synchronization_direction=u"ASC", priority=128, history_size=1), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"double-signed-text", DoubleMemberAuthentication(allow_signature_func=self.allow_double_signed_text), PublicResolution(), DirectDistribution(), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"full-sync-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text, self.undo_text),
                Message(self, u"ASC-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"DESC-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"DESC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"protected-full-sync-text", MemberAuthentication(), LinearResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"dynamic-resolution-text", MemberAuthentication(), DynamicResolution(PublicResolution(), LinearResolution()), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text, self.undo_text),
                Message(self, u"sequence-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=True, synchronization_direction=u"ASC", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text, self.undo_text),
                Message(self, u"full-sync-global-time-pruning-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=128, pruning=GlobalTimePruning(10, 20)), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text, self.undo_text),
                Message(self, u"high-priority-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=200), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"low-priority-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=100), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"medium-priority-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"ASC", priority=150), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                Message(self, u"RANDOM-text", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=False, synchronization_direction=u"RANDOM", priority=128), CommunityDestination(node_count=10), TextPayload(), self.check_text, self.on_text),
                ]

    def create_full_sync_text(self, text, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"full-sync-text")
        message = meta.impl(authentication=(self._my_member,),
                            distribution=(self.claim_global_time(),),
                            payload=(text,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    def create_full_sync_global_time_pruning_text(self, text, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"full-sync-global-time-pruning-text")
        message = meta.impl(authentication=(self._my_member,),
                            distribution=(self.claim_global_time(),),
                            payload=(text,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    #
    # double-signed-text
    #

    def create_double_signed_text(self, text, candidate, member, response_func, response_args=(), timeout=10.0, forward=True):
        assert isinstance(candidate, Candidate)
        meta = self.get_meta_message(u"double-signed-text")
        message = meta.impl(authentication=([self._my_member, member],),
                            distribution=(self.global_time,),
                            payload=(text,))
        return self.create_dispersy_signature_request(candidate, message, response_func, response_args, timeout, forward)

    def allow_double_signed_text(self, message):
        """
        Received a request to sign MESSAGE.

        Must return either: a. the same message, b. a modified version of message, or c. None.
        """
        logger.debug("%s \"%s\"", message, message.payload.text)
        assert message.payload.text in ("Allow=True", "Allow=False")
        if message.payload.text == "Allow=True":
            return message

    #
    # last-1-doublemember-text
    #
    def allow_signature_func(self, message):
        return True

    #
    # protected-full-sync-text
    #
    def create_protected_full_sync_text(self, text, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"protected-full-sync-text")
        message = meta.impl(authentication=(self._my_member,),
                            distribution=(self.claim_global_time(),),
                            payload=(text,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    #
    # dynamic-resolution-text
    #
    def create_dynamic_resolution_text(self, text, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"dynamic-resolution-text")
        message = meta.impl(authentication=(self._my_member,),
                            distribution=(self.claim_global_time(),),
                            payload=(text,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    #
    # sequence-text
    #
    def create_sequence_text(self, text, store=True, update=True, forward=True):
        meta = self.get_meta_message(u"sequence-text")
        message = meta.impl(authentication=(self._my_member,),
                            distribution=(self.claim_global_time(), meta.distribution.claim_sequence_number()),
                            payload=(text,))
        self._dispersy.store_update_forward([message], store, update, forward)
        return message

    #
    # any text-payload
    #

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
        for message in messages:
            if not "Dprint=False" in message.payload.text:
                logger.debug("%s \"%s\" @%d", message, message.payload.text, message.distribution.global_time)

        if messages[0].distribution.enable_sequence_number:
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
