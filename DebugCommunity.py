from struct import pack, unpack_from

from Authentication import MultiMemberAuthentication, MemberAuthentication
from Community import Community
from Conversion import DictionaryConversion, BinaryConversion
from Debug import Node
from Destination import MemberDestination, CommunityDestination, SimilarityDestination
from Distribution import DirectDistribution, FullSyncDistribution, LastSyncDistribution
from Message import Message, DropPacket
from Member import MyMember
from Payload import Permit
from Resolution import PublicResolution

if __debug__:
    from Print import dprint

#
# Node
#

class DebugNode(Node):
    def create_last_1_test_message(self, text, global_time):
        meta = self._community.get_meta_message(u"last-1-test")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(),
                              meta.payload.implement(text))

    def create_last_9_test_message(self, text, global_time):
        meta = self._community.get_meta_message(u"last-9-test")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time),
                              meta.destination.implement(),
                              meta.payload.implement(text))

    def create_taste_aware_message(self, number, global_time, sequence_number):
        assert isinstance(number, (int, long))
        meta = self._community.get_meta_message(u"taste-aware-record")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time, sequence_number),
                              meta.destination.implement(),
                              meta.payload.implement(number))

    def create_taste_aware_message_last(self, number, global_time, sequence_number):
        assert isinstance(number, (int, long))
        meta = self._community.get_meta_message(u"taste-aware-record-last")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(global_time, sequence_number),
                              meta.destination.implement(),
                              meta.payload.implement(number))

#
# Conversion
#

class DebugCommunityConversion(BinaryConversion):
    def __init__(self, community):
        super(DebugCommunityConversion, self).__init__(community, "\x00\x02")
        self.define_meta_message(chr(1), community.get_meta_message(u"last-1-test"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(2), community.get_meta_message(u"last-9-test"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(3), community.get_meta_message(u"double-signed-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(4), community.get_meta_message(u"triple-signed-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(5), community.get_meta_message(u"taste-aware-record"), self._encode_taste_aware_record, self._decode_taste_aware_record)
        self.define_meta_message(chr(6), community.get_meta_message(u"taste-aware-record-last"), self._encode_taste_aware_record, self._decode_taste_aware_record)

    def _encode_text(self, message):
        return pack("!B", len(message.payload.text)), message.payload.text

    def _decode_text(self, meta_message, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        text_length, = unpack_from("!B", data, offset)
        offset += 1

        if len(data) < offset + text_length:
            raise DropPacket("Insufficient packet size")

        text = data[offset:offset+text_length]
        offset += text_length

        return offset, meta_message.payload.implement(text)

    def _encode_taste_aware_record(self, message):
        return pack("!L", message.payload.number),

    def _decode_taste_aware_record(self, meta_message, offset, data):
        if len(data) < offset + 4:
            raise DropPacket("Insufficient packet size")

        number, = unpack_from("!L", data, offset)
        offset += 8

        return offset, meta_message.payload.implement(number)

#
# Payload
#

class TextPayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, text):
            assert isinstance(text, str)
            super(TextPayload.Implementation, self).__init__(meta)
            self._text = text

        @property
        def text(self):
            return self._text

class Last1TestPayload(TextPayload):
    pass

class Last9TestPayload(TextPayload):
    pass

class DoubleSignedTextPayload(TextPayload):
    pass

class TripleSignedTextPayload(TextPayload):
    pass

class TasteAwarePayload(Permit):
    class Implementation(Permit.Implementation):
        def __init__(self, meta, number):
            assert isinstance(number, (int, long))
            super(TasteAwarePayload.Implementation, self).__init__(meta)
            self._number = number

        @property
        def number(self):
            return self._number

#
# Community
#

class DebugCommunity(Community):
    """
    Community to debug Dispersy related messages and policies.
    """
    def get_meta_messages(self):
        return [Message(self, u"last-1-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(enable_sequence_number=True, cluster=1, history_size=1), CommunityDestination(), Last1TestPayload()),
                Message(self, u"last-9-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(enable_sequence_number=True, cluster=2, history_size=9), CommunityDestination(), Last9TestPayload()),
                Message(self, u"double-signed-text", MultiMemberAuthentication(count=2, allow_signature_func=self.allow_double_signed_text), PublicResolution(), DirectDistribution(), MemberDestination(), DoubleSignedTextPayload()),
                Message(self, u"triple-signed-text", MultiMemberAuthentication(count=3, allow_signature_func=self.allow_triple_signed_text), PublicResolution(), DirectDistribution(), MemberDestination(), TripleSignedTextPayload()),
                Message(self, u"taste-aware-record", MemberAuthentication(), PublicResolution(), FullSyncDistribution(enable_sequence_number=True), SimilarityDestination(cluster=1, size=16, minimum_bits=6, maximum_bits=10, threshold=12), TasteAwarePayload()),
                Message(self, u"taste-aware-record-last", MemberAuthentication(), PublicResolution(), LastSyncDistribution(enable_sequence_number=True, cluster=3, history_size=1), SimilarityDestination(cluster=2, size=16, minimum_bits=6, maximum_bits=10, threshold=12), TasteAwarePayload())]

    def __init__(self, cid):
        super(DebugCommunity, self).__init__(cid)

        # containers
        self._received_last_1_test = []
        self._received_last_9_test = []

        # mapping
        self._incoming_message_map = {u"last-1-test":self.on_last_1_test,
                                      u"last-9-test":self.on_last_9_test,
                                      u"double-signed-text":self.on_double_signed_text,
                                      u"triple-signed-text":self.on_triple_signed_text,
                                      u"taste-aware-record":self.on_taste_aware_record,
                                      u"taste-aware-record-last":self.on_taste_aware_record}

        # add the Dispersy message handlers to the
        # _incoming_message_map
        for message, handler in self._dispersy.get_message_handlers(self):
            assert message.name not in self._incoming_message_map
            self._incoming_message_map[message.name] = handler

        # available conversions
        self.add_conversion(DebugCommunityConversion(self), True)

    def on_message(self, address, message):
        if self._timeline.check(message):
            self._incoming_message_map[message.name](address, message)
        else:
            raise DelayMessageByProof()

    #
    # last-1-test
    #

    def get_received_last_1_test(self, address=None):
        if address:
            return [(address, message) for address, message in self._received_last_1_test if address == address]
        else:
            return self._received_last_1_test

    def on_last_1_test(self, address, message):
        self._received_last_1_test.append((address, message))

    #
    # last-9-test
    #

    def get_received_last_9_test(self, address=None):
        if address:
            return [(address, message) for address, message in self._received_last_9_test if address == address]
        else:
            return self._received_last_9_test

    def on_last_9_test(self, address, message):
        self._received_last_9_test.append((address, message))

    #
    # double-signed-text
    #

    def create_double_signed_text(self, text, member, response_func, timeout=10.0, store_and_forward=True):
        meta = self.get_meta_message(u"double-signed-text")
        message = meta.implement(meta.authentication.implement((self._my_member, member)),
                                 meta.distribution.implement(self._timeline.global_time),
                                 meta.destination.implement(member),
                                 meta.payload.implement(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def create_taste_aware_record(self, number, sequence_number):
        meta = self.get_meta_message(u"taste-aware-record")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(self._timeline.global_time, sequence_number),
                              meta.destination.implement(),
                              meta.payload.implement(number))

    def create_taste_aware_record_last(self, number, sequence_number):
        meta = self.get_meta_message(u"taste-aware-record-last")
        return meta.implement(meta.authentication.implement(self._my_member),
                              meta.distribution.implement(self._timeline.global_time, sequence_number),
                              meta.destination.implement(),
                              meta.payload.implement(number))

    def allow_double_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        assert message.payload.text in ("Allow=True", "Allow=False")
        return message.payload.text == "Allow=True"

    def on_double_signed_text(self, address, message):
        """
        Received a double signed message.
        """
        dprint(message)

    #
    # triple-signed-text
    #

    def create_triple_signed_text(self, text, member1, member2, response_func, timeout=10.0, store_and_forward=True):
        meta = self.get_meta_message(u"triple-signed-text")
        message = meta.implement(meta.authentication.implement((self._my_member, member1, member2)),
                                 meta.distribution.implement(self._timeline.global_time),
                                 meta.destination.implement(member1, member2),
                                 meta.payload.implement(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def allow_triple_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        assert message.payload.text in ("Allow=True", "Allow=False")
        return message.payload.text == "Allow=True"

    def on_triple_signed_text(self, address, message):
        """
        Received a triple signed message.
        """
        dprint(message)

    def on_taste_aware_record(self, address, message):
        """
        Received a taste aware record.
        """
        dprint(message.payload.number)

