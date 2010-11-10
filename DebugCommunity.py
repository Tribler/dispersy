from struct import pack, unpack_from

from Message import Message
from Authentication import MultiMemberAuthentication
from Resolution import PublicResolution
from Conversion import DictionaryConversion, BinaryConversion
from Community import Community
from Payload import Permit
from Distribution import DirectDistribution
from Destination import MemberDestination

#
# Conversion
#

class DebugCommunityConversion(BinaryConversion):
    def __init__(self, community):
        super(DebugCommunityConversion, self).__init__(community, "\x00\x02")
        self.define_meta_message(chr(1), community.get_meta_message(u"double-signed-text"), self._encode_double_signed_text, self._decode_double_signed_text)
        self.define_meta_message(chr(2), community.get_meta_message(u"triple-signed-text"), self._encode_triple_signed_text, self._decode_triple_signed_text)

    def _encode_double_signed_text(self, message):
        return pack("!B", len(message.payload.text)), message.payload.text

    def _decode_double_signed_text(self, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        text_length, = unpack_from("!B", data, offset)
        offset += 1

        if len(data) < offset + text_length:
            raise DropPacket("Insufficient packet size")

        text = data[offset:offset+text_length]
        offset += text_length

        return offset, DoubleSignedTextPayload(text)

    def _encode_triple_signed_text(self, message):
        return pack("!B", len(message.payload.text)), message.payload.text

    def _decode_triple_signed_text(self, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        text_length, = unpack_from("!B", data, offset)
        offset += 1

        if len(data) < offset + text_length:
            raise DropPacket("Insufficient packet size")

        text = data[offset:offset+text_length]
        offset += text_length

        return offset, TripleSignedTextPayload(text)

#
# Payload
#

class DoubleSignedTextPayload(Permit):
    def __init__(self, text):
        assert isinstance(text, str)
        self._text = text

    @property
    def text(self):
        return self._text

class TripleSignedTextPayload(Permit):
    def __init__(self, text):
        assert isinstance(text, str)
        self._text = text

    @property
    def text(self):
        return self._text

#
# Community
#

class DebugCommunity(Community):
    """
    Community to debug Dispersy related messages and policies.
    """
    def get_meta_messages(self):
        return [Message(self, u"double-signed-text", MultiMemberAuthentication(2, self.allow_double_signed_text), PublicResolution(), DirectDistribution(), MemberDestination()),
                Message(self, u"triple-signed-text", MultiMemberAuthentication(3, self.allow_triple_signed_text), PublicResolution(), DirectDistribution(), MemberDestination())]

    def __init__(self, cid):
        super(DebugCommunity, self).__init__(cid)

        # mapping
        self._incoming_message_map = {u"double-signed-text":self.on_double_signed_text,
                                      u"triple-signed-text":self.on_triple_signed_text}

        # add the Dispersy message handlers to the
        # _incoming_message_map
        for message, handler in self._dispersy.get_message_handlers(self):
            assert message.name not in self._incoming_message_map
            self._incoming_message_map[message.name] = handler

        # available conversions
        self.add_conversion(DebugCommunityConversion(self), True)

    def create_double_signed_text(self, text, member, response_func, timeout=10.0, store_and_forward=True):
        meta = self.get_meta_message(u"double-signed-text")
        message = meta.implement(meta.authentication.implement((self._my_member, member)),
                                 meta.distribution.implement(self._timeline.global_time),
                                 meta.destination.implement(member),
                                 DoubleSignedTextPayload(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def create_triple_signed_text(self, text, member1, member2, response_func, timeout=10.0, store_and_forward=True):
        meta = self.get_meta_message(u"triple-signed-text")
        message = meta.implement(meta.authentication.implement((self._my_member, member1, member2)),
                                 meta.distribution.implement(self._timeline.global_time),
                                 meta.destination.implement(member1, member2),
                                 TripleSignedTextPayload(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def allow_double_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        return False

    def allow_triple_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        return False

    def on_message(self, address, message):
        if self._timeline.check(message):
            self._incoming_message_map[message.name](address, message)
        else:
            raise DelayMessageByProof()

    def on_double_signed_text(self, address, message):
        """
        Received a double signed message.
        """
        dprint(message)

    def on_triple_signed_text(self, address, message):
        """
        Received a triple signed message.
        """
        dprint(message)
