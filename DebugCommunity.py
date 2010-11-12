from struct import pack, unpack_from

from Authentication import MultiMemberAuthentication, MemberAuthentication
from Community import Community
from Conversion import DictionaryConversion, BinaryConversion
from Debug import Node
from Destination import MemberDestination, CommunityDestination
from Distribution import DirectDistribution, LastSyncDistribution
from Message import Message
from Payload import Permit
from Resolution import PublicResolution

#
# Node
#

class DebugNode(Node):
    def create_last_1_test_message(self, text, global_time):
        meta = self._community.get_meta_message(u"last-1-test")
        authentication = meta.authentication.implement(self._my_member)
        distribution = meta.distribution.implement(global_time)
        destination = meta.destination.implement()
        payload = Last1TestPayload(text)
        return meta.implement(authentication, distribution, destination, payload)

    def create_last_9_test_message(self, text, global_time):
        meta = self._community.get_meta_message(u"last-9-test")
        authentication = meta.authentication.implement(self._my_member)
        distribution = meta.distribution.implement(global_time)
        destination = meta.destination.implement()
        payload = Last9TestPayload(text)
        return meta.implement(authentication, distribution, destination, payload)

#
# Conversion
#

class DebugCommunityConversion(BinaryConversion):
    def __init__(self, community):
        super(DebugCommunityConversion, self).__init__(community, "\x00\x02")
        self.define_meta_message(chr(1), community.get_meta_message(u"last-1-test"), self._encode_text, lambda offset, data: self._decode_text(offset, data, Last1TestPayload))
        self.define_meta_message(chr(2), community.get_meta_message(u"last-9-test"), self._encode_text, lambda offset, data: self._decode_text(offset, data, Last9TestPayload))
        self.define_meta_message(chr(3), community.get_meta_message(u"double-signed-text"), self._encode_text, lambda offset, data: self._decode_text(offset, data, DoubleSignedTextPayload))
        self.define_meta_message(chr(4), community.get_meta_message(u"triple-signed-text"), self._encode_text, lambda offset, data: self._decode_text(offset, data, TripleSignedTextPayload))

    def _encode_text(self, message):
        return pack("!B", len(message.payload.text)), message.payload.text

    def _decode_text(self, offset, data, cls):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        text_length, = unpack_from("!B", data, offset)
        offset += 1

        if len(data) < offset + text_length:
            raise DropPacket("Insufficient packet size")

        text = data[offset:offset+text_length]
        offset += text_length

        return offset, cls(text)

#
# Payload
#

class TextPayload(Permit):
    def __init__(self, text):
        assert isinstance(text, str)
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

#
# Community
#

class DebugCommunity(Community):
    """
    Community to debug Dispersy related messages and policies.
    """
    def get_meta_messages(self):
        return [Message(self, u"last-1-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(1), CommunityDestination()),
                Message(self, u"last-9-test", MemberAuthentication(), PublicResolution(), LastSyncDistribution(9), CommunityDestination()),
                Message(self, u"double-signed-text", MultiMemberAuthentication(2, self.allow_double_signed_text), PublicResolution(), DirectDistribution(), MemberDestination()),
                Message(self, u"triple-signed-text", MultiMemberAuthentication(3, self.allow_triple_signed_text), PublicResolution(), DirectDistribution(), MemberDestination())]

    def __init__(self, cid):
        super(DebugCommunity, self).__init__(cid)

        # containers
        self._received_last_1_test = []
        self._received_last_9_test = []

        # mapping
        self._incoming_message_map = {u"last-1-test":self.on_last_1_test,
                                      u"last-9-test":self.on_last_9_test,
                                      u"double-signed-text":self.on_double_signed_text,
                                      u"triple-signed-text":self.on_triple_signed_text}

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
                                 DoubleSignedTextPayload(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def allow_double_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        return False

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
                                 TripleSignedTextPayload(text))
        return self.create_signature_request(message, response_func, timeout, store_and_forward)

    def allow_triple_signed_text(self, message):
        """
        Received a request to sign MESSAGE.
        """
        dprint(message)
        return False

    def on_triple_signed_text(self, address, message):
        """
        Received a triple signed message.
        """
        dprint(message)

