from struct import pack, unpack_from

from ...conversion import BinaryConversion
from ...message import DropPacket


class DebugCommunityConversion(BinaryConversion):

    """
    DebugCommunityConversion is used to convert messages to and from binary while performing unittests.
    """
    def __init__(self, community, version="\x01"):
        assert isinstance(version, str), type(version)
        assert len(version) == 1, len(version)
        super(DebugCommunityConversion, self).__init__(community, version)
        # we use higher message identifiers to reduce the chance that we clash with either Dispersy (255 and down) and
        # normal communities (1 and up).
        self.define_meta_message(chr(101), community.get_meta_message("last-1-test"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(102), community.get_meta_message("last-9-test"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(103), community.get_meta_message("double-signed-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(104), community.get_meta_message("double-signed-text-split"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(105), community.get_meta_message("full-sync-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(106), community.get_meta_message("n-hop-sync-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(107), community.get_meta_message("ASC-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(108), community.get_meta_message("DESC-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(109), community.get_meta_message("last-1-doublemember-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(110), community.get_meta_message("protected-full-sync-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(111), community.get_meta_message("dynamic-resolution-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(112), community.get_meta_message("sequence-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(113), community.get_meta_message("full-sync-global-time-pruning-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(114), community.get_meta_message("high-priority-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(115), community.get_meta_message("low-priority-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(116), community.get_meta_message("medium-priority-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(117), community.get_meta_message("RANDOM-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(118), community.get_meta_message("batched-text"), self._encode_text, self._decode_text)
        self.define_meta_message(chr(119), community.get_meta_message("bin-key-text"), self._encode_text, self._decode_text)

    def _encode_text(self, message):
        """
        Encode a text message.
        Returns one byte containing len(message.payload.text) followed by this text.
        """
        return message.payload.text,

    def _decode_text(self, placeholder, offset, data):
        """
        Decode a text message.
        Returns the new offset and a payload implementation.
        """
        text = data[offset:]
        offset += len(text)

        return offset, placeholder.meta.payload.implement(text)
