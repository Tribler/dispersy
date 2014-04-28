from struct import pack, unpack_from
from random import choice, sample
from binascii import hexlify, unhexlify

from ..message import DropPacket
from ..conversion import BinaryConversion
from ..bloomfilter import BloomFilter
from ..candidate import BootstrapCandidate


def bytes_to_long(val, nrbytes=0):
    if nrbytes < 0 and (val[0] == "-" or val[0] == "+"):
        _val = long(hexlify(val[1:][::-1]), 16)
        if val[0] == "-":
            return -_val
        return _val
    else:
        return long(hexlify(val[::-1]), 16)


class DiscoveryConversion(BinaryConversion):
    def __init__(self, community):
        super(DiscoveryConversion, self).__init__(community, "\x01")
        # we need to use 4 , 5, and 6 as we are combining this overlay with the searchcommunity which has 1,2,and 3 defined.
        self.define_meta_message(chr(1), community.get_meta_message(u"similarity-request"), lambda message: self._encode_decode(self._encode_similarity_request, self._decode_similarity_request, message), self._decode_similarity_request)
        self.define_meta_message(chr(2), community.get_meta_message(u"similarity-response"), lambda message: self._encode_decode(self._encode_similarity_response, self._decode_similarity_response, message), self._decode_similarity_response)
        self.define_meta_message(chr(3), community.get_meta_message(u"ping"), lambda message: self._encode_decode(self._encode_ping, self._decode_ping, message), self._decode_ping)
        self.define_meta_message(chr(4), community.get_meta_message(u"pong"), lambda message: self._encode_decode(self._encode_pong, self._decode_pong, message), self._decode_pong)

    def _encode_similarity_request(self, message):
        preference_list = message.payload.preference_list
        fmt = "!H" + "20s"*len(preference_list)
        packet = pack(fmt, message.payload.identifier, *preference_list)
        return packet,

    def _decode_similarity_request(self, placeholder, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        identifier, = unpack_from('!H', data, offset)
        offset += 2

        length = len(data) - offset
        if length % 20 != 0:
            raise DropPacket("Invalid number of bytes available")

        preference_list = []
        if length:
            hashpack = '20s' * (length / 20)
            preference_list = unpack_from('!' + hashpack, data, offset)
        offset += length

        return offset, placeholder.meta.payload.implement(identifier, preference_list)

    def _encode_similarity_response(self, message):
        preference_list = message.payload.preference_list
        tb_overlap = message.payload.tb_overlap
        fmt = "!H" + "20s"*len(preference_list) + "20sI"*len(tb_overlap)
        args = preference_list + sum([list(t) for t in tb_overlap], [])
        packet = pack(fmt, message.payload.identifier, *(args))
        return packet,

    def _decode_similarity_response(self, placeholder, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        identifier, = unpack_from('!H', data, offset)
        offset += 2

        length = len(data) - offset
        if length % 4 != 0:
            raise DropPacket("Invalid number of bytes available")

        preference_list = []
        if length:
            hashpack = '20s' * (length / 20)
            preference_list = unpack_from('!' + hashpack, data, offset)
        offset += length

        tb_overlap = []
        if length:
            hashpack = '20sI' * (length / 24)
            tb_overlap = unpack_from('!' + hashpack, data, offset)
        offset += length

        return offset, placeholder.meta.payload.implement(identifier, preference_list, tb_overlap)

    def _encode_ping(self, message):
        return pack('!H', message.payload.identifier),

    def _decode_ping(self, placeholder, offset, data):
        if len(data) < offset + 2:
            raise DropPacket("Insufficient packet size")

        identifier, = unpack_from('!H', data, offset)
        offset += 2

        return offset, placeholder.meta.payload.implement(identifier)

    def _encode_pong(self, message):
        return self._encode_ping(message)
    def _decode_pong(self, placeholder, offset, data):
        return self._decode_ping(placeholder, offset, data)

    def _encode_introduction_request(self, message):
        data = BinaryConversion._encode_introduction_request(self, message)

        if not isinstance(message.destination.candidates[0], BootstrapCandidate):
            if message.payload.introduce_me_to:
                data.insert(0, pack('!c20s', 'Y', message.payload.introduce_me_to))
        return data

    def _decode_introduction_request(self, placeholder, offset, data):
        has_introduce_me, = unpack_from('!c', data, offset)
        if has_introduce_me == 'Y':
            # we assume that it contains an introduce_me, doesn't have to be true
            offset += 1
            candidate_mid, = unpack_from('!20s', data, offset)
            offset += 20

            try:
                # no exception, hence a valid mid
                offset, payload = BinaryConversion._decode_introduction_request(self, placeholder, offset, data)
                payload.set_introduce_me_to(candidate_mid)
                return offset, payload

            except DropPacket:
                # could not decode, reset offset parse as normal introduction request
                offset -= 21

        return BinaryConversion._decode_introduction_request(self, placeholder, offset, data)

    def _encode_decode(self, encode, decode, message):
        result = encode(message)
        try:
            decode(None, 0, result[0])

        except DropPacket:
            from traceback import print_exc
            print_exc()
            raise
        except:
            pass
        return result
