from struct import pack, unpack_from
from random import choice, sample

from Tribler.Core.Utilities.encoding import encode, decode
from Tribler.dispersy.message import DropPacket
from Tribler.dispersy.conversion import BinaryConversion
from Tribler.dispersy.bloomfilter import BloomFilter

from binascii import hexlify, unhexlify
from Tribler.dispersy.candidate import BootstrapCandidate
def long_to_bytes(val, nrbytes=0):
    hex_val = '%x' % abs(val)
    if nrbytes:
        padding = '0' * ((abs(nrbytes) * 2) - len(hex_val))
    else:
        padding = ''
    result = unhexlify(padding + hex_val)[::-1]

    if nrbytes < 0:
        return ("-" if val < 0 else "+") + result
    return result

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
        super(ForwardConversion, self).__init__(community, "\x02")
        # we need to use 4 , 5, and 6 as we are combining this overlay with the searchcommunity which has 1,2,and 3 defined.
        self.define_meta_message(chr(4), community.get_meta_message(u"similarity-reveal"), lambda message: self._encode_decode(self._encode_simi_reveal, self._decode_simi_reveal, message), self._decode_simi_reveal)
        self.define_meta_message(chr(5), community.get_meta_message(u"ping"), lambda message: self._encode_decode(self._encode_ping, self._decode_ping, message), self._decode_ping)
        self.define_meta_message(chr(6), community.get_meta_message(u"pong"), lambda message: self._encode_decode(self._encode_pong, self._decode_pong, message), self._decode_pong)

    def _encode_simi_reveal(self, message):
        if isinstance(message.payload.overlap, int):
            return pack('!ci', 'I', message.payload.overlap),

        # convert long into string
        str_overlap = [long_to_bytes(overlap, 20) for overlap in message.payload.overlap]
        return pack('!c' + '20s' * len(message.payload.overlap), 'L', *str_overlap),

    def _decode_simi_reveal(self, placeholder, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        identifier, = unpack_from('!c', data, offset)
        offset += 1

        if identifier == 'I':
            overlap, = unpack_from('!i', data, offset)
            offset += 4
        else:
            length = len(data) - offset
            if length % 20 != 0:
                raise DropPacket("Invalid number of bytes available (sr)")

            if length:
                hashpack = '20s' * (length / 20)
                str_overlap = unpack_from('!' + hashpack, data, offset)
                overlap = [bytes_to_long(str_over) for str_over in str_overlap]
            else:
                overlap = []

            offset += length
        return offset, placeholder.meta.payload.implement(overlap)

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
            raise
        except:
            pass
        return result
