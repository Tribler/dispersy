from struct import pack, unpack_from
from socket import inet_ntoa, inet_aton

from ..message import DropPacket
from ..conversion import BinaryConversion


class DiscoveryConversion(BinaryConversion):
    def __init__(self, community):
        super(DiscoveryConversion, self).__init__(community, "\x02")
        self.define_meta_message(chr(1), community.get_meta_message(u"similarity-request"), self._encode_similarity_request, self._decode_similarity_request)
        self.define_meta_message(chr(2), community.get_meta_message(u"similarity-response"), self._encode_similarity_response, self._decode_similarity_response)
        self.define_meta_message(chr(3), community.get_meta_message(u"ping"), self._encode_ping, self._decode_ping)
        self.define_meta_message(chr(4), community.get_meta_message(u"pong"), self._encode_pong, self._decode_pong)

    def _encode_similarity_request(self, message):
        preference_list = message.payload.preference_list
        peer_info = [inet_aton(message.payload.lan_address[0]), message.payload.lan_address[1],
                     inet_aton(message.payload.wan_address[0]), message.payload.wan_address[1],
                     self._encode_connection_type_map[message.payload.connection_type]]
        fmt = "!H4sH4sHB" + "20s"*len(preference_list)
        packet = pack(fmt, message.payload.identifier, *(peer_info + preference_list))
        return packet,

    def _decode_similarity_request(self, placeholder, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        identifier, = unpack_from('!H', data, offset)
        offset += 2
        lan_ip, lan_port = unpack_from('!4sH', data, offset)
        lan_address = (inet_ntoa(lan_ip), lan_port)
        offset += 6
        wan_ip, wan_port = unpack_from('!4sH', data, offset)
        wan_address = (inet_ntoa(wan_ip), wan_port)
        offset += 6
        connection_type = self._decode_connection_type_map[unpack_from('!B', data, offset)[0]]
        offset += 1

        length = len(data) - offset
        if length % 20 != 0:
            raise DropPacket("Invalid number of bytes available")

        preference_list = []
        if length:
            hashpack = '20s' * (length / 20)
            preference_list = unpack_from('!' + hashpack, data, offset)
        offset += length

        return offset, placeholder.meta.payload.implement(identifier, lan_address, wan_address, connection_type, preference_list)

    def _encode_similarity_response(self, message):
        preference_list = message.payload.preference_list
        tb_overlap = message.payload.tb_overlap
        fmt = "!HH" + "20s"*len(preference_list) + "20sI"*len(tb_overlap)
        args = preference_list + sum([list(t) for t in tb_overlap], [])
        packet = pack(fmt, message.payload.identifier, len(preference_list), *(args))
        return packet,

    def _decode_similarity_response(self, placeholder, offset, data):
        if len(data) < offset + 1:
            raise DropPacket("Insufficient packet size")

        identifier, num_preferences = unpack_from('!HH', data, offset)
        offset += 4

        length = len(data) - offset
        if (length - (num_preferences * 20)) % 24 != 0:
            raise DropPacket("Invalid number of bytes available")

        preference_list = []
        if length:
            hashpack = '20s' * num_preferences
            preference_list = unpack_from('!' + hashpack, data, offset)
        offset += num_preferences * 20

        length = len(data) - offset
        tb_overlap = []
        if length:
            hashpack = '20sI' * (length / 24)
            tb_overlap = unpack_from('!' + hashpack, data, offset)
            tb_overlap = zip(tb_overlap[0::2], tb_overlap[1::2])
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
