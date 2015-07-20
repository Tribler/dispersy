from time import sleep

from .dispersytestclass import DispersyTestFunc


class TestSignature(DispersyTestFunc):

    def test_invalid_public_key(self):
        """
        NODE sends a message containing an invalid public-key to OTHER.
        OTHER should drop it
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        message = node.create_bin_key_text('Should drop')
        packet = node.encode_message(message)

        # replace the valid public-key with an invalid one
        public_key = node.my_member.public_key
        self.assertIn(public_key, packet)

        invalid_packet = packet.replace(public_key, "I" * len(public_key))
        self.assertNotEqual(packet, invalid_packet)

        # give invalid message to OTHER
        other.give_packet(invalid_packet, node)

        self.assertEqual(other.fetch_messages([u"bin-key-text", ]), [])

    def test_invalid_signature(self):
        """
        NODE sends a message containing an invalid signature to OTHER.
        OTHER should drop it
        """
        node, other = self.create_nodes(2)
        other.send_identity(node)

        message = node.create_full_sync_text('Should drop')
        packet = node.encode_message(message)

        # replace the valid signature with an invalid one
        invalid_packet = packet[:-node.my_member.signature_length] + 'I' * node.my_member.signature_length
        self.assertNotEqual(packet, invalid_packet)

        # give invalid message to OTHER
        other.give_packet(invalid_packet, node)

        self.assertEqual(other.fetch_messages([u"full-sync-text", ]), [])
