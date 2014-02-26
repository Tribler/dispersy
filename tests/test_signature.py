from time import sleep
from unittest.case import skip

from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc
from ..logger import get_logger
logger = get_logger(__name__)

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
        invalid_packet = packet[:-node.my_member.signature_length] + '0' * node.my_member.signature_length
        self.assertNotEqual(packet, invalid_packet)

        # give invalid message to OTHER
        other.give_packet(invalid_packet, node)

        self.assertEqual(other.fetch_messages([u"full-sync-text", ]), [])

class TestDoubleSign(DispersyTestFunc):

    def test_no_response_from_node(self):
        """
        OTHER will request a signature from NODE. NODE will ignore this request and SELF should get
        a timeout on the signature request after a few seconds.
        """
        container = {"timeout": 0}

        node, other = self.create_nodes(2)
        other.send_identity(node)

        def on_response(request, response, modified):
            self.assertIsNone(response)
            container["timeout"] += 1
            return False, False, False

        message = other.create_double_signed_text(node.my_pub_member, "Allow=True", False)
        other.call(other._community.create_signature_request, node.my_candidate, message, on_response, timeout=1.0)

        sleep(1.5)

        self.assertEqual(container["timeout"], 1)

    @skip('TODO: emilon')
    def test_response_from_node(self):
        """
        OTHER will request a signature from NODE. OTHER will receive the signature and produce a
        double signed message.
        """
        container = {"response": 0}

        node, other = self.create_nodes(2)
        other.send_identity(node)

        def on_response(request, response, modified):
            self.assertEqual(container["response"], 0)
            self.assertTrue(response.authentication.is_signed)
            self.assertFalse(modified)
            container["response"] += 1
            return False

        message = other.create_double_signed_text(node.my_pub_member, "Allow=True", False)
        other.call(other._community.create_signature_request, node.my_candidate, message, on_response, timeout=1.0)

        _, message = node.receive_message(names=[u"dispersy-signature-request"]).next()
        submsg = message.payload.message

        second_signature_offset = len(submsg.packet) - other.my_member.signature_length
        self.assertEqual(submsg.packet[second_signature_offset:], "\x00" * node.my_member.signature_length, "The first signature MUST BE \x00's.  The creator must hold control over the community+member+global_time triplet")

        # message sent by other is ok, give it to node to process it
        node.give_message(message, other)
        other.process_packets()

        sleep(1.5)

        self.assertEqual(container["response"], 1)
