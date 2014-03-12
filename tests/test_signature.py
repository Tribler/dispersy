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
        invalid_packet = packet[:-node.my_member.signature_length] + 'I' * node.my_member.signature_length
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

    def test_response_from_node(self):
        """
        NODE will request a signature from OTHER.
        NODE will receive the response signed by OTHER.
        """
        container = {"response": 0}

        node, other = self.create_nodes(2)
        other.send_identity(node)

        def on_response(request, response, modified):
            self.assertEqual(container["response"], 0)
            mid_signatures = dict([(member.mid, signature) for signature, member in response.authentication.signed_members])
            # It should be signed by OTHER
            self.assertNotEqual(mid_signatures[other.my_member.mid], '')
            # BUT it should not be signed by NODE yet
            self.assertEqual(mid_signatures[node.my_member.mid], '')
            # is_signed should be False, as it is not yet signed by both parties
            self.assertFalse(response.authentication.is_signed)
            self.assertFalse(modified)
            container["response"] += 1
            return False

        # NODE creates the unsigned request and sends it to OTHER
        message = node.create_double_signed_text(other.my_pub_member, "Allow=True", False)
        node.call(node._community.create_signature_request, other.my_candidate, message, on_response, timeout=1.0)

        # OTHER receives the request
        _, message = other.receive_message(names=[u"dispersy-signature-request"]).next()
        submsg = message.payload.message

        second_signature_offset = len(submsg.packet) - other.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        self.assertEqual(submsg.packet[first_signature_offset:second_signature_offset], "\x00" * node.my_member.signature_length, "The first signature MUST BE 0x00's.")
        self.assertEqual(submsg.packet[second_signature_offset:], "\x00" * other.my_member.signature_length, "The second signature MUST BE 0x00's.")

        # reply sent by OTHER is ok, give it to NODE to process it
        other.give_message(message, node)
        node.process_packets()

        sleep(1.5)

        self.assertEqual(container["response"], 1)
