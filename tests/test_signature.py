from time import sleep
from unittest.case import skip

from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc
from ..logger import get_logger
logger = get_logger(__name__)

class TestSignature(DispersyTestFunc):

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
