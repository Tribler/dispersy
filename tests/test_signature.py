from ..logger import get_logger
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
from unittest.case import skip
logger = get_logger(__name__)


class TestSignature(DispersyTestFunc):

    @skip('TODO: emilon')
    @call_on_dispersy_thread
    def test_no_response_from_node(self):
        """
        OTHER will request a signature from NODE. NODE will ignore this request and SELF should get
        a timeout on the signature request after a few seconds.
        """
        container = {"timeout": 0}

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        def on_response(request, response, modified):
            self.assertIsNone(response)
            container["timeout"] += 1
            return False, False, False

        message = other.create_double_signed_text(node.my_member, "Accept=<does not reach this point>", 1, False)
        self._community.create_signature_request(node.my_candidate, message, on_response, timeout=1.0)

        yield 1.11

        self.assertEqual(container["timeout"], 1)

    @skip('TODO: emilon')
    @call_on_dispersy_thread
    def test_response_from_node(self):
        """
        OTHER will request a signature from NODE. OTHER will receive the signature and produce a
        double signed message.
        """
        container = {"response": 0}

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        def on_response(request, response, modified):
            self.assertEqual(container["response"], 0)
            self.assertTrue(response.authentication.is_signed)
            self.assertFalse(modified)
            container["response"] += 1
            return False

        message = other.create_double_signed_text(node.my_member, "Accept=<does not matter>", 1, False)
        self._community.create_signature_request(node.my_candidate, message, on_response, timeout=1.0)

        yield 0.11

        _, message = node.receive_message(names=[u"dispersy-signature-request"])
        submsg = message.payload.message

        second_signature_offset = len(submsg.packet) - other.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        self.assertEqual(submsg.packet[second_signature_offset:], "\x00" * node.my_member.signature_length, "The first signature MUST BE \x00's.  The creator must hold control over the community+member+global_time triplet")

        signature = node.my_member.sign(submsg.packet, length=first_signature_offset)
        submsg.authentication.set_signature(node.my_member, signature)

        other.give_message(node.create_dispersy_signature_response(message.payload.identifier, submsg, self._community.global_time), node)

        yield 0.11

        self.assertEqual(container["response"], 1)
