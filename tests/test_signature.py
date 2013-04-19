#!/usr/bin/env/python

import logging
logger = logging.getLogger(__name__)

from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode

from .dispersytestclass import DispersyTestClass, call_on_dispersy_thread

class TestSignature(DispersyTestClass):
    @call_on_dispersy_thread
    def test_double_signed_timeout(self):
        """
        SELF will request a signature from NODE.  Node will ignore this request and SELF should get
        a timeout on the signature request after a few seconds.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        container = {"timeout":0}

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        logger.debug("SELF requests NODE to double sign")
        def on_response(request, response, modified):
            self.assertIsNone(response)
            container["timeout"] += 1
            return False, False, False

        community.create_double_signed_text("Accept=<does not reach this point>", self._dispersy.get_member(node.my_member.public_key), on_response, (), 3.0)
        yield 0.11

        logger.debug("NODE receives dispersy-signature-request message")
        _, message = node.receive_message(message_names=[u"dispersy-signature-request"])
        # do not send a response

        # should timeout
        wait = 4
        for counter in range(wait):
            logger.debug("waiting... %d", wait-counter)
            yield 1.0
        yield 0.11

        logger.debug("SELF must have timed out by now")
        self.assertEqual(container["timeout"], 1)

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_double_signed_response(self):
        """
        SELF will request a signature from NODE.  SELF will receive the signature and produce a
        double signed message.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        container = {"response":0}

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        logger.debug("SELF requests NODE to double sign")
        def on_response(request, response, modified):
            self.assertEqual(container["response"], 0)
            self.assertTrue(response.authentication.is_signed)
            self.assertFalse(modified)
            container["response"] += 1
            return False
        community.create_double_signed_text("Accept=<does not matter>", self._dispersy.get_member(node.my_member.public_key), on_response, (), 3.0)
        yield 0.11

        logger.debug("NODE receives dispersy-signature-request message from SELF")
        candidate, message = node.receive_message(message_names=[u"dispersy-signature-request"])
        submsg = message.payload.message
        second_signature_offset = len(submsg.packet) - community.my_member.signature_length
        first_signature_offset = second_signature_offset - node.my_member.signature_length
        self.assertEqual(submsg.packet[second_signature_offset:], "\x00" * node.my_member.signature_length, "The first signature MUST BE \x00's.  The creator must hold control over the community+member+global_time triplet")
        signature = node.my_member.sign(submsg.packet, length=first_signature_offset)
        submsg.authentication.set_signature(node.my_member, signature)

        logger.debug("NODE sends dispersy-signature-response message to SELF")
        identifier = message.payload.identifier
        global_time = community.global_time
        node.give_message(node.create_dispersy_signature_response(identifier, submsg, global_time, candidate))
        yield 1.11
        self.assertEqual(container["response"], 1)

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
