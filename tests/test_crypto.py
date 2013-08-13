import logging
logger = logging.getLogger(__name__)

from hashlib import sha1
from unittest import TestCase

from ..crypto import ec_get_curves, ec_generate_key, ec_sign, ec_verify, ec_signature_length, \
    ec_to_public_bin, ec_to_private_bin, ec_check_public_bin, ec_check_private_bin, \
    ec_from_public_bin, ec_from_private_bin, \
    ec_to_public_pem, ec_to_private_pem, ec_check_public_pem, ec_check_private_pem, \
    ec_from_public_pem, ec_from_private_pem
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread


class TestLowLevelCrypto(TestCase):

    def test_sign_and_verify(self):
        """
        Creates each curve, signs some data, and finally verifies the signature.
        """
        data = "".join(chr(i % 256) for i in xrange(1024))
        digest = sha1(data).digest()

        for curve in ec_get_curves():
            ec = ec_generate_key(curve)
            signature = ec_sign(ec, digest)
            self.assertEqual(len(signature), ec_signature_length(ec))
            self.assertTrue(ec_verify(ec, digest, signature))

            self.assertFalse(ec_verify(ec, digest, "-" * ec_signature_length(ec)))
            self.assertFalse(ec_verify(ec, "---", signature))

            for i in xrange(len(signature)):
                # invert one bit in the ith character of the signature
                invalid_signature = list(signature)
                invalid_signature[i] = chr(ord(invalid_signature[i]) ^ 1)
                invalid_signature = "".join(invalid_signature)
                self.assertNotEqual(signature, invalid_signature)
                self.assertFalse(ec_verify(ec, digest, invalid_signature))

    def test_serialise_binary(self):
        """
        Creates and serialises each curve.
        """
        data = "".join(chr(i % 256) for i in xrange(1024))
        digest = sha1(data).digest()

        for curve in ec_get_curves():
            ec = ec_generate_key(curve)
            signature = ec_sign(ec, digest)
            self.assertEqual(len(signature), ec_signature_length(ec))
            self.assertTrue(ec_verify(ec, digest, signature))

            #
            # serialise using BIN
            #

            public = ec_to_public_bin(ec)
            self.assertTrue(ec_check_public_bin(public))
            self.assertEqual(public, ec_to_public_bin(ec))
            private = ec_to_private_bin(ec)
            self.assertTrue(ec_check_private_bin(private))
            self.assertEqual(private, ec_to_private_bin(ec))

            ec_clone = ec_from_public_bin(public)
            self.assertTrue(ec_verify(ec_clone, digest, signature))
            ec_clone = ec_from_private_bin(private)
            self.assertTrue(ec_verify(ec_clone, digest, signature))

            #
            # serialise using PEM
            #

            public = ec_to_public_pem(ec)
            self.assertTrue(ec_check_public_pem(public))
            self.assertEqual(public, ec_to_public_pem(ec))
            private = ec_to_private_pem(ec)
            self.assertTrue(ec_check_private_pem(private))
            self.assertEqual(private, ec_to_private_pem(ec))

            ec_clone = ec_from_public_pem(public)
            self.assertTrue(ec_verify(ec_clone, digest, signature))
            ec_clone = ec_from_private_pem(private)
            self.assertTrue(ec_verify(ec_clone, digest, signature))

class TestCrypto(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_invalid_public_key(self):
        """
        SELF receives a dispersy-identity message containing an invalid public-key.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member(candidate=False, identity=False)

        # create dispersy-identity message
        global_time = 10
        message = node.create_dispersy_identity(global_time)

        # replace the valid public-key with an invalid one
        public_key = node.my_member.public_key
        self.assertIn(public_key, message.packet)
        invalid_packet = message.packet.replace(public_key, "I" * len(public_key))
        self.assertNotEqual(message.packet, invalid_packet)

        # give invalid message to SELF
        node.give_packet(invalid_packet)

        # ensure that the message was not stored in the database
        ids = list(self._dispersy.database.execute(u"SELECT id FROM sync WHERE community = ? AND packet = ?",
                                                   (community.database_id, buffer(invalid_packet))))
        self.assertEqual(ids, [])

        # cleanup
        community.create_dispersy_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
