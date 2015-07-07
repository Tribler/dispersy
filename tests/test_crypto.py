from unittest import TestCase

from ..crypto import ECCrypto


class TestLowLevelCrypto(TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestLowLevelCrypto, cls).setUpClass()
        cls.crypto = ECCrypto()

    def test_sign_and_verify(self):
        """
        Creates each curve, signs some data, and finally verifies the signature.
        """
        data = "".join(chr(i % 256) for i in xrange(1024))
        for curve in self.crypto.security_levels:
            ec = self.crypto.generate_key(curve)
            signature = self.crypto.create_signature(ec, data)
            self.assertEqual(len(signature), self.crypto.get_signature_length(ec))
            self.assertTrue(self.crypto.is_valid_signature(ec, data, signature))

            self.assertFalse(self.crypto.is_valid_signature(ec, data, "-" * self.crypto.get_signature_length(ec)))
            self.assertFalse(self.crypto.is_valid_signature(ec, "---", signature))

            for i in xrange(len(signature)):
                # invert one bit in the ith character of the signature
                invalid_signature = list(signature)
                invalid_signature[i] = chr(ord(invalid_signature[i]) ^ 1)
                invalid_signature = "".join(invalid_signature)
                self.assertNotEqual(signature, invalid_signature)
                self.assertFalse(self.crypto.is_valid_signature(ec, data, invalid_signature))

    def test_serialise_binary(self):
        """
        Creates and serialises each curve.
        """
        data = "".join(chr(i % 256) for i in xrange(1024))
        for curve in self.crypto.security_levels:
            ec = self.crypto.generate_key(curve)
            ec_pub = ec.pub()

            signature = self.crypto.create_signature(ec, data)
            self.assertEqual(len(signature), self.crypto.get_signature_length(ec))
            self.assertTrue(self.crypto.is_valid_signature(ec, data, signature))

            public = self.crypto.key_to_bin(ec_pub)
            self.assertTrue(self.crypto.is_valid_public_bin(public), public)
            self.assertEqual(public, self.crypto.key_to_bin(ec_pub))

            private = self.crypto.key_to_bin(ec)
            self.assertTrue(self.crypto.is_valid_private_bin(private), private)
            self.assertEqual(private, self.crypto.key_to_bin(ec))

            ec_clone = self.crypto.key_from_public_bin(public)
            self.assertTrue(self.crypto.is_valid_signature(ec_clone, data, signature))
            ec_clone = self.crypto.key_from_private_bin(private)
            self.assertTrue(self.crypto.is_valid_signature(ec_clone, data, signature))

    def test_performance(self):
        from time import time
        import sys
        import os

        ec = self.crypto.generate_key(u"very-low")

        data = [os.urandom(1024) for i in xrange(1000)]
        for curve in [u"very-low", u"low", u"medium", u"high", u"curve25519"]:
            t1 = time()
            ec = self.crypto.generate_key(curve)
            t2 = time()
            signatures = [self.crypto.create_signature(ec, msg) for msg in data]
            t3 = time()
            verfified = [self.crypto.is_valid_signature(ec, msg, signature) for msg, signature in zip(data, signatures)]
            # print >> sys.stderr, curve, "verify", time() - t3, "sign", t3 - t2, "genkey", t2 - t1

            assert all(verfified)
