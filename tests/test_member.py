from .dispersytestclass import DispersyTestFunc
from ..util import call_on_reactor_thread


class TestMember(DispersyTestFunc):

    def test_verify(self):
        self._test_verify(u"medium")
        self._test_verify(u"curve25519")

    @call_on_reactor_thread
    def _test_verify(self, curve):
        """
        Test test member.verify assuming create_signature works properly.
        """
        ec = self._dispersy.crypto.generate_key(curve)
        member = self._dispersy.get_member(private_key=self._dispersy.crypto.key_to_bin(ec))

        # sign and verify "0123456789"[0:10]
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789")))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=0))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=0))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=9))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=9))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=10))
        self.assertTrue(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=10))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=11))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=11))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=666))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "0123456789"), offset=0, length=666))

        # sign and verify "0123456789"[1:10]
        self.assertTrue(member.verify("123456789", self._dispersy.crypto.create_signature(ec, "123456789")))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=0))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=0))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=8))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=8))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=9))
        self.assertTrue(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=9))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=10))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=10))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=666))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "123456789"), offset=1, length=666))

        # sign and verify "0123456789"[0:9]
        self.assertTrue(member.verify("012345678", self._dispersy.crypto.create_signature(ec, "012345678")))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=0))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=0))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=8))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=8))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=9))
        self.assertTrue(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=9))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=10))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=10))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=666))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "012345678"), offset=0, length=666))

        # sign and verify "0123456789"[1:9]
        self.assertTrue(member.verify("12345678", self._dispersy.crypto.create_signature(ec, "12345678")))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=0))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=0))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=7))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=7))
        self.assertTrue(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=8))
        self.assertTrue(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=8))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=9))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=9))
        self.assertFalse(member.verify("0123456789", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=666))
        self.assertFalse(member.verify("0123456789E", self._dispersy.crypto.create_signature(ec, "12345678"), offset=1, length=666))


    def test_sign(self):
        self._test_sign(u"medium")
        self._test_sign(u"curve25519")

    @call_on_reactor_thread
    def _test_sign(self, curve):
        """
        Test test member.sign assuming is_valid_signature works properly.
        """
        ec = self._dispersy.crypto.generate_key(curve)
        member = self._dispersy.get_member(private_key=self._dispersy.crypto.key_to_bin(ec))

        # sign and verify "0123456789"[0:10]
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789")))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789", offset=0, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789E", offset=0, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789", offset=0, length=9)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789E", offset=0, length=9)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789", offset=0, length=10)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789E", offset=0, length=10)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789", offset=0, length=11))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789E", offset=0, length=11)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789", offset=0, length=666))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "0123456789", member.sign("0123456789E", offset=0, length=666))

        # sign and verify "0123456789"[1:10]
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("123456789")))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789", offset=1, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789E", offset=1, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789", offset=1, length=8)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789E", offset=1, length=8)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789", offset=1, length=9)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789E", offset=1, length=9)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789", offset=1, length=10))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789E", offset=1, length=10)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789", offset=1, length=666))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "123456789", member.sign("0123456789E", offset=1, length=666))

        # sign and verify "0123456789"[0:9]
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("012345678")))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789", offset=0, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789E", offset=0, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789", offset=0, length=8)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789E", offset=0, length=8)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789", offset=0, length=9)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789E", offset=0, length=9)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789", offset=0, length=10)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789E", offset=0, length=10)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789", offset=0, length=666))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "012345678", member.sign("0123456789E", offset=0, length=666))

        # sign and verify "0123456789"[1:9]
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("12345678")))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789", offset=1, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789E", offset=1, length=0)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789", offset=1, length=7)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789E", offset=1, length=7)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789", offset=1, length=8)))
        self.assertTrue(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789E", offset=1, length=8)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789", offset=1, length=9)))
        self.assertFalse(self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789E", offset=1, length=9)))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789", offset=1, length=666))
        with self.assertRaises(ValueError): self._dispersy.crypto.is_valid_signature(ec, "12345678", member.sign("0123456789E", offset=1, length=666))
