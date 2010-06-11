from .Encoding import encode, decode

class Member(object):
    def __init__(self, public_key, private_key):
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        self._public_key = public_key
        self._private_key = private_key

    def get_key(self):
        return self._public_key

    def sign(self, value):
        """
        Sign VALUE using our public key.  Returns a binary string.
        """
        # todo!
        return encode(value)

    def verify(self, value):
        """
        Verify that VALUE was signed with our public key.  Returns
        decrypted VALUE or raises ValueError.
        """
        # todo!
        return decode(value)
