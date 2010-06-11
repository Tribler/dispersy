from .Encoding import encode, decode

class Permission(object):
    def __init__(self, name, public_key, private_key):
        assert isinstance(name, str)
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        self._name = name
        self._public_key = public_key
        self._private_key = private_key

    def get_name(self):
        return self._name

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

class AuthorizePermission(Permission):
    pass

class RevokePermission(Permission):
    pass

class GrantPermission(Permission):
    pass

        

