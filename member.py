import logging



class DummyMember(object):

    def __init__(self, dispersy, database_id, mid):
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(database_id, int), type(database_id)
        assert isinstance(mid, str), type(mid)
        assert len(mid) == 20, len(mid)

        self._logger = logging.getLogger(self.__class__.__name__)

        self._database_id = database_id
        self._mid = mid

    @property
    def mid(self):
        """
        The member id.  This is the 20 byte sha1 hash over the public key.
        """
        return self._mid

    @property
    def database_id(self):
        """
        The database id.  This is the unsigned integer used to store
        this member in the Dispersy database.
        """
        return self._database_id

    @property
    def public_key(self):
        return ""

    @property
    def private_key(self):
        return ""

    @property
    def signature_length(self):
        return 0

    def has_identity(self, community):
        return False

    def verify(self, data, signature, offset=0, length=0):
        return False

    def sign(self, data, offset=0, length=0):
        return ""

    def __eq__(self, member):
        return False

    def __ne__(self, member):
        return True

    def __cmp__(self, member):
        return -1

    def __hash__(self):
        return self._mid.__hash__()

    def __str__(self):
        return "<%s 0 %s>" % (self.__class__.__name__, self._mid.encode("HEX"))


class Member(DummyMember):

    def __init__(self, dispersy, key, database_id, mid=None):
        """
        Create a new Member instance.
        """
        from .dispersy import Dispersy
        from .crypto import DispersyKey
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(key, DispersyKey), type(key)
        assert isinstance(database_id, int), type(database_id)

        if not mid:
            mid = dispersy.crypto.key_to_hash(key.pub())
        super(Member, self).__init__(dispersy, database_id, mid)

        public_key = dispersy.crypto.key_to_bin(key.pub())

        if key.has_secret_key():
            private_key = key
        else:
            private_key = None

        self._crypto = dispersy.crypto
        self._database = dispersy.database
        self._public_key = public_key
        self._private_key = private_key
        self._ec = key
        self._signature_length = self._crypto.get_signature_length(self._ec)
        self._has_identity = set()

    @property
    def public_key(self):
        """
        The public key.

        This is binary representation of the public key.
        """
        return self._public_key

    @property
    def private_key(self):
        """
        The private key.

        This is binary representation of the private key.

        It may be an empty string when the private key is not yet available.  In this case the sign
        method will raise a RuntimeError.
        """
        return self._private_key

    @property
    def signature_length(self):
        """
        The length, in bytes, of a signature.
        """
        return self._signature_length

    def add_identity(self, community):
        self._has_identity.add(community.cid)

    def has_identity(self, community):
        """
        Returns True when we have a dispersy-identity message for this member in COMMUNITY.
        """
        from .community import Community
        assert isinstance(community, Community)

        return community.cid in self._has_identity

    def verify(self, data, signature, offset=0, length=0):
        """
        Verify that DATA, starting at OFFSET up to LENGTH bytes, was signed by this member and
        matches SIGNATURE.

        DATA is the signed data and the signature concatenated.
        OFFSET is the offset for the signed data.
        LENGTH is the number of bytes, starting at OFFSET, to be verified.  When this value is 0 it
               is set to len(data) - OFFSET.

        Returns True or False.
        """
        assert isinstance(data, str), type(data)
        assert isinstance(signature, str), type(signature)
        assert isinstance(offset, (int, long)), type(offset)
        assert isinstance(length, (int, long)), type(length)

        if length == 0:
            # default LENGTH is len(DATA[OFFSET:])
            length = len(data) - offset

        elif len(data) < offset + length:
            # DATA is to small, we expect len(DATA[OFFSET:OFFSET+LENGTH]) to be LENGTH
            return False

        if self._public_key and self._signature_length == len(signature):
            return self._crypto.is_valid_signature(self._ec, data[offset:offset + length], signature)

    def sign(self, data, offset=0, length=0):
        """
        Returns the signature of DATA, starting at OFFSET up to LENGTH bytes.

        Will raise a ValueError when len(DATA) < offset + length
        Will raise a RuntimeError when this we do not have the private key.
        """
        assert isinstance(data, str), type(data)
        assert isinstance(offset, (int, long)), type(offset)
        assert isinstance(length, (int, long)), type(length)

        if length == 0:
            # default LENGTH is len(DATA[OFFSET:])
            length = len(data) - offset

        elif len(data) < offset + length:
            # DATA is to small, we expect len(DATA[OFFSET:OFFSET+LENGTH]) to be LENGTH
            raise ValueError("LENGTH is larger than the available DATA")

        if self._private_key:
            return self._crypto.create_signature(self._ec, data[offset:offset + length])
        else:
            raise RuntimeError("unable to sign data without the private key")

    def __eq__(self, member):
        if member:
            assert isinstance(member, DummyMember)
            assert (self._database_id == member.database_id) == (self._mid == member.mid), (self._database_id, member.database_id, self._mid, member.mid)
            return self._database_id == member.database_id
        return False

    def __ne__(self, member):
        return not self == member

    def __cmp__(self, member):
        assert isinstance(member, DummyMember)
        assert (self._database_id == member.database_id) == (self._mid == member.mid)
        return cmp(self._database_id, member.database_id)

    def __hash__(self):
        """
        Allows Member classes to be used as keys in a dictionary.
        """
        return self._public_key.__hash__()

    def __str__(self):
        """
        Returns a human readable string representing the member.
        """
        return "<%s %d %s>" % (self.__class__.__name__, self._database_id, self._mid.encode("HEX"))
