from .logger import get_logger
logger = get_logger(__name__)

from M2Crypto.EC import EC_pub, EC

class DummyMember(object):

    def __init__(self, dispersy, mid):
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(mid, str), type(mid)
        assert len(mid) == 20, len(mid)
        database = dispersy.database

        try:
            database_id, = database.execute(u"SELECT id FROM member WHERE mid = ? LIMIT 1", (buffer(mid),)).next()
        except StopIteration:
            database.execute(u"INSERT INTO member (mid) VALUES (?)", (buffer(mid),))
            database_id = database.last_insert_rowid

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

    @property
    def must_store(self):
        return False

    @must_store.setter
    def must_store(self, value):
        pass

    @property
    def must_ignore(self):
        return False

    @must_ignore.setter
    def must_ignore(self, value):
        pass

    @property
    def must_blacklist(self):
        return False

    @must_blacklist.setter
    def must_blacklist(self, value):
        pass

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

    def __init__(self, dispersy, key, database_id):
        """
        Create a new Member instance.
        """
        from .dispersy import Dispersy
        assert isinstance(dispersy, Dispersy), type(dispersy)
        assert isinstance(key, (EC, EC_pub))
        assert isinstance(database_id, int), type(database_id)

        public_key = dispersy.crypto.key_to_bin(key.pub())

        if key.__class__ is EC:
            private_key = key
        else:
            private_key = None
        mid = dispersy.crypto.key_to_hash(key.pub())

        self._crypto = dispersy.crypto
        self._database = dispersy.database
        self._database_id = database_id
        self._mid = mid
        self._public_key = public_key
        self._private_key = private_key
        self._ec = key
        self._signature_length = self._crypto.get_signature_length(self._ec)
        self._has_identity = set()

        logger.debug("mid:%s db:%d public:%s private:%s", self._mid.encode("HEX"), self._database_id, bool(self._public_key), bool(self._private_key))

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

    def set_private_key(self, private_key):
        assert isinstance(private_key, str)
        assert self._private_key == ""
        self._private_key = private_key
        self._ec = self._crypto.key_from_private_bin(private_key)
        self._database.execute(u"INSERT INTO private_key (member, private_key) VALUES (?, ?)", (self._database_id, buffer(private_key)))

    def has_identity(self, community):
        """
        Returns True when we have a dispersy-identity message for this member in COMMUNITY.
        """
        from .community import Community
        assert isinstance(community, Community)

        if community.cid in self._has_identity:
            return True
        else:
            try:
                self._database.execute(u"SELECT 1 FROM sync WHERE member = ? AND meta_message = ? LIMIT 1",
                                       (self._database_id, community.get_meta_message(u"dispersy-identity").database_id)).next()
            except StopIteration:
                return False
            else:
                self._has_identity.add(community.cid)
                return True

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

        return self._public_key and \
            self._signature_length == len(signature) \
            and self._crypto.is_valid_signature(self._ec, data[offset:offset + length], signature)

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
            assert (self._database_id == member.database_id) == (self._mid == member.mid),  (self._database_id, member.database_id, self._mid, member.mid)
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
