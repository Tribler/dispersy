"""
For each peer that we have the public key, we have one Member
instance.  Each member instance is used to uniquely identify a peer.
Special Member subclasses exist to identify, for instance, youself.
"""

from hashlib import sha1

from Singleton import Parameterized1Singleton
from DispersyDatabase import DispersyDatabase
from Crypto import rsa_from_private_pem, rsa_from_public_pem, rsa_to_public_pem
from Encoding import encode, decode

if __debug__:
    from Print import dprint

class Public(object):
    @property
    def mid(self):
        """
        The member id.  This is the 20 byte sha1 hash over the public
        pem.
        """
        raise NotImplementedError()

    @property
    def pem(self):
        """
        The public PEM.  This is a human readable representation of
        the public key.
        """
        raise NotImplementedError()

    @property
    def signature_length(self):
        """
        The length, in bytes, a a signature.
        """
        raise NotImplementedError()

    def verify(self, data, signature, offset=0, length=0):
        """
        Verify that DATA, starting at OFFSET up to LENGTH bytes, was
        signed by this member and matches SIGNATURE.

        DATA is the signed data and the signature concatenated.
        OFFSET is the offset for the signed data.
        LENGTH is the length of the signature and the data, in bytes.

        Returns True or False.
        """
        raise NotImplementedError()

class Private(object):
    @property
    def private_pem(self):
        raise NotImplementedError()

    def sign(self, data, offset=0, length=0):
        """
        Sign DATA using our private key.  Returns a signature.
        """
        raise NotImplementedError()

class Member(Public, Parameterized1Singleton):
    """
    The Member class represents a single member in the Dispersy
    database.

    There should only be one or less Member instance for each member
    in the database.  To ensure this, each Member instance must be
    created or retrieved using has_instance or get_instance.
    """
    def __init__(self, public_pem, rsa=None, sync_with_database=True):
        """
        Create a new Member instance.  Member instances must be reated
        or retrieved using has_instance or get_instance.

        PUBLIC_PEM must be a string giving the public RSA key in PEM format.
        RSA is an optional RSA object (given when created from private PEM).
        """
        assert isinstance(public_pem, str)
        assert public_pem[:26] == "-----BEGIN PUBLIC KEY-----"
        assert rsa is None or len(rsa) % 8 == 0
        assert isinstance(sync_with_database, bool)
        self._public_pem = public_pem
        if rsa is None:
            self._rsa = rsa_from_public_pem(public_pem)
        else:
            self._rsa = rsa
        self._mid = sha1(public_pem).digest()

        # sync with database
        if sync_with_database:
            database = DispersyDatabase.get_instance()
            try:
                self._database_id = database.execute(u"SELECT id FROM user WHERE pem = ? LIMIT 1", (buffer(public_pem),)).next()[0]
            except StopIteration:
                database.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(self._mid), buffer(public_pem)))
                self._database_id = database.last_insert_rowid
        else:
            self._database_id = -1

        # link to the discovery metadata
        self._discovery = None

    @property
    def discovery(self):
        if not self._discovery:
            from Tribler.Community.Discovery.UserMetadata import UserMetadata
            self._discovery = UserMetadata.get_instance(self)
        return self._discovery

    @property
    def mid(self):
        return self._mid

    @property
    def pem(self):
        return self._public_pem

    @property
    def signature_length(self):
        return len(self._rsa) / 8

    @property
    def database_id(self):
        """
        The database id.  This is the unsigned integer used to store
        this member in the Dispersy database.
        """
        return self._database_id

    def verify(self, data, signature, offset=0, length=0):
        assert isinstance(data, str)
        assert isinstance(signature, str)
        assert isinstance(offset, (int, long))
        assert isinstance(length, (int, long))
        return len(signature) == len(self._rsa) / 8 and bool(self._rsa.verify(sha1(data[offset:offset+length]).digest(), signature))

    # def verify_pair(self, data, offset=0, length=0):
    #     """
    #     Verify that DATA, containing n byte signature followed by m
    #     byte data, was signed with our public key.

    #     DATA is the signed data and the signature concatenated.
    #     OFFSET is the offset for the signed data.
    #     LENGTH is the length of the signature and the data, in bytes.

    #     Returns True or False.
    #     """
    #     assert isinstance(data, str)
    #     assert isinstance(offset, (int, long))
    #     assert isinstance(length, (int, long))
    #     if not length: length = len(data)
    #     signature_length = len(self._rsa) / 8
    #     return bool(self._rsa.verify(sha1(data[offset:length-signature_length]).digest(), data[length-signature_length:length]))

    def __hash__(self):
        """
        Allows Member classes to be used as keys in a dictionary.
        """
        return self._database_id

    def __str__(self):
        """
        Returns a human readable string representing the member.
        """
        return "<%s %d %s>" % (self.__class__.__name__, self._database_id, self._mid.encode("HEX"))

class PrivateMember(Private, Member):
    def __init__(self, public_pem, private_pem=None, sync_with_database=True):
        assert isinstance(public_pem, str)
        assert public_pem[:26] == "-----BEGIN PUBLIC KEY-----"
        assert isinstance(private_pem, (type(None), str))
        assert private_pem is None or private_pem[:31] == "-----BEGIN RSA PRIVATE KEY-----"
        assert isinstance(sync_with_database, bool)

        if sync_with_database:
            if private_pem is None:
                # get private pem
                database = DispersyDatabase.get_instance()
                try:
                    private_pem = str(database.execute(u"SELECT private_pem FROM key WHERE public_pem == ? LIMIT 1", (buffer(public_pem),)).next()[0])
                except StopIteration:
                    pass

            else:
                # set private pem
                database = DispersyDatabase.get_instance()
                database.execute(u"INSERT INTO key(public_pem, private_pem) VALUES(?, ?)", (buffer(public_pem), buffer(private_pem)))

        if private_pem is None:
            rsa = rsa_from_public_pem(public_pem)
        else:
            rsa = rsa_from_private_pem(private_pem)

        super(PrivateMember, self).__init__(public_pem, rsa, sync_with_database)
        self._private_pem = private_pem
        self._sequence_number = 0

    def claim_sequence_number(self):
        assert not self._private_pem is None
        self._sequence_number += 1
        return self._sequence_number

    @property
    def private_pem(self):
        return self._private_pem

    def sign(self, data, offset=0, length=0):
        """
        Sign DATA using our private key.  Returns the signature.
        """
        assert not self._private_pem is None
        return self._rsa.sign(sha1(data[offset:length or len(data)]).digest())

    # def generate_pair(self, data, offset=0, length=0):
    #     """
    #     Sign DATA using our private key.  Returns a binary string
    #     concatenated with the signature.
    #     """
    #     assert not self._private_pem is None
    #     return data[offset:length or len(data)] + self._rsa.sign(sha1(data[offset:length or len(data)]).digest())

class MasterMember(PrivateMember):
    pass

class MyMember(PrivateMember):
    pass
