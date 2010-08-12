from hashlib import sha1

from Singleton import Parameterized1Singleton
from DispersyDatabase import DispersyDatabase
from Crypto import rsa_from_private_pem, rsa_from_public_pem, rsa_to_public_pem
from Encoding import encode, decode

class Member(Parameterized1Singleton):
    def __init__(self, public_pem, rsa=None):
        assert isinstance(public_pem, str)
        assert public_pem[:26] == "-----BEGIN PUBLIC KEY-----"
        assert rsa is None or len(rsa) % 8 == 0
        self._public_pem = public_pem
        if rsa is None:
            self._rsa = rsa_from_public_pem(public_pem)
        else:
            self._rsa = rsa
        self._mid = sha1(public_pem).digest()

        # sync with database
        database = DispersyDatabase.get_instance()
        try:
            self._database_id = database.execute(u"SELECT id FROM user WHERE pem = ? LIMIT 1", (buffer(public_pem),)).next()[0]
        except StopIteration:
            database.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(self._mid), buffer(public_pem)))
            self._database_id = database.get_last_insert_rowid()

    def get_pem(self):
        """
        Returns the public PEM.
        """
        return self._public_pem

    def get_database_id(self):
        return self._database_id

    def verify_pair(self, data, offset=0, length=0):
        """
        Verify that DATA, containing n byte signature followed by m
        byte data, was signed with our public key.

        DATA is the signed data and the signature concatenated.
        OFFSET is the offset for the signed data.
        LENGTH is the length of the signature and the data, in bytes.

        Returns True or False.
        """
        assert isinstance(data, str)
        assert isinstance(offset, (int, long))
        assert isinstance(length, (int, long))
        if not length: length = len(data)
        signature_length = len(self._rsa) / 8
        return bool(self._rsa.verify(sha1(data[offset:length-signature_length]).digest(), data[length-signature_length:length]))

    def __str__(self):
        return "<%s %d %s>" % (self.__class__.__name__, self._database_id, self._mid.encode("HEX"))

class PrivateMemberBase(Member):
    def __init__(self, public_pem, private_pem=None):
        assert isinstance(public_pem, str)
        assert public_pem[:26] == "-----BEGIN PUBLIC KEY-----"
        assert isinstance(private_pem, (type(None), str))
        assert private_pem is None or private_pem[:31] == "-----BEGIN RSA PRIVATE KEY-----"

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

        Member.__init__(self, public_pem, rsa)
        self._private_pem = private_pem
        self._sequence_number = 0

    def claim_sequence_number(self):
        assert not self._private_pem is None
        self._sequence_number += 1
        return self._sequence_number
        
    def get_private_pem(self):
        return self._private_pem

    def generate_pair(self, data, offset=0, length=0):
        """
        Sign DATA using our private key.  Returns a binary string
        concatenated with the signature.
        """
        assert not self._private_pem is None
        return data[offset:length or len(data)] + self._rsa.sign(sha1(data[offset:length or len(data)]).digest())

class MasterMember(PrivateMemberBase):
    pass

class MyMember(PrivateMemberBase):
    pass
