from hashlib import sha1

from DispersyDatabase import DispersyDatabase
from Crypto import rsa_from_private_pem, rsa_from_public_pem, rsa_to_public_pem
from Encoding import encode, decode

class _Public(object):
    def __init__(self, pem, rsa):
        assert len(rsa) % 8 == 0
        self._pem = pem
        self._rsa = rsa
        self._mid = sha1(pem).digest()

        # sync with database
        database = DispersyDatabase.get_instance()
        try:
            self._database_id = database.execute(u"SELECT id FROM user WHERE pem = ? LIMIT 1", (self._pem,)).next()[0]
        except StopIteration:
            database.execute(u"INSERT INTO user(mid, pem) VALUES(?, ?)", (buffer(self._mid), self._pem))
            self._database_id = database.get_last_insert_rowid()

    def get_pem(self):
        """
        Returns the public PEM.
        """
        return self._pem

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
        assert isinstance(data, (str, buffer))
        assert isinstance(offset, (int, long))
        assert isinstance(length, (int, long))
        if not length: length = len(data)
        signature_length = len(self._rsa) / 8
        return bool(self._rsa.verify(sha1(data[offset:length-signature_length]).digest(), data[length-signature_length:length]))

    def __str__(self):
        return "<%s>" % (self.__class__.__name__)

class _Private(_Public):
    def __init__(self, pem, rsa):
        assert len(rsa) % 8 == 0
        _Public.__init__(self, rsa_to_public_pem(rsa), rsa)
        self._private_pem = pem
        self._sequence_number = 0

    def claim_sequence_number(self):
        self._sequence_number += 1
        return self._sequence_number
        
    def get_private_pem(self):
        return self._private_pem

    def generate_pair(self, data, offset=0, length=0):
        """
        Sign DATA using our private key.  Returns a binary string
        concatenated with the signature.
        """
        return data[offset:length or len(data)] + self._rsa.sign(sha1(data[offset:length or len(data)]).digest())

class Member(_Public):
    def __init__(self, pem):
        assert isinstance(pem, buffer)
        assert pem[:26] == "-----BEGIN PUBLIC KEY-----"
        _Public.__init__(self, pem, rsa_from_public_pem(pem))

class MasterMember(Member, _Private):
    def __init__(self, pem):
        assert isinstance(pem, buffer)
        assert pem[:31] == "-----BEGIN RSA PRIVATE KEY-----"
        _Private.__init__(self,  pem, rsa_from_private_pem(pem))

class MyMember(Member, _Private):
    def __init__(self, pem):
        assert isinstance(pem, buffer)
        assert pem[:31] == "-----BEGIN RSA PRIVATE KEY-----"
        _Private.__init__(self,  pem, rsa_from_private_pem(pem))
