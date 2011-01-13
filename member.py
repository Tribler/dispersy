"""
For each peer that we have the public key, we have one Member
instance.  Each member instance is used to uniquely identify a peer.
Special Member subclasses exist to identify, for instance, youself.
"""

from hashlib import sha1

from singleton import Parameterized1Singleton
from dispersydatabase import DispersyDatabase
from crypto import ec_from_private_pem, ec_from_public_pem, ec_to_public_pem, ec_signature_length, ec_verify, ec_sign
from encoding import encode, decode

if __debug__:
    from dprint import dprint

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
        The length, in bytes, of a signature.
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

    # This _singleton_instances is very important.  It ensures that
    # all subclasses of Member use the same dictionary when looking
    # for a public_pem.  Otherwise each subclass would get its own
    # _singleton_instances dictionary.
    _singleton_instances = {}

    def __init__(self, public_pem, ec=None, sync_with_database=True):
        """
        Create a new Member instance.  Member instances must be reated
        or retrieved using has_instance or get_instance.

        PUBLIC_PEM must be a string giving the public EC key in PEM format.
        EC is an optional EC object (given when created from private PEM).
        """
        assert isinstance(public_pem, str)
        assert public_pem[:26] == "-----BEGIN PUBLIC KEY-----"
        assert isinstance(sync_with_database, bool)
        self._public_pem = public_pem
        if ec is None:
            self._ec = ec_from_public_pem(public_pem)
        else:
            self._ec = ec

        self._signature_length = ec_signature_length(self._ec)
        self._mid = sha1(public_pem).digest()

        self._database_id = -1
        self._address = ("", -1)

        # sync with database
        if sync_with_database:
            if not self.update():
                database = DispersyDatabase.get_instance()
                database.execute(u"INSERT INTO user(mid, pem, host, port) VALUES(?, ?, '', -1)", (buffer(self._mid), buffer(self._public_pem)))
                self._database_id = database.last_insert_rowid

    def update(self):
        """
        Update this instance from the database
        """
        try:
            self._database_id, host, port = DispersyDatabase.get_instance().execute(u"SELECT id, host, port FROM user WHERE pem = ? LIMIT 1", (buffer(self._public_pem),)).next()
            self._address = (str(host), port)
            return True

        except StopIteration:
            return False

    @property
    def mid(self):
        return self._mid

    @property
    def pem(self):
        return self._public_pem

    @property
    def signature_length(self):
        return self._signature_length

    @property
    def database_id(self):
        """
        The database id.  This is the unsigned integer used to store
        this member in the Dispersy database.
        """
        assert self._database_id > 0, "No database id set.  Please call member.update()"
        return self._database_id

    @property
    def address(self):
        """
        The most recently advertised address for this member.

        Addresses are advertised using a dispersy-identity message,
        and the most recent -per member- is stored and forwarded.  The
        address will be ('', -1) until at least one dispersy-identity
        message for the member is received.
        """
        return self._address

    def verify(self, data, signature, offset=0, length=0):
        assert isinstance(data, str)
        assert isinstance(signature, str)
        assert isinstance(offset, (int, long))
        assert isinstance(length, (int, long))
        length = length or len(data)
        return self._signature_length == len(signature) and ec_verify(self._ec, sha1(data[offset:offset+length]).digest(), signature)

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
        assert private_pem is None or private_pem[:30] == "-----BEGIN EC PRIVATE KEY-----", private_pem
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
            ec = ec_from_public_pem(public_pem)
        else:
            ec = ec_from_private_pem(private_pem)

        super(PrivateMember, self).__init__(public_pem, ec, sync_with_database)
        self._private_pem = private_pem

    @property
    def private_pem(self):
        return self._private_pem

    def sign(self, data, offset=0, length=0):
        """
        Sign DATA using our private key.  Returns the signature.
        """
        assert not self._private_pem is None
        return ec_sign(self._ec, sha1(data[offset:length or len(data)]).digest())

class MasterMember(PrivateMember):
    pass

class MyMember(PrivateMember):
    pass

if __debug__:
    if __name__ == "__main__":
        from crypto import ec_generate_key, ec_to_public_pem, ec_to_private_pem

        ec = ec_generate_key("low")
        public_pem = ec_to_public_pem(ec)
        private_pem = ec_to_private_pem(ec)
        public_member = Member(public_pem, sync_with_database=False)
        private_member = PrivateMember(public_pem, private_pem, sync_with_database=False)

        print
        print public_pem
        print
        print private_pem
        print

        data = "Hello World! " * 1000
        sig = private_member.sign(data)
        digest = sha1(data).digest()
        dprint(sig.encode("HEX"))
        assert public_member.verify(data, sig)
        assert private_member.verify(data, sig)
