"""
A simple forum community
"""

from hashlib import sha1
from time import time

from Privilege import PrivilegeBase, LinearPrivilege
from Crypto import *
from Encoding import encode, decode
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Community import Community
from Conversion import Conversion00001
from Database import Database
from Message import SyncMessage, FullSyncDistribution, CommunityDestination
from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Member import Member

class ForumDatabase(Database):
    def check_database(self, database_version):
        if database_version == "0":
            self.execute(u"""
CREATE TABLE thread(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 key BLOB,
 member INTEGER,
 title STRING,
 comment STRING);

CREATE TABLE post(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 thread INTEGER REFERENCES thread(id),
 member INTEGER,
 comment STRING);
 
CREATE TABLE option(key STRING PRIMARY KEY, value BLOB);
INSERT INTO option (key, value) VALUES('database_version', '1');
""")

        elif database_version == "1":
            # current version requires no action
            pass
                         
        else:
            # unknown database version
            raise ValueError

class ForumCommunity(Community):
    # static privilege settings
    _privileges = {buffer("thread"):LinearPrivilege("thread"),
                   buffer("post"):LinearPrivilege("post")}

    @classmethod
    def create_community(cls, my_member):
        return Community.create_community(cls, cls._privileges.values(), my_member)

    def __init__(self, cid, my_member):
        Community.__init__(self, cid, my_member)
        # forum storage
        self._database = ForumDatabase.get_instance(":memory:")

    def get_privilege(self, name):
        assert isinstance(name, buffer)
        return self._privileges[name]

    def create_thread(self, title, comment):
        assert isinstance(title, unicode)
        assert isinstance(comment, unicode)
        key = buffer(sha1(u"%d %s %s %s" % (time(), title, comment, self.get_my_member().get_pem())).digest())
        self.permit(PermitPermission(self.get_privilege(buffer("thread")), (key, title, comment)))
        return key

    def create_post(self, key, comment):
        assert isinstance(key, buffer)
        assert isinstance(comment, unicode)
        self.permit(PermitPermission(self.get_privilege(buffer("post")), (key, comment)))

    def on_incoming_message(self, address, packet, message):
        print message

def test_crypto():
    rsa = rsa_generate_key()
    pub = rsa_to_public_pem(rsa)
    prv = rsa_to_private_pem(rsa)
    print pub
    print prv
    for i in range(10):
        assert pub == rsa_to_public_pem(rsa_from_private_pem(prv))

    rsa = rsa_from_private_pem(prv)
    rsa = rsa_from_public_pem(pub)

def test_create():
    dispersy = Dispersy.get_instance()
    database = DispersyDatabase.get_instance()

    community = ForumCommunity.create_community(dispersy.get_my_member())
    dispersy.add_community(community)
    assert community.get_my_member() == dispersy.get_my_member()

    return community

def test_timeline():
    dispersy = Dispersy.get_instance()
    database = DispersyDatabase.get_instance()
    community = test_create()

    my_member = community.get_my_member()
    conversion = community.get_conversion()

    bob_address = ("localhost", 1)
    bob_rsa = rsa_generate_key(512)
    bob = Member(rsa_to_public_pem(bob_rsa))

    pair = (community.get_privilege(buffer("thread")), PermitPermission)
    community.authorize(bob, [pair])

    key = community.create_thread(u"Hello all!", u"Bob was here!")
    community.create_post(key, u"Bob has gone now...")

    print database    
        
if __name__ == "__main__":
    # test_crypto()
    # test_create()
    test_timeline()

