"""
A simple forum community
"""

from hashlib import sha1
from time import time

from Privilege import PrivilegeBase, PublicPrivilege, LinearPrivilege
from Crypto import *
from Encoding import encode, decode
from Dispersy import Dispersy
from DispersyDatabase import DispersyDatabase
from Community import Community
from Conversion import Conversion00001
from Database import Database
from Message import DelayMessage, SyncMessage, FullSyncDistribution, CommunityDestination
from Permission import AuthorizePermission, RevokePermission, PermitPermission
from Member import Member, MyMember

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
    dispersy = Dispersy.get_instance(":memory:")
    database = DispersyDatabase.get_instance()

    community = ForumCommunity.create_community(dispersy.get_my_member())
    dispersy.add_community(community)
    assert community.get_my_member() == dispersy.get_my_member()

    return community

def test_timeline():
    def create_thread_for(rsa, global_time, sequence_number, title, comment):
        member = MyMember(rsa_to_private_pem(rsa))
        key = buffer(sha1(u"%d %s %s %s" % (time(), title, comment, member.get_pem())).digest())
        distribution = FullSyncDistribution(global_time, sequence_number)
        destination = CommunityDestination()
        permission = PermitPermission(community.get_privilege(u"thread"), (key, title, comment))

        message = SyncMessage(community, member, distribution, destination, permission)
        packet = community.get_conversion().encode_message(message)
        
        return key, message, packet

    def create_post_for(rsa, global_time, sequence_number, key, comment):
        member = MyMember(rsa_to_private_pem(rsa))
        distribution = FullSyncDistribution(global_time, sequence_number)
        destination = CommunityDestination()
        permission = PermitPermission(community.get_privilege(u"post"), (key, comment))

        message = SyncMessage(community, member, distribution, destination, permission)
        packet = community.get_conversion().encode_message(message)
        
        return message, packet

    def create_metadata_for(rsa, global_time, sequence_number, name):
        member = MyMember(rsa_to_private_pem(rsa))
        distribution = FullSyncDistribution(global_time, sequence_number)
        destination = CommunityDestination()
        permission = PermitPermission(community.get_privilege(u"metadata"), (name,))

        message = SyncMessage(community, member, distribution, destination, permission)
        packet = community.get_conversion().encode_message(message)
        
        return message, packet

    dispersy = Dispersy.get_instance(":memory:")
    database = DispersyDatabase.get_instance()
    community = test_create()

    # Alice
    community.create_metadata(u"Alice")
    key = community.create_thread(u"Welcome all!", u"Please leave a message in this thread if you are alive!")
    community.create_post(key, u"Alice was here!")

    # Bob
    bob_address = ("localhost", 1)
    bob_rsa = rsa_generate_key(512)
    bob = Member(rsa_to_public_pem(bob_rsa))
    pairs = [(community.get_privilege(u"thread"), PermitPermission), (community.get_privilege(u"post"), PermitPermission)]
    community.authorize(bob, pairs)

    time = community._timeline._global_time + 1

    # bob puts something on the forum
    message, packet = create_metadata_for(bob_rsa, time, 1, u"Bob")
    dispersy.on_incoming_packets([(bob_address, packet)])
    message, packet = create_post_for(bob_rsa, time, 2, key, u"Bob was here...")
    dispersy.on_incoming_packets([(bob_address, packet)])

    time = community._timeline._global_time
    time = 1

    # Carol
    carol_address = ("localhost", 2)
    carol_rsa = rsa_generate_key(512)
    message, packet = create_post_for(carol_rsa, time, 1, key, u"Carol was here...")
    dispersy.on_incoming_packets([(carol_address, packet)])
    message, packet = create_metadata_for(carol_rsa, time, 2, u"Carol")
    dispersy.on_incoming_packets([(carol_address, packet)])

    database.screen_dump()
    community._database.screen_dump()
        
if __name__ == "__main__":
    # test_crypto()
    # test_create()
    test_timeline()

