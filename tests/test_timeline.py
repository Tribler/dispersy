from ..logger import get_logger
from ..message import DelayMessageByProof
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestTimeline(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_succeed_check(self):
        """
        Create a community and perform check if a hard-kill message is accepted.

        Whenever a community is created the owner message is authorized to use the
        dispersy-destroy-community message.  Hence, this message should be accepted by the
        timeline.check().
        """
        # create a community.
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        # the master member must have given my_member all permissions for dispersy-destroy-community
        yield 0.555

        logger.debug("master_member: %s, %s", community.master_member.database_id, community.master_member.mid.encode("HEX"))
        logger.debug("    my_member: %s, %s", community.my_member.database_id, community.my_member.mid.encode("HEX"))

        # check if we are still allowed to send the message
        message = community.create_destroy_community(u"hard-kill", store=False, update=False, forward=False)
        self.assertEqual(message.authentication.member, self._my_member)
        result = list(message.check_callback([message]))
        self.assertEqual(result, [message], "check_... methods should return a generator with the accepted messages")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_fail_check(self):
        """
        Create a community and perform check if a hard-kill message is NOT accepted.

        Whenever a community is created the owner message is authorized to use the
        dispersy-destroy-community message.  We will first revoke the authorization (to use this
        message) and ensure that the message is no longer accepted by the timeline.check().
        """
        # create a community.
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        # the master member must have given my_member all permissions for dispersy-destroy-community
        yield 0.555

        logger.debug("master_member: %d, %s", community.master_member.database_id, community.master_member.mid.encode("HEX"))
        logger.debug("    my_member: %d, %s", community.my_member.database_id, community.my_member.mid.encode("HEX"))

        # remove the right to hard-kill
        community.create_revoke([(community.my_member, community.get_meta_message(u"dispersy-destroy-community"), u"permit")], sign_with_master=True, store=False, forward=False)

        # check if we are still allowed to send the message
        message = community.create_destroy_community(u"hard-kill", store=False, update=False, forward=False)
        self.assertEqual(message.authentication.member, self._my_member)
        result = list(message.check_callback([message]))
        self.assertEqual(len(result), 1, "check_... methods should return a generator with the accepted messages")
        self.assertIsInstance(result[0], DelayMessageByProof, "check_... methods should return a generator with the accepted messages")

        # cleanup
        community.create_destroy_community(u"hard-kill", sign_with_master=True)
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_loading_community(self):
        """
        When a community is loaded it must load all available dispersy-authorize and dispersy-revoke
        message from the database.
        """
        class LoadingCommunityTestCommunity(DebugCommunity):
            pass

        # create a community.  the master member must have given my_member all permissions for
        # dispersy-destroy-community
        community = LoadingCommunityTestCommunity.create_community(self._dispersy, self._my_member)
        cid = community.cid

        logger.debug("master_member: %d, %s", community.master_member.database_id, community.master_member.mid.encode("HEX"))
        logger.debug("    my_member: %d, %s", community.my_member.database_id, community.my_member.mid.encode("HEX"))

        logger.debug("unload community")
        community.unload_community()
        community = None
        yield 0.555

        # load the same community and see if the same permissions are loaded
        communities = [LoadingCommunityTestCommunity.load_community(self._dispersy, master)
                       for master
                       in LoadingCommunityTestCommunity.get_master_members(self._dispersy)]
        self.assertEqual(len(communities), 1)
        self.assertEqual(communities[0].cid, cid)
        community = communities[0]

        # check if we are still allowed to send the message
        message = community.create_destroy_community(u"hard-kill", store=False, update=False, forward=False)
        self.assertTrue(community.timeline.check(message))

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_delay_by_proof(self):
        """
        When SELF receives a message that it has no permission for, it will send a
        dispersy-missing-proof message to try to obtain the dispersy-authorize.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node1 = DebugNode(community)
        node1.init_socket()
        node1.init_my_member()
        yield 0.555

        # create node and ensure that SELF knows the node address
        node2 = DebugNode(community)
        node2.init_socket()
        node2.init_my_member()
        yield 0.555

        # permit NODE1
        logger.debug("SELF creates dispersy-authorize for NODE1")
        community.create_authorize([(node1.my_member, community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                             (node1.my_member, community.get_meta_message(u"protected-full-sync-text"), u"authorize")])

        # NODE2 created message @20
        logger.debug("NODE2 creates protected-full-sync-text, should be delayed for missing proof")
        global_time = 20
        message = node2.create_protected_full_sync_text("Protected message", global_time)
        node2.give_message(message)
        yield 0.555

        # may NOT have been stored in the database
        try:
            packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                       (community.database_id, node2.my_member.database_id, global_time)).next()
        except StopIteration:
            pass

        else:
            self.fail("should not have stored, did not have permission")

        # SELF sends dispersy-missing-proof to NODE2
        logger.debug("NODE2 receives dispersy-missing-proof")
        _, message = node2.receive_message(message_names=[u"dispersy-missing-proof"])
        self.assertEqual(message.payload.member.public_key, node2.my_member.public_key)
        self.assertEqual(message.payload.global_time, global_time)

        logger.debug("=====")
        logger.debug("node1: %d", node1.my_member.database_id)
        logger.debug("node2: %d", node2.my_member.database_id)

        # NODE1 provides proof
        logger.debug("NODE1 creates and provides missing proof")
        sequence_number = 1
        proof_global_time = 10
        node2.give_message(node1.create_dispersy_authorize([(node2.my_member, community.get_meta_message(u"protected-full-sync-text"), u"permit")], sequence_number, proof_global_time))
        yield 0.555

        logger.debug("=====")

        # must have been stored in the database
        logger.debug("SELF must have processed both the proof and the protected-full-sync-text message")
        try:
            packet, = self._dispersy.database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                       (community.database_id, node2.my_member.database_id, global_time)).next()
        except StopIteration:
            self.fail("should have been stored")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_missing_proof(self):
        """
        When SELF receives a dispersy-missing-proof message she needs to find and send the proof.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()
        yield 0.555

        # SELF creates a protected message
        message = community.create_protected_full_sync_text("Protected message")

        # flush incoming socket buffer
        node.drop_packets()

        # NODE pretends to receive the protected message and requests the proof
        node.give_message(node.create_dispersy_missing_proof(message.authentication.member, message.distribution.global_time))
        yield 0.555

        # SELF sends dispersy-authorize to NODE
        _, authorize = node.receive_message(message_names=[u"dispersy-authorize"])

        permission_triplet = (community.my_member, community.get_meta_message(u"protected-full-sync-text"), u"permit")
        self.assertIn(permission_triplet, authorize.payload.permission_triplets)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_missing_authorize_proof(self):
        """
             MASTER
               \\        authorize(MASTER, OWNER)
                \\
                OWNER
                  \\        authorize(OWNER, NODE1)
                   \\
                   NODE1

        When SELF receives a dispersy-missing-proof message from NODE2 for authorize(OWNER, NODE1)
        the dispersy-authorize message for authorize(MASTER, OWNER) must be returned.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)

        # create node and ensure that SELF knows the node address
        node1 = DebugNode(community)
        node1.init_socket()
        node1.init_my_member()
        yield 0.555

        # create node and ensure that SELF knows the node address
        node2 = DebugNode(community)
        node2.init_socket()
        node2.init_my_member()
        yield 0.555

        # permit NODE1
        logger.debug("SELF creates dispersy-authorize for NODE1")
        message = community.create_authorize([(node1.my_member, community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                                       (node1.my_member, community.get_meta_message(u"protected-full-sync-text"), u"authorize")])

        # flush incoming socket buffer
        node2.drop_packets()

        logger.debug("===")
        logger.debug("master: %d", community.master_member.database_id)
        logger.debug("member: %d", community.my_member.database_id)
        logger.debug("node1:  %d", node1.my_member.database_id)
        logger.debug("node2:  %d", node2.my_member.database_id)

        # NODE2 wants the proof that OWNER is allowed to grant authorization to NODE1
        logger.debug("NODE2 asks for proof that NODE1 is allowed to authorize")
        node2.give_message(node2.create_dispersy_missing_proof(message.authentication.member, message.distribution.global_time))
        yield 0.555

        logger.debug("===")

        # SELF sends dispersy-authorize containing authorize(MASTER, OWNER) to NODE
        logger.debug("NODE2 receives the proof from SELF")
        _, authorize = node2.receive_message(message_names=[u"dispersy-authorize"])

        permission_triplet = (message.authentication.member, community.get_meta_message(u"protected-full-sync-text"), u"permit")
        logger.debug("%s", (permission_triplet[0].database_id, permission_triplet[1].name, permission_triplet[2]))
        logger.debug("%s", [(x.database_id, y.name, z) for x, y, z in authorize.payload.permission_triplets])
        self.assertIn(permission_triplet, authorize.payload.permission_triplets)

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
