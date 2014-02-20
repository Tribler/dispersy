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

        # check if we are still allowed to send the message
        message = self._community.create_destroy_community(u"hard-kill", store=False, update=False, forward=False)
        self.assertEqual(message.authentication.member, self._community._my_member)

        result = list(message.check_callback([message]))
        self.assertEqual(result, [message], "check_... methods should return a generator with the accepted messages")

    @call_on_dispersy_thread
    def test_fail_check(self):
        """
        Create a community and perform check if a hard-kill message is NOT accepted.

        Whenever a community is created the owner message is authorized to use the
        dispersy-destroy-community message.  We will first revoke the authorization (to use this
        message) and ensure that the message is no longer accepted by the timeline.check().
        """
        # remove the right to hard-kill
        self._community.create_revoke([(self._community.my_member, self._community.get_meta_message(u"dispersy-destroy-community"), u"permit")], sign_with_master=True, store=False, forward=False)

        # check if we are still allowed to send the message
        message = self._community.create_destroy_community(u"hard-kill", store=False, update=False, forward=False)
        self.assertEqual(message.authentication.member, self._community._my_member)
        result = list(message.check_callback([message]))
        self.assertEqual(len(result), 1, "check_... methods should return a generator with the accepted messages")
        self.assertIsInstance(result[0], DelayMessageByProof, "check_... methods should return a generator with the accepted messages")

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
        community = LoadingCommunityTestCommunity.create_community(self._dispersy, self._community._my_member)
        cid = community.cid

        community.unload_community()
        community = None

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

    @call_on_dispersy_thread
    def test_delay_by_proof(self):
        """
        When OTHER receives a message that it has no permission for, it will send a
        dispersy-missing-proof message to try to obtain the dispersy-authorize.
        """

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # permit NODE
        proof_msg = self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                    (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")], store=False, update=False, forward=False)

        # NODE creates message
        tmessage = node.create_protected_full_sync_text("Protected message", 42)
        other.give_message(tmessage, node)
        yield 0.11

        # must NOT have been stored in the database
        self.assert_not_stored(tmessage)

        # OTHER sends dispersy-missing-proof to NODE
        _, message = node.receive_message(names=[u"dispersy-missing-proof"])
        self.assertEqual(message.payload.member.public_key, node.my_member.public_key)
        self.assertEqual(message.payload.global_time, 42)

        # NODE provides proof
        other.give_message(proof_msg, node)
        yield 0.11

        # must have been stored in the database
        self.assert_is_stored(tmessage)

    @call_on_dispersy_thread
    def test_missing_proof(self):
        """
        When OTHER receives a dispersy-missing-proof message she needs to find and send the proof.
        """

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # permit NODE
        self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                    (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")], store=True, update=True, forward=False)

        # create a protected message
        node.give_message(node.create_protected_full_sync_text("Protected message", 42), node)

        # OTHER pretends to received the protected message and requests the proof
        node.give_message(other.create_dispersy_missing_proof(node.my_member, 42), other)
        yield 0.11

        # NODE sends dispersy-authorize to OTHER
        _, authorize = other.receive_message(names=[u"dispersy-authorize"])

        permission_triplet = (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit")
        self.assertIn(permission_triplet, authorize.payload.permission_triplets)

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
        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # permit NODE
        message = self._community.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                                       (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")])

        # OTHER wants the proof that OWNER is allowed to grant authorization to NODE
        node.give_message(other.create_dispersy_missing_proof(message.authentication.member, message.distribution.global_time), other)

        # NODE sends dispersy-authorize containing authorize(MASTER, OWNER) to OTHER
        _, authorize = other.receive_message(names=[u"dispersy-authorize"])

        permission_triplet = (message.authentication.member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit")
        self.assertIn(permission_triplet, authorize.payload.permission_triplets)
