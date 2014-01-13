from ..logger import get_logger
from ..resolution import PublicResolution, LinearResolution
from .debugcommunity.community import DebugCommunity
from .debugcommunity.node import DebugNode
from .dispersytestclass import DispersyTestFunc, call_on_dispersy_thread
logger = get_logger(__name__)


class TestDynamicSettings(DispersyTestFunc):

    @call_on_dispersy_thread
    def test_default_resolution(self):
        """
        Ensure that the default resolution policy is used first.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"dynamic-resolution-text")

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # check default policy
        policy, proof = community.timeline.get_resolution_policy(meta, community.global_time)
        self.assertIsInstance(policy, PublicResolution)
        self.assertEqual(proof, [])

        # NODE creates a message (should allow, because the default policy is PublicResolution)
        global_time = 10
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, policy.implement()))

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_change_resolution(self):
        """
        Change the resolution policy from default to linear and to public again.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"dynamic-resolution-text")
        public = meta.resolution.policies[0]
        linear = meta.resolution.policies[1]

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # check default policy
        public_policy, proof = community.timeline.get_resolution_policy(meta, community.global_time + 1)
        self.assertIsInstance(public_policy, PublicResolution)
        self.assertEqual(proof, [])

        # change and check policy
        message = community.create_dynamic_settings([(meta, linear)])
        linear_policy, proof = community.timeline.get_resolution_policy(meta, community.global_time + 1)
        self.assertIsInstance(linear_policy, LinearResolution)
        self.assertEqual(proof, [message])

        # NODE creates a message (should allow)
        global_time = message.distribution.global_time
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public_policy.implement()))
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # NODE creates a message (should drop)
        global_time += 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, linear_policy.implement()))
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            pass
        else:
            self.fail("must not accept the message")

        # change and check policy
        message = community.create_dynamic_settings([(meta, public)])
        public_policy, proof = community.timeline.get_resolution_policy(meta, community.global_time + 1)
        self.assertIsInstance(public_policy, PublicResolution)
        self.assertEqual(proof, [message])

        # NODE creates a message (should drop)
        global_time = message.distribution.global_time
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public_policy.implement()))
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            pass
        else:
            self.fail("must not accept the message")

        # NODE creates a message (should allow)
        global_time += 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public_policy.implement()))
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_change_resolution_undo(self):
        """
        Change the resolution policy from default to linear, the messages already accepted should be
        undone
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"dynamic-resolution-text")
        public = meta.resolution.policies[0]
        linear = meta.resolution.policies[1]

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # create policy change, but do not yet process
        community.update_global_time(10)
        self.assertEqual(community.global_time, 10)
        policy_linear = community.create_dynamic_settings([(meta, linear)], store=False, update=False, forward=False)
        self.assertEqual(policy_linear.distribution.global_time, 11)  # hence the policy starts at 12

        community.update_global_time(20)
        self.assertEqual(community.global_time, 20)
        policy_public = community.create_dynamic_settings([(meta, public)], store=False, update=False, forward=False)
        self.assertEqual(policy_public.distribution.global_time, 21)  # hence the policy starts at 22

        # because above policy changes were not applied (i.e. update=False) everything is still
        # PublicResolution without any proof
        for global_time in range(1, 32):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])

        # NODE creates a message (should allow)
        global_time = 25
        text_message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public.implement()))
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, text_message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        logger.debug("-- apply linear")

        # process the policy change
        node.give_message(policy_linear)

        for global_time in range(1, 12):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])
        for global_time in range(12, 32):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, LinearResolution)
            self.assertEqual([message.packet.encode("HEX") for message in proof], [policy_linear.packet.encode("HEX")])

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, text_message.distribution.global_time)).next()
        except StopIteration:
            self.fail("the message must be in the database with undone > 0")
        self.assertGreater(undone, 0)

        logger.debug("-- apply public")

        # process the policy change
        node.give_message(policy_public)

        for global_time in range(1, 12):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])
        for global_time in range(12, 22):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, LinearResolution)
            self.assertEqual([message.packet for message in proof], [policy_linear.packet])
        for global_time in range(22, 32):
            policy, proof = community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual([message.packet for message in proof], [policy_public.packet])

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, text_message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()

    @call_on_dispersy_thread
    def test_wrong_resolution(self):
        """
        For consistency we should not accept messages that have the wrong policy.

        Hence, when a message is created by a member with linear permission, but the community is
        set to public resolution, the message should NOT be accepted.
        """
        community = DebugCommunity.create_community(self._dispersy, self._my_member)
        meta = community.get_meta_message(u"dynamic-resolution-text")
        public = meta.resolution.policies[0]
        linear = meta.resolution.policies[1]

        node = DebugNode(community)
        node.init_socket()
        node.init_my_member()

        # set linear policy
        community.create_dynamic_settings([(meta, linear)])

        # give permission to node
        community.create_authorize([(self._dispersy.get_member(node.my_member.public_key), meta, u"permit")])

        # NODE creates a message (should allow, linear resolution and we have permission)
        global_time = community.global_time + 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, linear.implement()))

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # NODE creates a message (should drop because we use public resolution while linear is
        # currently configured)
        global_time = community.global_time + 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public.implement()))

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            pass
        else:
            self.fail("must NOT accept the message")

        # set public policy
        community.create_dynamic_settings([(meta, public)])

        # NODE creates a message (should allow, we use public resolution and that is the active policy)
        global_time = community.global_time + 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, public.implement()))

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # NODE creates a message (should drop because we use linear resolution while public is
        # currently configured)
        global_time = community.global_time + 1
        message = node.give_message(node.create_dynamic_resolution_text("Dprint=True", global_time, linear.implement()))

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (community.database_id, node.my_member.database_id, message.distribution.global_time)).next()
        except StopIteration:
            pass
        else:
            self.fail("must NOT accept the message")

        # cleanup
        community.create_destroy_community(u"hard-kill")
        self._dispersy.get_community(community.cid).unload_community()
