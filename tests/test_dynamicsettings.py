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
        meta = self._community.get_meta_message(u"dynamic-resolution-text")

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # check default policy
        policy, proof = self._community.timeline.get_resolution_policy(meta, self._community.global_time)
        self.assertIsInstance(policy, PublicResolution)
        self.assertEqual(proof, [])

        # NODE creates a message (should allow, because the default policy is PublicResolution)
        global_time = 10
        other.give_message(node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, policy.implement()), node)

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, global_time)).next()
            self.assertEqual(undone, 0, "must accept the message")
        except StopIteration:
            self.fail("must store the message")

    @call_on_dispersy_thread
    def test_change_resolution(self):
        """
        Change the resolution policy from default to linear.
        """
        meta = self._community.get_meta_message(u"dynamic-resolution-text")
        linear = meta.resolution.policies[1]

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # check default policy
        public_policy, _ = self._community.timeline.get_resolution_policy(meta, self._community.global_time)
        self.assertIsInstance(public_policy, PublicResolution)

        # change and check policy
        message = self._community.create_dynamic_settings([(meta, linear)])
        linear_policy, proof = self._community.timeline.get_resolution_policy(meta, self._community.global_time + 1)
        self.assertIsInstance(linear_policy, LinearResolution)
        self.assertEqual(proof, [message])

        # NODE creates a message (should allow), linear policy takes effect at globaltime + 1
        global_time = message.distribution.global_time
        other.give_message(node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, public_policy.implement()), node)
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, global_time)).next()
            self.assertEqual(undone, 0, "must accept the message")
        except StopIteration:
            self.fail("must store the message")

        # NODE creates another message (should drop), linear policy in effect
        global_time += 1
        other.give_message(node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, public_policy.implement()), node)
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, global_time)).next()
            self.fail("must not accept the message")
        except StopIteration:
            pass

        # NODE creates another message, correct policy (should drop), no permissions
        global_time += 1
        message = node.give_message(node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, linear_policy.implement()), node)
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, global_time)).next()
            self.fail("must not accept the message")
        except StopIteration:
            pass

    @call_on_dispersy_thread
    def test_change_resolution_undo(self):
        """
        Change the resolution policy from default to linear, the messages already accepted should be
        undone
        """
        meta = self._community.get_meta_message(u"dynamic-resolution-text")
        public = meta.resolution.policies[0]
        linear = meta.resolution.policies[1]

        node = DebugNode(self._community)
        node.init_socket()
        node.init_my_member()

        other = DebugNode(self._community)
        other.init_socket()
        other.init_my_member()

        # create policy change, but do not yet process
        self._community.update_global_time(10)
        self.assertEqual(self._community.global_time, 10)
        policy_linear = self._community.create_dynamic_settings([(meta, linear)], store=False, update=False, forward=False)
        self.assertEqual(policy_linear.distribution.global_time, 11)  # hence the linear policy starts at 12

        self._community.update_global_time(20)
        self.assertEqual(self._community.global_time, 20)
        policy_public = self._community.create_dynamic_settings([(meta, public)], store=False, update=False, forward=False)
        self.assertEqual(policy_public.distribution.global_time, 21)  # hence the public policy starts at 22

        # because above policy changes were not applied (i.e. update=False) everything is still
        # PublicResolution without any proof
        for global_time in range(1, 32):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])

        # NODE creates a message (should allow)
        tm_global_time = 25
        other.give_message(node.create_dynamic_resolution_text("Message #%d" % tm_global_time, tm_global_time, public.implement()), node)
        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, tm_global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must accept the message")

        # process the policy change
        other.give_message(policy_linear, node)

        for global_time in range(1, 12):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])

        for global_time in range(12, 32):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, LinearResolution)
            self.assertEqual([message.packet.encode("HEX") for message in proof], [policy_linear.packet.encode("HEX")])

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, tm_global_time)).next()
        except StopIteration:
            self.fail("the message must be in the database with undone > 0")
        self.assertGreater(undone, 0, "must be undone")

        # process the policy change
        other.give_message(policy_public, node)

        for global_time in range(1, 12):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual(proof, [])

        for global_time in range(12, 22):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, LinearResolution)
            self.assertEqual([message.packet for message in proof], [policy_linear.packet])

        for global_time in range(22, 32):
            policy, proof = self._community.timeline.get_resolution_policy(meta, global_time)
            self.assertIsInstance(policy, PublicResolution)
            self.assertEqual([message.packet for message in proof], [policy_public.packet])

        try:
            undone, = self._dispersy.database.execute(u"SELECT undone FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                                     (self._community.database_id, node.my_member.database_id, tm_global_time)).next()
        except StopIteration:
            self.fail("must accept the message")
        self.assertEqual(undone, 0, "must be redone")
