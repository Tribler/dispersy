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
        message = node.create_dynamic_resolution_text("Message #%d" % 10, 10, policy.implement())
        other.give_message(message, node)
        self.assert_is_done(message)

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

        message = node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, public_policy.implement())
        other.give_message(message, node)
        self.assert_is_stored(message)

        # NODE creates another message (should drop), linear policy in effect
        global_time += 1
        message = node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, public_policy.implement())
        other.give_message(message, node)

        self.assert_not_stored(message)

        # NODE creates another message, correct policy (should drop), no permissions
        global_time += 1
        message = node.create_dynamic_resolution_text("Message #%d" % global_time, global_time, linear_policy.implement())
        other.give_message(message, node)

        self.assert_not_stored(message)

    @call_on_dispersy_thread
    def test_change_resolution_undo(self):
        """
        Change the resolution policy from default to linear, the messages already accepted should be
        undone
        """
        def check_policy(time_low, time_high, meta, policyclass):
            for global_time in range(time_low, time_high):
                policy, _ = self._community.timeline.get_resolution_policy(meta, global_time)
                self.assertIsInstance(policy, policyclass)

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
        check_policy(1, 32, meta, PublicResolution)

        # NODE creates a message (should allow)
        tmessage = node.create_dynamic_resolution_text("Message #%d" % 25, 25, public.implement())
        other.give_message(tmessage, node)
        self.assert_is_stored(tmessage)

        # process the policy change
        other.give_message(policy_linear, node)

        check_policy(1, 12, meta, PublicResolution)
        check_policy(12, 32, meta, LinearResolution)

        # policy change should have undone the tmessage
        self.assert_is_undone(tmessage)

        # process the policy change
        other.give_message(policy_public, node)

        check_policy(1, 12, meta, PublicResolution)
        check_policy(12, 22, meta, LinearResolution)
        check_policy(22, 32, meta, PublicResolution)

        # policy change should have redone the tmessage
        self.assert_is_done(tmessage)
