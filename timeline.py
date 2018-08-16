"""
The Timeline is an important part of Dispersy.  The Timeline can be
queried as to who had what actions at some point in time.
"""

from itertools import count, groupby
import logging

from .authentication import MemberAuthentication, DoubleMemberAuthentication
from .resolution import PublicResolution, LinearResolution, DynamicResolution


class Timeline(object):

    def __init__(self, community):
        from .community import Community
        assert isinstance(community, Community)

        super(Timeline, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        # the community that this timeline is keeping track off
        self._community = community

        # _members contains the permission grants and revokes per member
        # Member / [(global_time, {u"permission^message-name":(True/False, [Message.Implementation])})]
        self._members = {}

        # _policies contains the policies that the community is currently using (dynamic settings)
        # [(global_time, {u"resolution^message-name":(resolution-policy, [Message.Implementation])})]
        self._policies = []

    if __debug__:
        def printer(self):
            for global_time, dic in self._policies:
                self._logger.debug("policy @%d", global_time)
                for key, (policy, proofs) in dic.items():
                    self._logger.debug("policy %50s  %s based on %d proofs", key, policy, len(proofs))

            for member, lst in self._members.items():
                self._logger.debug("member %d %s", member.database_id, member.mid.encode("HEX"))
                for global_time, dic in lst:
                    self._logger.debug("member %d @%d", member.database_id, global_time)
                    for key, (allowed, proofs) in sorted(dic.items()):
                        if allowed:
                            assert all(proof.name == "dispersy-authorize" for proof in proofs)
                            self._logger.debug("member %d %50s  granted by %s",
                                               member.database_id, key,
                                               ", ".join("%d@%d" % (proof.authentication.member.database_id,
                                                                    proof.distribution.global_time)
                                                         for proof in proofs))
                        else:
                            assert all(proof.name == "dispersy-revoke" for proof in proofs)
                            self._logger.debug("member %d %50s  revoked by %s",
                                               member.database_id, key,
                                               ", ".join("%d@%d" % (proof.authentication.member.database_id,
                                                                    proof.distribution.global_time)
                                                         for proof in proofs))

    def check(self, message, permission="permit"):
        """
        Check if message is allowed.

        Returns an (allowed, proofs) tuple where allowed is either True or False and proofs is a
        list containing zero or more Message.Implementation instances that grant or revoke
        permissions.
        """
        from .message import Message
        assert isinstance(message, Message.Implementation), message
        assert isinstance(message.authentication, (MemberAuthentication.Implementation, DoubleMemberAuthentication.Implementation)), message.authentication
        assert isinstance(permission, str)
        assert permission in ("permit", "authorize", "revoke", "undo")
        if isinstance(message.authentication, MemberAuthentication.Implementation):
            # MemberAuthentication

            if message.name == "dispersy-authorize" or message.name == "dispersy-revoke":
                assert isinstance(message.resolution, PublicResolution.Implementation), message
                if __debug__:
                    self._logger.debug("collecting proof for container message %s", message.name)
                    self._logger.debug("master-member: %d; my-member: %d",
                                       message.community.master_member.database_id,
                                       message.community.my_member.database_id)
                    self.printer()

                # if one or more of the contained permission_triplets are allowed, we will allow the
                # entire message.  when the message is processed only the permission_triplets that
                # are still valid will be used
                all_allowed = []
                all_proofs = set()

                # question: is message.authentication.member allowed to authorize or revoke one or
                # more of the contained permission triplets?

                # proofs for the permission triplets in the payload
                key = lambda member_sub_message__: member_sub_message__[1]
                for sub_message, iterator in groupby(message.payload.permission_triplets, key=key):
                    permission_pairs = [(sub_message, sub_permission) for _, _, sub_permission in iterator]
                    allowed, proofs = self._check(message.authentication.member, message.distribution.global_time, sub_message.resolution, permission_pairs)
                    all_allowed.append(allowed)
                    all_proofs.update(proofs)

                if __debug__:
                    self._logger.debug("is one or more permission triplets allowed? %s.  based on %d proofs",
                                       any(all_allowed), len(all_proofs))

                return any(all_allowed), [proof for proof in all_proofs]

            elif message.name == "dispersy-undo-other":
                assert isinstance(message.resolution, LinearResolution.Implementation), message
                if __debug__:
                    self._logger.debug("collecting proof for container message dispersy-undo-other")
                    self._logger.debug("master-member: %d; my-member: %d",
                                       message.community.master_member.database_id,
                                       message.community.my_member.database_id)
                    self._logger.debug("dispersy-undo-other created by %d@%d",
                                       message.authentication.member.database_id,
                                       message.distribution.global_time)
                    self._logger.debug("            undoing message by %d@%d (%s, %s)",
                                       message.payload.member.database_id, message.payload.global_time,
                                       message.payload.packet.name, message.payload.packet.resolution)
                    self.printer()

                return self._check(message.authentication.member, message.distribution.global_time, message.resolution, [(message.payload.packet.meta, "undo")])

            else:
                return self._check(message.authentication.member, message.distribution.global_time, message.resolution, [(message.meta, permission)])
        else:
            # DoubleMemberAuthentication
            all_proofs = set()
            for member in message.authentication.members:
                allowed, proofs = self._check(member, message.distribution.global_time, message.resolution, [(message.meta, permission)])
                all_proofs.update(proofs)
                if not allowed:
                    return (False, [proof for proof in all_proofs])
            return (True, [proof for proof in all_proofs])

    def allowed(self, meta, global_time=0, permission="permit"):
        """
        Check if we are allowed to create a message.
        """
        from .message import Message
        assert isinstance(meta, Message)
        assert isinstance(global_time, int)
        assert global_time >= 0
        assert isinstance(permission, str)
        assert permission in ("permit", "authorize", "revoke", "undo")
        return self._check(self._community.my_member, global_time if global_time else self._community.global_time, meta.resolution, [(meta, permission)])

    def _check(self, member, global_time, resolution, permission_pairs):
        """
        Check is MEMBER has all of the permission pairs in PERMISSION_PAIRS at GLOBAL_TIME.

        Returns a (allowed, proofs) tuple where allowed is either True or False and proofs is a list
        containing the Message.Implementation instances grant or revoke the permissions.
        """
        from .member import Member
        from .message import Message
        assert isinstance(member, Member)
        assert isinstance(global_time, int)
        assert global_time > 0
        assert isinstance(permission_pairs, list)
        assert len(permission_pairs) > 0
        for pair in permission_pairs:
            assert isinstance(pair, tuple)
            assert len(pair) == 2
            assert isinstance(pair[0], Message), "Requires meta message"
            assert isinstance(pair[1], str)
            assert pair[1] in ("permit", "authorize", "revoke", "undo")
        assert isinstance(resolution, (PublicResolution.Implementation, LinearResolution.Implementation, DynamicResolution.Implementation, PublicResolution, LinearResolution, DynamicResolution)), resolution

        # TODO: we can make this more efficient by changing the loop a bit.  make a shallow copy of
        # the permission_pairs and remove one after another as they succeed.  key is to loop though
        # the self._members[member] once (currently looping over the timeline for every item in
        # permission_pairs).

        all_proofs = []

        for message, permission in permission_pairs:
            # the master member can do anything
            if member == self._community.master_member:
                self._logger.debug("ACCEPT time:%d user:%d -> %s^%s (master member)",
                                   global_time, member.database_id, permission, message.name)

            else:
                # dynamically set the resolution policy
                if isinstance(resolution, (DynamicResolution, DynamicResolution.Implementation)):
                    local_resolution, proofs = self.get_resolution_policy(message, global_time)
                    assert isinstance(local_resolution, (PublicResolution, LinearResolution))
                    all_proofs.extend(proofs)

                    # if not resolution.policy.meta == local_resolution:
                    # either we didn't receive an update to the dynamic policy, or the peer creating the message did not
                    # however, we cannot tell the difference -> hence we continue with our local knowledge
                    # this will result in the following:
                    #    local policy == public -> we accept the message and might be told differently lateron
                    #    local policy == linear -> we accept/reject this message and request the peer for proofs
                    # however, we might have already received those proofs, as the peer is actually behind
                    # hence we also reply with all proofs
                    resolution = local_resolution

                # everyone is allowed PublicResolution
                if isinstance(resolution, (PublicResolution, PublicResolution.Implementation)):
                    self._logger.debug("ACCEPT time:%d user:%d -> %s^%s (public resolution)",
                                       global_time, member.database_id, permission, message.name)

                # allowed LinearResolution is stored in Timeline
                elif isinstance(resolution, (LinearResolution, LinearResolution.Implementation)):
                    key = permission + "^" + message.name

                    if member in self._members:
                        iterator = reversed(self._members[member])
                        try:
                            # go backwards while time > global_time
                            while True:
                                time, permissions = next(iterator)
                                if time <= global_time:
                                    break

                            # check permissions and continue backwards in time
                            while True:
                                if key in permissions:
                                    assert isinstance(permissions[key], tuple)
                                    assert len(permissions[key]) == 2
                                    assert isinstance(permissions[key][0], bool)
                                    assert isinstance(permissions[key][1], list)
                                    assert len(permissions[key][1]) > 0
                                    assert all(isinstance(x, Message.Implementation) for x in permissions[key][1])
                                    allowed, proofs = permissions[key]

                                    if allowed:
                                        self._logger.debug("ACCEPT time:%d user:%d -> %s (authorized)",
                                                           global_time, member.database_id, key)
                                        all_proofs.extend(proofs)
                                        break
                                    else:
                                        self._logger.warning("DENIED time:%d user:%d -> %s (revoked)",
                                                             global_time, member.database_id, key)
                                        return (False, [proofs])

                                time, permissions = next(iterator)

                        except StopIteration:
                            self._logger.warning("FAIL time:%d user:%d -> %s (not authorized)",
                                                 global_time, member.database_id, key)
                            return (False, all_proofs)
                    else:
                        self._logger.warning("FAIL time:%d user:%d -> %s (no authorization)",
                                             global_time, member.database_id, key)
                        return (False, all_proofs)

                    # accept with proof
                    assert len(all_proofs) > 0

                else:
                    raise NotImplementedError("Unknown Resolution")

        return (True, all_proofs)

    def authorize(self, author, global_time, permission_triplets, proof):
        from .member import Member
        from .message import Message
        assert isinstance(author, Member)
        assert isinstance(global_time, int)
        assert global_time > 0
        assert isinstance(permission_triplets, list)
        assert len(permission_triplets) > 0
        for triplet in permission_triplets:
            assert isinstance(triplet, tuple)
            assert len(triplet) == 3
            assert isinstance(triplet[0], Member)
            assert isinstance(triplet[1], Message)
            assert isinstance(triplet[1].resolution, (PublicResolution, LinearResolution, DynamicResolution))
            assert isinstance(triplet[1].authentication, (MemberAuthentication, DoubleMemberAuthentication))
            assert isinstance(triplet[2], str)
            assert triplet[2] in ("permit", "authorize", "revoke", "undo")
        assert isinstance(proof, Message.Implementation)
        assert proof.name in ("dispersy-authorize", "dispersy-revoke", "dispersy-undo-own", "dispersy-undo-other")

        # check that AUTHOR is allowed to perform authorizations for these messages
        messages = set(message for _, message, _ in permission_triplets)
        authorize_allowed, authorize_proofs = self._check(author, global_time, LinearResolution(), [(message, "authorize") for message in messages])
        if not authorize_allowed:
            self._logger.debug("the author is NOT allowed to perform authorisations"
                               " for one or more of the given permission triplets")
            self._logger.debug("-- the author is... the master member? %s;  my member? %s",
                               author == self._community.master_member, author == self._community.my_member)
            return (False, authorize_proofs)

        for member, message, permission in permission_triplets:
            if isinstance(message.resolution, (PublicResolution, LinearResolution, DynamicResolution)):
                if not member in self._members:
                    self._members[member] = []

                key = permission + "^" + message.name

                for index, (time, permissions) in zip(count(0), self._members[member]):
                    # extend when time == global_time
                    if time == global_time:
                        if key in permissions:
                            allowed, proofs = permissions[key]
                            if allowed:
                                # multiple proofs for the same permissions at this exact time
                                self._logger.debug("AUTHORISE time:%d user:%d -> %s (extending duplicate)",
                                                   global_time, member.database_id, key)
                                proofs.append(proof)

                            else:
                                # TODO: when two authorise contradict each other on the same global
                                # time, the ordering of the packet will decide the outcome.  we need
                                # those packets!  [SELECT packet FROM sync WHERE ...]
                                raise NotImplementedError("Requires ordering by packet to resolve permission conflict")

                        else:
                            # no earlier proof on this global time
                            self._logger.debug("AUTHORISE time:%d user:%d -> %s (extending)",
                                               global_time, member.database_id, key)
                            permissions[key] = (True, [proof])
                        break

                    # insert when time > global_time
                    elif time > global_time:
                        # TODO: ensure that INDEX is correct!
                        self._logger.debug("AUTHORISE time:%d user:%d -> %s (inserting)",
                                           global_time, member.database_id, key)
                        self._members[member].insert(index, (global_time, {key: (True, [proof])}))
                        break

                    # otherwise: go forward while time < global_time

                else:
                    # we have reached the end without a BREAK: append the permission
                    self._logger.debug("AUTHORISE time:%d user:%d -> %s (appending)",
                                       global_time, member.database_id, key)
                    self._members[member].append((global_time, {key: (True, [proof])}))

            else:
                raise NotImplementedError(message.resolution)

        return (True, authorize_proofs)

    def revoke(self, author, global_time, permission_triplets, proof):
        from .member import Member
        from .message import Message
        assert isinstance(author, Member)
        assert isinstance(global_time, int)
        assert global_time > 0
        assert isinstance(permission_triplets, list)
        assert len(permission_triplets) > 0
        for triplet in permission_triplets:
            assert isinstance(triplet, tuple)
            assert len(triplet) == 3
            assert isinstance(triplet[0], Member)
            assert isinstance(triplet[1], Message)
            assert isinstance(triplet[1].resolution, (PublicResolution, LinearResolution, DynamicResolution))
            assert isinstance(triplet[1].authentication, (MemberAuthentication, DoubleMemberAuthentication))
            assert isinstance(triplet[2], str)
            assert triplet[2] in ("permit", "authorize", "revoke", "undo")
        assert isinstance(proof, Message.Implementation)
        assert proof.name in ("dispersy-authorize", "dispersy-revoke", "dispersy-undo-own", "dispersy-undo-other")

        # TODO: we must remove duplicates in the below permission_pairs list
        # check that AUTHOR is allowed to perform these authorizations
        revoke_allowed, revoke_proofs = self._check(author, global_time, LinearResolution(), [(message, "revoke") for _, message, __ in permission_triplets])
        if not revoke_allowed:
            self._logger.debug("the author is NOT allowed to perform authorizations"
                               " for one or more of the given permission triplets")
            self._logger.debug("-- the author is... the master member? %s;  my member? %s",
                               author == self._community.master_member, author == self._community.my_member)
            return (False, revoke_proofs)

        for member, message, permission in permission_triplets:
            if isinstance(message.resolution, (PublicResolution, LinearResolution, DynamicResolution)):
                if not member in self._members:
                    self._members[member] = []

                key = permission + "^" + message.name

                for index, (time, permissions) in zip(count(0), self._members[member]):
                    # extend when time == global_time
                    if time == global_time:
                        if key in permissions:
                            allowed, proofs = permissions[key]
                            if allowed:
                                # TODO: when two authorize contradict each other on the same global
                                # time, the ordering of the packet will decide the outcome.  we need
                                # those packets!  [SELECT packet FROM sync WHERE ...]
                                raise NotImplementedError("Requires ordering by packet to resolve permission conflict")

                            else:
                                # multiple proofs for the same permissions at this exact time
                                self._logger.debug("REVOKE time:%d user:%d -> %s (extending duplicate)",
                                                   global_time, member.database_id, key)
                                proofs.append(proof)

                        else:
                            # no earlier proof on this global time
                            self._logger.debug("REVOKE time:%d user:%d -> %s (extending)",
                                               global_time, member.database_id, key)
                            permissions[key] = (False, [proof])
                        break

                    # insert when time > global_time
                    elif time > global_time:
                        # TODO: ensure that INDEX is correct!
                        self._logger.debug("REVOKE time:%d user:%d -> %s (inserting)",
                                           global_time, member.database_id, key)
                        self._members[member].insert(index, (global_time, {key: (False, [proof])}))
                        break

                    # otherwise: go forward while time < global_time

                else:
                    # we have reached the end without a BREAK: append the permission
                    self._logger.debug("REVOKE time:%d user:%d -> %s (appending)",
                                       global_time, member.database_id, key)
                    self._members[member].append((global_time, {key: (False, [proof])}))

            else:
                raise NotImplementedError(message.resolution)

        return (True, revoke_proofs)

    def get_resolution_policy(self, message, global_time):
        """
        Returns the resolution policy and associated proof that is used for MESSAGE at time
        GLOBAL_TIME.
        """
        from .message import Message
        assert isinstance(message, Message)
        assert isinstance(global_time, int)

        key = "resolution^" + message.name
        for policy_time, policies in reversed(self._policies):
            if policy_time < global_time and key in policies:
                self._logger.debug("using %s for time %d (configured at %s)",
                                   policies[key][0].__class__.__name__, global_time, policy_time)
                return policies[key]

        self._logger.debug("using %s for time %d (default)", message.resolution.default.__class__.__name__, global_time)
        return message.resolution.default, []

    def change_resolution_policy(self, message, global_time, policy, proof):
        from .message import Message
        assert isinstance(message, Message)
        assert isinstance(global_time, int)
        assert isinstance(policy, (PublicResolution, LinearResolution))
        assert isinstance(proof, Message.Implementation)

        for policy_time, policies in reversed(self._policies):
            if policy_time == global_time:
                break
        else:
            policies = {}
            self._policies.append((global_time, policies))
            self._policies.sort()

        # TODO it is possible that different members set different policies at the same time
        policies["resolution^" + message.name] = (policy, [proof])
