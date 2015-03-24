from .dispersytestclass import DispersyTestFunc


class TestTimeline(DispersyTestFunc):

    def test_delay_by_proof(self):
        """
        When OTHER receives a message that it has no permission for, it will send a
        dispersy-missing-proof message to try to obtain the dispersy-authorize.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # permit NODE
        proof_msg = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                    (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")])

        # NODE creates message
        tmessage = node.create_protected_full_sync_text("Protected message", 42)
        other.give_message(tmessage, node)

        # must NOT have been stored in the database
        other.assert_not_stored(tmessage)

        # OTHER sends dispersy-missing-proof to NODE
        responses = node.receive_messages()
        self.assertEqual(len(responses), 1)
        for _, message in responses:
            self.assertEqual(message.name, u"dispersy-missing-proof")
            self.assertEqual(message.payload.member.public_key, node.my_member.public_key)
            self.assertEqual(message.payload.global_time, 42)

        # NODE provides proof
        other.give_message(proof_msg, node)

        # must have been stored in the database
        other.assert_is_stored(tmessage)

    def test_missing_proof(self):
        """
        When OTHER receives a dispersy-missing-proof message it needs to find and send the proof.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # permit NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                               (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")])
        node.give_message(authorize, self._mm)

        protected_text = node.create_protected_full_sync_text("Protected message", 42)
        node.store([protected_text])

        # OTHER pretends to received the protected message and requests the proof
        node.give_message(other.create_missing_proof(node.my_member, 42), other)

        # NODE sends dispersy-authorize to OTHER
        _, authorize = other.receive_message(names=[u"dispersy-authorize"]).next()

        permission_triplet = (node.my_member.mid, u"protected-full-sync-text", u"permit")
        authorize_permission_triplets = [(triplet[0].mid, triplet[1].name, triplet[2]) for triplet in authorize.payload.permission_triplets]
        self.assertIn(permission_triplet, authorize_permission_triplets)

    def test_missing_authorize_proof(self):
        """
             MASTER
               \\        authorize(MASTER, OWNER)
                \\
                OWNER
                  \\        authorize(OWNER, NODE1)
                   \\
                   NODE1

        When NODE receives a dispersy-missing-proof message from OTHER for authorize(MM, NODE)
        the dispersy-authorize message for authorize(MASTER, MM) must be returned.
        """
        node, other = self.create_nodes(2)
        node.send_identity(other)

        # permit NODE
        authorize = self._mm.create_authorize([(node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"permit"),
                                             (node.my_member, self._community.get_meta_message(u"protected-full-sync-text"), u"authorize")])
        node.give_message(authorize, self._mm)

        # OTHER wants the proof that OWNER is allowed to grant authorization to NODE
        node.give_message(other.create_missing_proof(authorize.authentication.member, authorize.distribution.global_time), other)

        # NODE sends dispersy-authorize containing authorize(MASTER, OWNER) to OTHER
        _, authorize = other.receive_message(names=[u"dispersy-authorize"]).next()

        permission_triplet = (self._mm.my_member.mid, u"protected-full-sync-text", u"permit")
        authorize_permission_triplets = [(triplet[0].mid, triplet[1].name, triplet[2]) for triplet in authorize.payload.permission_triplets]
        self.assertIn(permission_triplet, authorize_permission_triplets)
