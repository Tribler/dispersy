from .Permission import AuthorizePermission, RevokePermission, GrantPermission
from .Community import Community
from .Encoding import encode, decode
from .Message import Message

def sign(key, value):
    """
    Sign VALUE using KEY.  Returns a binary string.
    """
    # todo!
    return encode(value)

def verify(key, value):
    """
    Verify that VALUE was signed with KEY.  Returns decrypted VALUE or
    raises ValueError.
    """
    # todo!
    return decode(value)

class Conversion(object):
    """
    A Conversion object is used to convert incoming packets to a
    different, often more recent, community version.  If also allows
    outgoing messages to be converted to a different, often older,
    community version.
    """ 
    RUNNING_VID = "00001"
    assert isinstance(CURRENT_VID, str)
    assert len(CURRENT_VID) == 5
    
    def __init__(self, community, vid):
        """
        COMMUNITY instance that this conversion belongs to.
        VID is the conversion identifyer (on the wire version).
        """
        assert isinstance(community, Community)
        assert isinstance(vid, str)
        assert len(vid) == 5

        # the community that this conversion belongs to.
        self._community = community

        # the messages that this instance can handle, and that this
        # instance produces, is identified by _prefix.
        self._prefix = community.get_cid() + vid

    def get_community(self):
        return self._community

    def get_vid(self):
        return self._prefix[20:25]

    def decode_packet(self, data):
        """
        DATA is a string, where the first 20 bytes indicate the CID
        and the rest forms a CID dependent message payload.
        
        Returns a Message instance.
        """
        assert isinstance(data, str)
        assert len(data) >= 20
        assert data[:25] == self._prefix
        raise NotImplemented

    def encode_packet(self, message):
        """
        Encode a Message instance into a binary string.
        """
        assert isinstance(message, Message)
        raise NotImplemented

class Conversion00001(Conversion):
    """
    On-The-Wire version 00001.
    """
    def __init__(self, cid):
        Conversion.__init__(self, cid, "00001")
    
    def decode_packet(self, data):
        """
        Convert version 00001 DATA into an internal data structure.
        """
        assert isinstance(data, str)
        assert len(data) >= 20
        assert data[:25] == self._prefix

        # data[25:] == encode([public_key, signed_container])
        payload = decode(data, 25)
        if not isinstance(payload, list):
            raise ValueError
        if not len(payload) == 2:
            raise ValueError

        public_key = payload[0]
        if not isinstance(public_key, str):
            raise ValueError

        signed_container = payload[2]
        if not isinstance(signed_container, str):
            raise ValueError

        # signed_container == private_key.sign(encode([global_counter, local_counter, in_state, embedded_public_key, encoded_action_i, ..., encoded_action_n]))
        type_, container = decode(verify(public_key, signed_container))
        if not isinstance(container, list):
            raise ValueError
        if not len(container) > 4:
            raise ValueError

        global_counter = container[0]
        if not isinstance(global_counter, (int, long)):
            raise ValueError

        local_counter = container[1]
        if not isinstance(local_counter, (int, long)):
            raise ValueError

        in_state = container[2]
        if not isinstance(in_state, bool):
            raise ValueError

        embedded_public_key = container[3]
        if not isinstance(embedded_public_key, str):
            raise ValueError
        if not embedded_public_key == public_key:
            raise ValueError # SECURITY VIOLATION!

        actions = []

        # container[3:] == [encoded_action_i, ..., encoded_action_n]
        for encoded_action in container[3:]:

            # encoded_action == encode([action_key, signed_action])
            decoded_action = decode(encoded_action)
            if not isinstance(decoded_action, list):
                raise ValueError
            if not len(decoded_action) == 2:
                raise ValueError
            
            action_key = decoded_action[0]
            if not isinstance(action_key, str):
                raise ValueError

            signed_action = decoded_action[1]
            if not isinstance(signed_action, str):
                raise ValueError

            permission = self._community.get_permission(action_key)
            assert isinstance(permission, (AuthorizePermission, RevokePermission, GrantPermission))

            action_data = permission.verify(signed_action)
            assert isinstance(action_data, str)

            if isinstance(permission, AuthorizePermission):
                container = decode(action_data)
                if not isinstance(container, list):
                    raise ValueError
                if not len(container) > 1:
                    raise ValueError

                # action[0] is the target user's public key
                # action[1:] are the permissions that this user is given
                if filter(lambda x: isinstance(x, str), action):
                    raise ValueError

                permissions = [self._community.get_permission(key) for key in container[1:]]
                actions.append(AuthorizeAction(permission, User(action[0]), permissions))

                # todo
                # 1. check that action[1:] are subsets of permission
                # 2. send to state change to community

            elif isinstance(permission, RevokePermission):
                container = decode(action_data)
                if not isinstance(container, list):
                    raise ValueError
                if not len(container) > 1:
                    raise ValueError

                # action[0] is the target user's public key
                # action[1:] are the permissions that are revoked
                if filter(lambda x: isinstance(x, str), action):
                    raise ValueError

                permissions = [self._community.get_permission(key) for key in container[1:]]
                actions.append(RevokeAction(permission, User(action[0]), permissions))

                # todo
                # 1. check that action[1:] are subsets of permission
                # 2. send to state change to community
                
            elif isinstance(permission, GrantPermission):
                actions.append(GrantAction(permission, action_data))

        message = Message()
        message.cid = self._community.get_cid()
        message.signed_by = public_key
        message.global_counter = global_counter
        message.local_counter = local_counter
        message.in_state = in_state
        message.actions = actions
                                    
        return message

    def encode_packet(self, message):
        def encode_action(self, action):
            assert isinstance(action, Action)
            if isinstance(action, AuthorizeAction):
                permission = action.get_permission()
                return encode((permission.get_key(), permission.sign(encode([action.get_user().get_key()] + [permission.get_key() for permission in action.get_permissions()]))))

        assert isinstance(message, Message)
        container = [message.global_couner, message.local_counter, message.in_state]
        container.extend([encode_action(action) for action in message.get_actions()])

        member = self._community.get_member()
        return self._prefix + encode((member.get_key(), member.sign(encode(container))))
    
        
