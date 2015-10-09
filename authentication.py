"""
This module provides the Authentication policy.

Each Dispersy message that is send has an Authentication policy associated to it.  This policy
dictates how the message is authenticated, i.e. how the message is associated to the sender or
creator of this message.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from abc import ABCMeta, abstractproperty
from .meta import MetaObject


class Authentication(MetaObject):

    """
    The Authentication baseclass.
    """

    class Implementation(MetaObject.Implementation):

        """
        The implementation of an Authentication policy.
        """

        __metaclass__ = ABCMeta

        @abstractproperty
        def is_signed(self):
            """
            True when the message is (correctly) signed, False otherwise.
            @rtype: bool
            """
            pass

        def setup(self, message_impl):
            from .message import Message
            assert isinstance(message_impl, Message.Implementation)

    def setup(self, message):
        """
        Setup the Authentication meta part.

        Setup is called after the meta message is initially created.  This allows us to initialize
        the authentication meta part with, if required, information available to the meta message
        itself.  This gives us access to, among other, the community instance and the other meta
        policies.

        @param message: The meta message.  Note that self is message.authentication.
        @type message: Message
        """
        from .message import Message
        assert isinstance(message, Message)


class NoAuthentication(Authentication):

    """
    The NoAuthentication policy can be used when a message is not owned, i.e. signed, by anyone.

    A message that uses the no-authentication policy does not contain any identity information nor a
    signature.  This makes the message smaller --from a storage and bandwidth point of view-- and
    cheaper --from a CPU point of view-- to generate.  However, the message becomes less secure as
    everyone can generate and modify it as they please.  This makes this policy ill suited for
    gossiping purposes.
    """
    class Implementation(Authentication.Implementation):

        @property
        def is_signed(self):
            return True

        def sign(self, payload):
            return ""

        def has_valid_signature_for(self, placeholder, payload):
            return True


class MemberAuthentication(Authentication):

    """
    The MemberAuthentication policy can be used when a message is owned, i.e. signed, bye one
    member.

    A message that uses the member-authentication policy will add an identifier to the message that
    indicates the creator of the message.  This identifier can be either the public key or the sha1
    digest of the public key.  The former is relatively large but uniquely identifies the member,
    while the latter is relatively small but might not uniquely identify the member, although, this
    will uniquely identify the member when combined with the signature.

    Furthermore, a signature over the entire message is appended to ensure that no one else can
    modify the message or impersonate the creator.  Using the default curve, NID-sect233k1, each
    signature will be 58 bytes long.

    The member-authentication policy is used to sign a message, associating it to a specific member.
    This lies at the foundation of Dispersy where specific members are permitted specific actions.
    Furthermore, permissions can only be obtained by having another member, who is allowed to do so,
    give you this permission in the form of a signed message.
    """
    class Implementation(Authentication.Implementation):

        def __init__(self, meta, member, signature=""):
            """
            Initialize a new MemberAuthentication.Implementation instance.

            This method should only be called through the MemberAuthentication.implement(member,
            is_signed) method.

            @param meta: The MemberAuthentication instance
            @type meta: MemberAuthentication

            @param member: The member that will own, i.e. sign, this message.
            @type member: Member
            
            @param signature: The signature used to sign this message
            @type signature: string
            """
            from .member import Member
            assert isinstance(member, Member)
            assert isinstance(signature, str)
            super(MemberAuthentication.Implementation, self).__init__(meta)
            self._member = member
            self._signature = signature

        @property
        def encoding(self):
            """
            How the member identifier is encoded (public key or sha1-digest over public key).
            @rtype: string
            @note: This property is obtained from the meta object.
            """
            return self._meta._encoding

        @property
        def member(self):
            """
            The owner of the message.
            @rtype: Member
            """
            return self._member

        def is_signed(self):
            return bool(self._signature)

        def sign(self, payload):
            if self._is_sig_empty():
                self._signature = self._member.sign(payload)
            return self._signature

        def has_valid_signature_for(self, placeholder, payload):
            if placeholder.allow_empty_signature and self._is_sig_empty():
                return True
            return self._member.verify(payload, self._signature)

        def _is_sig_empty(self):
            return self._signature == "" or self._signature == "\x00" * self._member.signature_length


    def __init__(self, encoding="default"):
        """
        Initialize a new MemberAuthentication instance.

        Depending on the encoding parameter the member is identified in a different way.  The
        options below are available:

         - sha1: where the public key of the member is made into a 20 byte sha1 digest and added to
           the message.

         - bin: where the public key of the member is added to the message, prefixed with its
           length.

        Obviously sha1 results in smaller messages with the disadvantage that the same sha1 digest
        could be mapped to multiple members.  Retrieving the correct member from the sha1 digest is
        handled by dispersy when an incoming message is decoded.

        @param encoding: How the member identifier is encoded (bin or sha1)
        @type encoding: string
        """
        assert isinstance(encoding, str)
        assert encoding in ("default", "bin", "sha1")
        super(MemberAuthentication, self).__init__()
        self._encoding = encoding

    @property
    def encoding(self):
        """
        How the member identifier is encoded (bin or sha1).
        @rtype: string
        """
        return self._encoding


class DoubleMemberAuthentication(Authentication):

    """
    The DoubleMemberAuthentication policy can be used when a message needs to be signed by two
    members.

    A message that uses the double-member-authentication policy is signed by two member.  Similar to
    the member-authentication policy the message contains two identifiers where the first indicates
    the creator and the second indicates the members that added her signature.

    Dispersy is responsible for obtaining the signatures of the different members and handles this
    using the messages dispersy-signature-request and dispersy-signature-response, defined below.
    Creating a double signed message is performed using the following steps: first Alice creates a
    message (M) where M uses the double-member-authentication policy.  At this point M consists of
    the community identifier, the conversion identifier, the message identifier, the member
    identifier for both Alice and Bob, optional resolution information, optional distribution
    information, optional destination information, the message payload, and \0 bytes for the two
    signatures.

    Message M is then wrapped inside a dispersy-signature-request message (R) and send to Bob.  When
    Bob receives this request he can optionally apply changes to M2 and add his signature.  Assuming
    that he does the new message M2, which now includes Bob's signature while Alice's is still \0,
    is wrapped in a dispersy-signature-response message (E) and sent back to Alice.  If Alice agrees
    with the (possible) changes in M2 she can add her own signature and M2 is stored, updated, and
    forwarded to other nodes in the community.
    """
    class Implementation(Authentication.Implementation):

        def __init__(self, meta, members, signatures=[]):
            """
            Initialize a new DoubleMemberAuthentication.Implementation instance.

            This method should only be called through the MemberAuthentication.implement(members,
            signatures) method.

            @param members: The members that will need to sign this message, in this order.  The
             first member will considered the owner of the message.
            @type members: list containing Member instances

            @param signatures: The available, and verified, signatures for each member.  Should only
             be given when decoding a message.
            @type signatures: list containing strings
            """
            from .member import Member
            assert isinstance(members, list), type(members)
            assert len(members) == 2
            assert all(isinstance(member, Member) for member in members)
            assert isinstance(signatures, list)
            assert all(isinstance(signature, str) for signature in signatures)
            assert len(signatures) == 0 or len(signatures) == 2
            super(DoubleMemberAuthentication.Implementation, self).__init__(meta)
            self._members = members

            # will contain the list of signatures as they are received
            # from dispersy-signature-response messages
            if signatures:
                self._signatures = signatures
            else:
                self._signatures = ["", ""]

        @property
        def allow_signature_func(self):
            """
            The function that is called whenever a dispersy-signature-request is received.
            @rtype: callable function
            @note: This property is obtained from the meta object.
            """
            return self._meta.allow_signature_func

        @property
        def encoding(self):
            """
            How the member identifier is encoded (public key or sha1-digest over public key).
            @rtype: string
            @note: This property is obtained from the meta object.
            """
            return self._meta._encoding

        @property
        def member(self):
            """
            The message owner, i.e. the first member in self.members.
            @rtype: Member
            @note: This property is obtained from the meta object.
            """
            return self._members[0]

        @property
        def members(self):
            """
            The members that sign, of should sign, the message.
            @rtype: list or tuple containing Member instances
            """
            return self._members

        @property
        def signatures(self):
            """
            The signatures of the message that have been signed, or if missing "".
            @rtype: list or tuple containing String instances
            """
            return self._signatures

        @property
        def signed_members(self):
            """
            The members and their signatures.

            The signed members can be used to see from what members we have a valid signature.  A
            list is given with (signature, Member) tuples, where the signature is either a verified
            signature or an empty string.

            @rtype: list containing (string, Member) tuples
            """
            return [(signature if not self._is_sig_empty(signature, member) else '', member) for signature, member in zip(self._signatures, self._members)]

        @property
        def is_signed(self):
            return all(not self._is_sig_empty(signature, member) for signature, member in zip(self._signatures, self._members))

        def sign(self, payload):
            payloads = self._meta.split_payload_func(payload)
            for i, signature in enumerate(self._signatures):
                if self._is_sig_empty(signature, self._members[i]):
                    if self._members[i].private_key:
                        self._signatures[i] = self._members[i].sign(payloads[i])
                    else:
                        self._signatures[i] = "\x00" * self._members[i].signature_length
            return "".join(self._signatures)

        def has_valid_signature_for(self, placeholder, payload):
            payloads = self._meta.split_payload_func(payload)
            for signature, member, payload in zip(self._signatures, self._members, payloads):
                if self._is_sig_empty(signature, member):
                    if not placeholder.allow_empty_signature:
                        return False
                elif not member.verify(payload, signature):
                    return False
            return True

        def _is_sig_empty(self, signature, member):
            return signature == "" or signature == "\x00" * member.signature_length


    def __init__(self, allow_signature_func, split_payload_func=None, encoding="default"):
        """
        Initialize a new DoubleMemberAuthentication instance.

        When someone wants to create a double signed message, the Community.create_signature_request
        method can be used.  This will send dispersy-signature-request messages to all Members that
        have not yet signed and will wait until replies are received, or a timeout occurs.

        When a member receives a request to add her signature to a message, the allow_signature_func
        function is called.  We will only add our signature if the allow_signature_func method returns
        the same, or a modified sub-message.  If so, a dispersy-signature-response message is send to
        the creator  of the message, the first one in the authentication list.

        @param allow_signature_func: The function that is called when a signature request is
         received. Must return a Message to add a signature, or None to ignore the request.
        @type allow_signature_func: callable function
        
        @param split_payload_func: The function that is called when a payload needs to be split
        in order to verify the signature on parts of the payload.
        @type split_payload_func: callable function
        """
        assert hasattr(allow_signature_func, "__call__"), "ALLOW_SIGNATURE_FUNC must be callable"
        assert split_payload_func is None or hasattr(allow_signature_func, "__call__"), "SPLIT_PAYLOAD_FUNC must be callable"
        assert isinstance(encoding, str)
        assert encoding in ("default", "bin", "sha1")
        super(DoubleMemberAuthentication, self).__init__()
        self._allow_signature_func = allow_signature_func

        if split_payload_func is None:
            split_payload_func = lambda payload: payload
        self._split_payload_func = split_payload_func
        self._encoding = encoding

    @property
    def allow_signature_func(self):
        """
        The function that is called when a dispersy-signature-request is received.
        @rtype: callable function
        """
        return self._allow_signature_func

    @property
    def split_payload_func(self):
        """
        The function that is called when a payload needs to be split in order to verify the 
        signature on parts of the payload
        @rtype: callable function
        """
        return self._split_payload_func

    @property
    def encoding(self):
        """
        How the member identifier is encoded (bin or sha1).
        @rtype: string
        """
        return self._encoding
