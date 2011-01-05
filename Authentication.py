from Member import PrivateMember
from Meta import MetaObject

class Authentication(MetaObject):
    class Implementation(MetaObject.Implementation):
        @property
        def is_signed(self):
            raise NotImplementedError()

        @property
        def footprint(self):
            return "Authentication"

    def setup(self, message):
        """
        Setup is called after the meta message is initially created.
        """
        if __debug__:
            from Message import Message
        assert isinstance(message, Message)

    def generate_footprint(self):
        return "Authentication"

class NoAuthentication(Authentication):
    class Implementation(Authentication.Implementation):
        @property
        def is_signed(self):
            return True

        @property
        def footprint(self):
            return "NoAuthentication"

    def generate_footprint(self):
        return "NoAuthentication"

class MemberAuthentication(Authentication):
    class Implementation(Authentication.Implementation):
        def __init__(self, meta, member, is_signed=False):
            if __debug__:
                from Member import Member
            assert isinstance(member, Member)
            assert isinstance(is_signed, bool)
            super(MemberAuthentication.Implementation, self).__init__(meta)
            self._member = member
            self._is_signed = is_signed

        @property
        def encoding(self):
            return self._meta._encoding

        @property
        def member(self):
            return self._member

        @property
        def is_signed(self):
            return self._is_signed

        @property
        def footprint(self):
            return "MemberAuthentication:" + self._member.mid.encode("HEX")

    def __init__(self, encoding="sha1"):
        assert isinstance(encoding, str)
        assert encoding in ("pem", "sha1")
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding

    def generate_footprint(self, mids):
        assert isinstance(mids, (tuple, list))
        assert not filter(lambda x: not isinstance(x, str), mids)
        assert not filter(lambda x: not len(x) == 20, mids)
        return "MemberAuthentication:(" + "|".join([mid.encode("HEX") for mid in mids]) + ")"

class MultiMemberAuthentication(Authentication):
    class Implementation(Authentication.Implementation):
        def __init__(self, meta, members, signatures=[]):
            if __debug__:
                from Member import Member
            assert isinstance(members, (tuple, list)), type(members)
            assert not filter(lambda x: not isinstance(x, Member), members)
            assert len(members) == meta._count
            assert isinstance(signatures, list)
            assert not filter(lambda x: not isinstance(x, str), signatures)
            assert not signatures or len(signatures) == meta._count
            super(MultiMemberAuthentication.Implementation, self).__init__(meta)
            self._members = members

            # will contain the list of signatures as they are received
            # from dispersy-signature-response messages
            if signatures:
                self._signatures = signatures
            else:
                self._signatures = [""] * meta._count

        @property
        def count(self):
            return self._meta._count

        @property
        def allow_signature_func(self):
            return self._meta._allow_signature_func

        @property
        def member(self):
            """
            Returns the first member.
            """
            return self._members[0]

        @property
        def members(self):
            return self._members

        @property
        def signed_members(self):
            return zip(self._signatures, self._members)

        @property
        def is_signed(self):
            return all(self._signatures)

        def set_signature(self, member, signature):
            assert member in self._members
            self._signatures[self._members.index(member)] = signature

        @property
        def footprint(self):
            return "MultiMemberAuthentication:" + ",".join([member.mid.encode("HEX") for member in self._members])

    def __init__(self, count, allow_signature_func):
        assert isinstance(count, int)
        assert hasattr(allow_signature_func, "__call__"), "ALLOW_SIGNATURE_FUNC must be callable"
        self._count = count
        self._allow_signature_func = allow_signature_func

    @property
    def count(self):
        return self._count

    @property
    def allow_signature_func(self):
        return self._allow_signature_func

    def generate_footprint(self, *midss):
        assert isinstance(midss, (tuple, list))
        assert len(midss) == self._count
        if __debug__:
            for mids in midss:
                assert not filter(lambda x: not isinstance(x, str), mids)
                assert not filter(lambda x: not len(x) == 20, mids)
        return "MultiMemberAuthentication:" + ",".join(["(" + "|".join([mid.encode("HEX") for mid in mids]) + ")" for mids in midss])
