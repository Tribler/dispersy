from Member import PrivateMember
from Meta import MetaObject

class Authentication(MetaObject):
    class Implementation(MetaObject.Implementation):
        @property
        def is_signed(self):
            raise NotImplementedError()

class NoAuthentication(Authentication):
    class Implementation(Authentication.Implementation):
        @property
        def is_signed(self):
            return True

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
        def member(self):
            return self._member

        @property
        def is_signed(self):
            return self._is_signed

class MultiMemberAuthentication(Authentication):
    class Implementation(Authentication.Implementation):
        def __init__(self, meta, members, signatures=[]):
            if __debug__:
                from Member import Member
            assert isinstance(members, (tuple, list))
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
