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
        def __init__(self, meta, members, are_signed=[]):
            if __debug__:
                from Member import Member
            assert isinstance(members, (tuple, list))
            assert not filter(lambda x: not isinstance(x, Member), members)
            assert isinstance(are_signed, (tuple, list))
            assert not filter(lambda x: not isinstance(x, bool), are_signed)
            assert len(members) == meta._count
            super(MultiMemberAuthentication.Implementation, self).__init__(meta)
            self._members = members

            if are_signed:
                assert len(are_signed) == meta._count
                self._are_signed = are_signed
            else:
                self._are_signed = [isinstance(member, PrivateMember) for member in members]

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
            return zip(self._are_signed, self._members)

        @property
        def is_signed(self):
            return all(self._are_signed)

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
