from Meta import MetaObject

class Destination(MetaObject):
    class Implementation(MetaObject.Implementation):
        pass
    
# class NoDestination(Destination):
#     """
#     The message does not contain any destination.
#     """
#     class Implementation(Destination.Implementation):
#         pass

class AddressDestination(Destination):
    """
    The message is send to the destination address.
    """
    class Implementation(Destination.Implementation):
        def __init__(self, meta, *addresses):
            assert isinstance(addresses, tuple)
            assert len(addresses) > 0
            assert not filter(lambda x: not isinstance(x, tuple), addresses)
            assert not filter(lambda x: not len(x) == 2, addresses)
            assert not filter(lambda x: not isinstance(x[0], str), addresses)
            assert not filter(lambda x: not isinstance(x[1], int), addresses)
            super(AddressDestination.Implementation, self).__init__(meta)
            # the target addresses
            self._addresses = addresses

        @property
        def addresses(self):
            return self._addresses

class MemberDestination(Destination):
    """
    The message is send to the destination Member.
    """
    class Implementation(Destination.Implementation):
        def __init__(self, meta, *members):
            if __debug__:
                from Member import Member
            assert len(members) > 0
            assert not filter(lambda x: not isinstance(x, Member), members)
            super(MemberDestination.Implementation, self).__init__(meta)
            self._members = members

        @property
        def members(self):
            return self._members

class CommunityDestination(Destination):
    """
    The message is send to one or more peers in the Community.
    """
    class Implementation(Destination.Implementation):
        pass

class SimilarityDestination(Destination):
    class Implementation(Destination.Implementation):
        pass

    # todo: add stuff like: how big is the bitstring, how many to be
    # similar, do we pretend, etc.
    pass

# class PrivilegedDestination(Destination):
#     class Implementation(Destination.Implementation):
#         pass
