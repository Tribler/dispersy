class DestinationBase(object):
    class Implementation(object):
        def __init__(self, meta):
            assert isinstance(meta, DestinationBase)
            # the associated destination
            self._meta = meta

        @property
        def meta(self):
            return self._meta

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__}>".format(self)

    def __str__(self):
        return "<{0.__class__.__name__}>".format(self)

    def implement(self, *args, **kargs):
        return self.Implementation(self, *args, **kargs)

# class UserDestination(DestinationBase):
#     """
#     Send the message to the target user.
#     """
#     class Implementation(DestinationBase.Implementation):
#         pass

class AddressDestination(DestinationBase):
    """
    Send the message to an IP:port tuple.
    """
    class Implementation(DestinationBase.Implementation):
        def __init__(self, meta, address):
            assert isinstance(address, tuple)
            assert len(address) == 2
            assert isinstance(address[0], str)
            assert isinstance(address[1], int)
            super(AddressDestination.Implementation, self).__init__(meta)
            # the target address
            self._address = address

        @property
        def address(self):
            return self._address

        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__} address:{0.address[0]}:{0.address[1]}>".format(self)

class MemberDestination(DestinationBase):
    """
    Send the message to the target member.
    """
    class Implementation(DestinationBase.Implementation):
        pass

class CommunityDestination(DestinationBase):
    """
    Send the message some one or more peers in the Community.
    """
    class Implementation(DestinationBase.Implementation):
        pass

class PrivilegedDestination(DestinationBase):
    class Implementation(DestinationBase.Implementation):
        pass


