class DestinationBase(object):
    class Implementation(object):
        def __init__(self, meta):
            assert isinstance(meta, DestinationBase)
            # the associated destination
            self._meta = meta
            
        def __str__(self):
            return "<{0.meta.__class__.__name__}.{0.__class__.__name__}>".format(self)

    def __str__(self):
        return "<{0.__class__.__name__}>".format(self)

    def implement(self, *args, **kargs):
        return self.Implementation(self, *args, **kargs)

class UserDestination(DestinationBase):
    class Implementation(DestinationBase.Implementation):
        pass

class MemberDestination(DestinationBase):
    class Implementation(DestinationBase.Implementation):
        pass

class CommunityDestination(DestinationBase):
    class Implementation(DestinationBase.Implementation):
        pass

class PrivilegedDestination(DestinationBase):
    class Implementation(DestinationBase.Implementation):
        pass


