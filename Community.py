from .Conversion import Conversion
from .Member import Member

class Community(object):
    """
    The Community module manages the participation and the reconstruction
    of the current state of a distributed community.
    """
    
    def __init__(self, cid, member, conversions):
        """
        CID is the community identifier.
        MEMBER is the person participating in the community.
        CONVERSIONS is a list of available Conversion instances.
        """
        assert isinstance(cid, str)
        assert len(cid) == 20
        assert isinstance(member, Member)
        assert isinstance(conversions, (tuple, list))
        assert not filter(lambda x:isinstance(x, Conversion), conversions)

        # community identifier
        self._cid = cid

        # the person participating in the community
        self._member = member

        # dictionary containing available conversions
        self._conversions = conversions

    def get_cid(self):
        return self._cid

    def get_member(self, public_key=None):
        """
        Returns a Member instance associated with PUBLIC_KEY.  When
        PUBLIC_KEY is None our own Member instance is returned.

        When no member associated with PUBLIC_KEY is found, a new
        Member instance is returned without any permissions.
        """
        if public_key is None:
            return self._member

        else:
            pass
        
    def get_permission(self, public_key):
        pass

    def on_incoming_packets(self, packets):
        pass

