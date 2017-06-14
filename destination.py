from .candidate import Candidate
from .meta import MetaObject


class Destination(MetaObject):

    class Implementation(MetaObject.Implementation):
        pass

    def setup(self, message):
        """
        Setup is called after the meta message is initially created.
        """
        from .message import Message
        assert isinstance(message, Message)

    def __str__(self):
        return "<%s>" % (self.__class__.__name__,)


class CandidateDestination(Destination):

    """
    A destination policy where the message is sent to one or more specified candidates.
    """
    class Implementation(Destination.Implementation):

        def __init__(self, meta, *candidates):
            """
            Construct a CandidateDestination.Implementation object.

            META the associated CandidateDestination object.

            CANDIDATES is a tuple containing zero or more Candidate objects.  These will contain the
            destination addresses when the associated message is sent.
            """
            assert isinstance(candidates, tuple), type(candidates)
            assert len(candidates) >= 0, len(candidates)
            assert all(isinstance(candidate, Candidate) for candidate in candidates), [type(candidate) for candidate in candidates]
            super(CandidateDestination.Implementation, self).__init__(meta)
            self._candidates = candidates

        @property
        def candidates(self):
            return self._candidates


class CommunityDestination(Destination):

    """
    A destination policy where the message is sent to one or more community members selected from
    the current candidate list.

    At the time of sending at most NODE_COUNT addresses are obtained using
    community.yield_random_candidates(...) to receive the message.
    """
    class Implementation(Destination.Implementation):

        def __init__(self, meta, *candidates, **kwargs):
            """
            Construct a CandidateDestination.Implementation object.

            META the associated CandidateDestination object.

            CANDIDATES is a tuple containing zero or more Candidate objects.  These will contain the
            destination addresses when the associated message is sent.
            """
            assert isinstance(candidates, tuple), type(candidates)
            assert len(candidates) >= 0, len(candidates)
            assert all(isinstance(candidate, Candidate) for candidate in candidates), [type(candidate) for candidate in candidates]
            super(CommunityDestination.Implementation, self).__init__(meta)
            self._candidates = candidates

        @property
        def node_count(self):
            return self._meta._node_count

        @property
        def candidates(self):
            return self._candidates

    def __init__(self, node_count):
        """
        Construct a CommunityDestination object.

        NODE_COUNT is an integer giving the number of nodes where, when the message is created, the
        message must be sent to.  These nodes are selected using the
        community.yield_random_candidates(...) method.  NODE_COUNT must be zero or higher.

        DEPTH is an integer in [0, 127] v -1, this determines the _remaining_ hop count for this message. If
        DEPTH is equal to -1, no hop depth will be used.
        """
        assert isinstance(node_count, int)
        assert node_count >= 0
        self._node_count = node_count

    @property
    def node_count(self):
        return self._node_count

    def __str__(self):
        return "<%s node_count:%d>" % (self.__class__.__name__, self._node_count)

class NHopCommunityDestination(CommunityDestination):
    """
    An extension of the default CommunityDestination which also takes a maximum number of hops for the message
    to traverse.
    """

    class Implementation(CommunityDestination.Implementation):

        def __init__(self, meta, *candidates, **kwargs):
            """
            Construct a NHopCommunityDestination.Implementation object.

            META the associated CandidateDestination object.

            CANDIDATES is a tuple containing zero or more Candidate objects.  These will contain the
            destination addresses when the associated message is sent.
            """
            super(NHopCommunityDestination.Implementation, self).__init__(meta, *candidates, **kwargs)

            if 'depth' in kwargs:
                self._depth = kwargs['depth']
            else:
                self._depth = meta.depth

        @property
        def depth(self):
            return self._depth

    def __init__(self, node_count, depth=-1):
        """
        Construct a NHopCommunityDestination object.

        NODE_COUNT is an integer giving the number of nodes where, when the message is created, the
        message must be sent to.  These nodes are selected using the
        community.yield_verified_candidates(...) method.  NODE_COUNT must be zero or higher.

        DEPTH is an integer in [0, 127] v -1, this determines the _remaining_ hop count for this message. If
        DEPTH is equal to -1, no hop depth will be used.
        """
        super(NHopCommunityDestination, self).__init__(node_count)
        self._depth = depth

    @property
    def depth(self):
        return self._depth

    def __str__(self):
        return "<%s node_count:%d, depth:%d>" % (self.__class__.__name__, self._node_count, self.depth)
