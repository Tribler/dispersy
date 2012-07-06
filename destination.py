from meta import MetaObject
from revision import update_revision_information

# update version information directly from SVN
update_revision_information("$HeadURL$", "$Revision$")

class Destination(MetaObject):
    class Implementation(MetaObject.Implementation):
        pass

    def setup(self, message):
        """
        Setup is called after the meta message is initially created.
        """
        if __debug__:
            from message import Message
        assert isinstance(message, Message)

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
            if __debug__:
                from candidate import Candidate
            assert isinstance(candidates, tuple)
            assert len(candidates) >= 0
            assert all(isinstance(candidate, Candidate) for candidate in candidates)
            super(CandidateDestination.Implementation, self).__init__(meta)
            self._candidates = candidates

        @property
        def candidates(self):
            return self._candidates

class MemberDestination(Destination):
    """
    A destination policy where the message is sent to one or more specified Members.

    Note that the Member objects need to be translated into an address.  This is done using the
    candidates that are currently online.  As this candidate list constantly changes (random walk,
    timeout, churn, etc.) it is possible that no address can be found.  In this case the message can
    not be sent and will be silently dropped.
    """
    class Implementation(Destination.Implementation):
        def __init__(self, meta, *members):
            """
            Construct an AddressDestination.Implementation object.

            META the associated MemberDestination object.

            MEMBERS is a tuple containing one or more Member instances.  These will be used to try
            to find the destination addresses when the associated message is sent.
            """
            if __debug__:
                from member import Member
            assert len(members) >= 0
            assert all(isinstance(member, Member) for member in members)
            super(MemberDestination.Implementation, self).__init__(meta)
            self._members = members

        @property
        def members(self):
            return self._members

class CommunityDestination(Destination):
    """
    A destination policy where the message is sent to one or more community members selected from
    the current candidate list.

    At the time of sending at most NODE_COUNT addresses are obtained using
    dispersy.yield_random_candidates(...) to receive the message.
    """
    class Implementation(Destination.Implementation):
        @property
        def node_count(self):
            return self._meta._node_count

    def __init__(self, node_count):
        """
        Construct a CommunityDestination object.

        NODE_COUNT is an integer giving the number of nodes where, when the message is created, the
        message must be sent to.  These nodes are selected using the
        dispersy.yield_random_candidates(...) method.  NODE_COUNT must be zero or higher.
        """
        assert isinstance(node_count, int)
        assert node_count >= 0
        self._node_count = node_count

    @property
    def node_count(self):
        return self._node_count
