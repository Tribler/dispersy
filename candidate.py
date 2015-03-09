import logging

from .member import Member, DummyMember
from .util import is_valid_address


# delay and lifetime values are chosen to ensure that a candidate will not exceed 60.0 or 30.0
# seconds.  However, taking into account round trip time and processing delay we to use smaller
# values without conflicting with the next 5.0 walk cycle.  Hence, we pick 2.5 seconds below the
# actual cutoff point.
CANDIDATE_ELIGIBLE_DELAY = 27.5
CANDIDATE_ELIGIBLE_BOOTSTRAP_DELAY = 57.5
CANDIDATE_WALK_LIFETIME = 57.5
CANDIDATE_STUMBLE_LIFETIME = 57.5
CANDIDATE_DISCOVERED_LIFETIME = 57.5
CANDIDATE_INTRO_LIFETIME = 27.5
CANDIDATE_LIFETIME = 180.0
assert isinstance(CANDIDATE_ELIGIBLE_DELAY, float)
assert isinstance(CANDIDATE_ELIGIBLE_BOOTSTRAP_DELAY, float)
assert isinstance(CANDIDATE_WALK_LIFETIME, float)
assert isinstance(CANDIDATE_STUMBLE_LIFETIME, float)
assert isinstance(CANDIDATE_DISCOVERED_LIFETIME, float)
assert isinstance(CANDIDATE_INTRO_LIFETIME, float)
assert isinstance(CANDIDATE_LIFETIME, float)


class Candidate(object):

    def __init__(self, sock_addr, tunnel):
        assert self.is_valid_address(sock_addr), sock_addr
        assert isinstance(tunnel, bool), type(tunnel)
        super(Candidate, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self._sock_addr = sock_addr
        self._tunnel = tunnel

        # Member instances that this Candidate is associated with
        self._association = None

    def is_valid_address(self, address):
        return is_valid_address(address)

    @property
    def sock_addr(self):
        return self._sock_addr

    @property
    def tunnel(self):
        return self._tunnel

    def associate(self, member):
        """
        Once it is confirmed that the candidate is represented by a member,
        the member can be associated with the candidate.
        """
        assert isinstance(member, Member), member
        self._association = member

    def is_associated(self, member):
        """
        Check if the member is associated with this candidate.
        """
        assert isinstance(member, DummyMember), member
        return self._association == member

    def disassociate(self, member):
        """
        Remove the association with a member.
        """
        assert isinstance(member, Member), member
        if self._association == member:
            self._association = None

    def get_member(self):
        """
        Returns the Member associated to this candidate.
        """
        return self._association

    def __str__(self):
        return "{%s:%d}" % self._sock_addr

    def __eq__(self, other):
        """
        True when OTHER is a Candidate instance and self.sock_addr == other.sock_addr, otherwise
        False.
        """
        if isinstance(other, Candidate):
            if self._association and other.get_member():
                return self._association.mid == other.get_member().mid
            return self._sock_addr == other.sock_addr
        return False

    def __ne__(self, other):
        """
        False when OTHER is a Candidate instance and self.sock_addr == other.sock_addr, otherwise
        True.
        """
        return not (isinstance(other, Candidate) and self._sock_addr == other.sock_addr)

    def __hash__(self):
        return hash(str(self._sock_addr))


class WalkCandidate(Candidate):

    """
    A Candidate instance represents a communication endpoint with one or more member/community
    pairs.

    A WalkCandidate is added and removed by the Dispersy random walker when events occur.  These
    events results in the following marks:

    - WALK: we sent an introduction-request.  Viable up to CANDIDATE_WALK_LIFETIME seconds after the
      message was sent.

    - STUMBLE: we received an introduction-request.  Viable up to CANDIDATE_STUMBLE_LIFETIME seconds
      after the message was received.

    - INTRO: we know about this candidate through hearsay.  Viable up to CANDIDATE_INACTIVE seconds
      after the introduction-response message (talking about the candidate) was received.
    """

    def __init__(self, sock_addr, tunnel, lan_address, wan_address, connection_type):
        assert is_valid_address(sock_addr), sock_addr
        assert isinstance(tunnel, bool), type(tunnel)
        assert is_valid_address(lan_address), lan_address
        assert is_valid_address(wan_address) or wan_address == ('0.0.0.0', 0), wan_address
        assert isinstance(connection_type, unicode) and connection_type in (u"unknown", u"public", u"symmetric-NAT")

        super(WalkCandidate, self).__init__(sock_addr, tunnel)
        self._lan_address = lan_address
        self._wan_address = wan_address
        self._connection_type = connection_type

        # properties to determine the category
        self._last_walk_reply = 0.0
        self._last_walk = 0.0
        self._last_stumble = 0.0
        self._last_intro = 0.0
        self._last_discovered = 0.0

        # the highest global time that one of the walks reported from this Candidate
        self._global_time = 0

        if __debug__:
            if not (self.sock_addr == self._lan_address or self.sock_addr == self._wan_address):
                self._logger.error("Either LAN %s or the WAN %s should be SOCK_ADDR %s",
                                   self._lan_address, self._wan_address, self.sock_addr)
                assert False

    @property
    def lan_address(self):
        return self._lan_address

    @property
    def wan_address(self):
        return self._wan_address

    @property
    def connection_type(self):
        return self._connection_type

    def merge(self, other):
        if other.get_member():
            self._association = other.get_member()

        if isinstance(other, WalkCandidate):
            self._last_walk_reply = max(self._last_walk_reply, other._last_walk_reply)
            self._last_walk = max(self._last_walk, other._last_walk)
            self._last_stumble = max(self._last_stumble, other._last_stumble)
            self._last_intro = max(self._last_intro, other._last_intro)
            self._global_time = max(self._global_time, other._global_time)

    @property
    def global_time(self):
        return self._global_time

    @global_time.setter
    def global_time(self, global_time):
        self._global_time = max(self._global_time, global_time)

    def age(self, now, category=u""):
        """
        Returns the time between NOW and the most recent walk, stumble, or intro (depending on
        CATEGORY).

        When CATEGORY is an empty string candidate.get_category(NOW) will be used to obtain it.

        For the following CATEGORY values it will return the equivalent:
        - walk :: NOW - candidate.last_walk
        - stumble :: NOW - candidate.last_stumble
        - intro :: NOW - candidate.last_intro
        - discovered :: NOW - candidate.last_discovered
        - none :: NOW - max(candidate.last_walk, candidate.last_stumble, candidate.last_intro, candidate.last_discovered)
        """
        if not category:
            category = self.get_category(now)

        mapping = {u"walk": now - self._last_walk,
                   u"stumble": now - self._last_stumble,
                   u"intro": now - self._last_intro,
                   u"discovered": now - self._last_discovered,
                   None: now - max(self._last_walk, self._last_stumble, self._last_intro, self._last_discovered)}

        return mapping[category]

    def is_eligible_for_walk(self, now):
        """
        Returns True when this candidate is eligible for taking a step.

        A candidate is eligible when:
        - SELF is either walk, stumble, or intro; and
        - the previous step is more than CANDIDATE_ELIGIBLE_DELAY ago.
        """
        return (self._last_walk + CANDIDATE_ELIGIBLE_DELAY <= now and self.get_category(now) != u"none")

    @property
    def last_walk(self):
        return self._last_walk

    @property
    def last_stumble(self):
        return self._last_stumble

    @property
    def last_intro(self):
        return self._last_intro

    @property
    def last_discovered(self):
        return self._last_discovered

    def get_category(self, now):
        """
        Returns the category (u"walk", u"stumble", u"intro", or None) depending on the current
        time NOW.
        """
        assert isinstance(now, float), type(now)

        if now < self._last_walk_reply + CANDIDATE_WALK_LIFETIME:
            assert self._association, "a candidate in the walk category must have at least one associated member"
            return u"walk"

        if now < self._last_stumble + CANDIDATE_STUMBLE_LIFETIME:
            assert self._association, "a candidate in the stumble category must have at least one associated member"
            return u"stumble"

        if now < self._last_intro + CANDIDATE_INTRO_LIFETIME:
            return u"intro"

        if now < self._last_discovered + CANDIDATE_DISCOVERED_LIFETIME:
            return u"discovered"

        return None

    def walk(self, now):
        """
        Called when we are about to send an introduction-request to this candidate.
        """
        assert isinstance(now, float), type(now)
        self._last_walk = now

    def walk_response(self, now):
        """
        Called when we received an introduction-response to this candidate.
        """
        assert isinstance(now, float), type(now)
        assert now == -1.0 or self._last_walk_reply <= now, self._last_walk_reply
        self._last_walk_reply = now

    def stumble(self, now):
        """
        Called when we receive an introduction-request from this candidate.
        """
        assert isinstance(now, float), type(now)
        self._last_stumble = now

    def intro(self, now):
        """
        Called when we receive an introduction-response introducing this candidate.
        """
        assert isinstance(now, float), type(now)
        self._last_intro = now

    def discovered(self, now):
        """
        Called when we discovered this candidate in the DiscoveryCommunity.
        """
        assert isinstance(now, float), type(now)
        self._last_discovered = now

    def update(self, tunnel, lan_address, wan_address, connection_type):
        assert isinstance(tunnel, bool), tunnel
        assert lan_address == ("0.0.0.0", 0) or is_valid_address(lan_address), lan_address
        assert wan_address == ("0.0.0.0", 0) or is_valid_address(wan_address), wan_address
        assert isinstance(connection_type, unicode), type(connection_type)
        assert connection_type in (u"unknown", u"public", "symmetric-NAT"), connection_type
        self._tunnel = tunnel
        if lan_address != ("0.0.0.0", 0):
            self._lan_address = lan_address
        if wan_address != ("0.0.0.0", 0):
            self._wan_address = wan_address
        # someone can also reset from a known connection_type to unknown (i.e. it now believes it is
        # no longer public nor symmetric NAT)
        self._connection_type = u"public" if connection_type == u"unknown" and lan_address == wan_address else connection_type

        if __debug__:
            if not (self.sock_addr == self._lan_address or self.sock_addr == self._wan_address):
                self._logger.error("Either LAN %s or the WAN %s should be SOCK_ADDR %s", self._lan_address, self._wan_address, self.sock_addr)

    def __str__(self):
        if self._sock_addr == self._lan_address == self._wan_address:
            return "{%s:%d}" % self._lan_address
        elif self._sock_addr in (self._lan_address, self._wan_address):
            return "{%s:%d %s:%d}" % (self._lan_address[0], self._lan_address[1], self._wan_address[0], self._wan_address[1])
        else:
            # should not occur
            return "{%s:%d %s:%d %s:%d}" % (self._sock_addr[0], self._sock_addr[1], self._lan_address[0], self._lan_address[1], self._wan_address[0], self._wan_address[1])


class LoopbackCandidate(Candidate):
    __loopback_sock_addr = ("localhost", 0)
    def __init__(self):
        super(LoopbackCandidate, self).__init__(self.__loopback_sock_addr, False)

    def is_valid_address(self, address):
        return address == self.__loopback_sock_addr
