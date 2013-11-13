from .logger import get_logger
logger = get_logger(__name__)

if __debug__:
    from .member import Member

    def is_address(address):
        assert isinstance(address, tuple), type(address)
        assert len(address) == 2, len(address)
        assert isinstance(address[0], str), type(address[0])
        assert address[0], address[0]
        assert isinstance(address[1], int), type(address[1])
        assert address[1] >= 0, address[1]
        return True


# delay and lifetime values are chosen to ensure that a candidate will not exceed 60.0 or 30.0
# seconds.  However, taking into account round trip time and processing delay we to use smaller
# values without conflicting with the next 5.0 walk cycle.  Hence, we pick 2.5 seconds below the
# actual cutoff point.
CANDIDATE_ELIGIBLE_DELAY = 27.5
CANDIDATE_ELIGIBLE_BOOTSTRAP_DELAY = 57.5
CANDIDATE_WALK_LIFETIME = 57.5
CANDIDATE_STUMBLE_LIFETIME = 57.5
CANDIDATE_INTRO_LIFETIME = 27.5
CANDIDATE_LIFETIME = 180.0
assert isinstance(CANDIDATE_ELIGIBLE_DELAY, float)
assert isinstance(CANDIDATE_ELIGIBLE_BOOTSTRAP_DELAY, float)
assert isinstance(CANDIDATE_WALK_LIFETIME, float)
assert isinstance(CANDIDATE_STUMBLE_LIFETIME, float)
assert isinstance(CANDIDATE_INTRO_LIFETIME, float)
assert isinstance(CANDIDATE_LIFETIME, float)


class Candidate(object):

    def __init__(self, sock_addr, tunnel):
        assert is_address(sock_addr), sock_addr
        assert isinstance(tunnel, bool), type(tunnel)
        self._sock_addr = sock_addr
        self._tunnel = tunnel

    @property
    def sock_addr(self):
        return self._sock_addr

    @sock_addr.setter
    def sock_addr(self, sock_addr):
        self._sock_addr = sock_addr

    @property
    def tunnel(self):
        return self._tunnel

    def get_destination_address(self, wan_address):
        logger.debug("deprecated.  use candidate.sock_addr instead")
        return self._sock_addr

    def __str__(self):
        return "{%s:%d}" % self._sock_addr

    def __eq__(self, other):
        """
        True when OTHER is a Candidate instance and self.sock_addr == other.sock_addr, otherwise
        False.
        """
        return isinstance(other, Candidate) and self._sock_addr == other.sock_addr

    def __ne__(self, other):
        """
        False when OTHER is a Candidate instance and self.sock_addr == other.sock_addr, otherwise
        True.
        """
        return not (isinstance(other, Candidate) and self._sock_addr == other.sock_addr)


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
        assert is_address(sock_addr), sock_addr
        assert isinstance(tunnel, bool), type(tunnel)
        assert is_address(lan_address)
        assert is_address(wan_address)
        assert isinstance(connection_type, unicode) and connection_type in (u"unknown", u"public", u"symmetric-NAT")

        super(WalkCandidate, self).__init__(sock_addr, tunnel)
        self._lan_address = lan_address
        self._wan_address = wan_address
        self._connection_type = connection_type

        # Member instances that this Candidate is associated with
        self._associations = set()

        # properties to determine the category
        self._timeout_adjustment = 0.0
        self._last_walk = 0.0
        self._last_stumble = 0.0
        self._last_intro = 0.0

        # the highest global time that one of the walks reported from this Candidate
        self._global_time = 0

        if __debug__:
            if not (self.sock_addr == self._lan_address or self.sock_addr == self._wan_address):
                logger.error("Either LAN %s or the WAN %s should be SOCK_ADDR %s", self._lan_address, self._wan_address, self.sock_addr)
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
        assert isinstance(other, WalkCandidate), type(other)
        self._associations.update(other._associations)
        self._timeout_adjustment = max(self._timeout_adjustment, other._timeout_adjustment)
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

    def associate(self, member):
        """
        Once it is confirmed that the candidate is represented by a member, i.e. though a 3-way
        handshake, the member can be associated with the candidate.
        """
        assert isinstance(member, Member)
        self._associations.add(member)

    def is_associated(self, member):
        """
        Check if the member is associated with this candidate.
        """
        assert isinstance(member, Member)
        return member in self._associations

    def disassociate(self, member):
        """
        Remove the association with a member.
        """
        assert isinstance(member, Member)
        self._associations.remove(member)

    def get_members(self):
        """
        Returns all unique Member instances associated to this candidate.
        """
        return self._associations

    def is_obsolete(self, now):
        """
        Returns True if this candidate exceeded the CANDIDATE_LIFETIME.
        """
        return max(self._last_walk, self._last_stumble, self._last_intro) + CANDIDATE_LIFETIME < now

    def age(self, now, category=u""):
        """
        Returns the time between NOW and the most recent walk, stumble, or intro (depending on
        CATEGORY).

        When CATEGORY is an empty string candidate.get_category(NOW) will be used to obtain it.

        For the following CATEGORY values it will return the equivalent:
        - walk :: NOW - candidate.last_walk
        - stumble :: NOW - candidate.last_stumble
        - intro :: NOW - candidate.last_intro
        - none :: NOW - max(candidate.last_walk, candidate.last_stumble, candidate.last_intro)
        """
        if not category:
            category = self.get_category(now)

        mapping = {u"walk": now - self._last_walk,
                   u"stumble": now - self._last_stumble,
                   u"intro": now - self._last_intro,
                   u"none": now - max(self._last_walk, self._last_stumble, self._last_intro)}

        return mapping[category]

    def inactive(self, now):
        """
        Called to set this candidate to inactive.
        """
        self._last_walk = now - CANDIDATE_WALK_LIFETIME
        self._last_stumble = now - CANDIDATE_STUMBLE_LIFETIME
        self._last_intro = now - CANDIDATE_INTRO_LIFETIME

    def obsolete(self, now):
        """
        Called to set this candidate to obsolete.
        """
        self._last_walk = now - CANDIDATE_LIFETIME
        self._last_stumble = now - CANDIDATE_LIFETIME
        self._last_intro = now - CANDIDATE_LIFETIME

    def is_eligible_for_walk(self, now):
        """
        Returns True when this candidate is eligible for taking a step.

        A candidate is eligible when:
        - SELF is either walk, stumble, or intro; and
        - the previous step is more than CANDIDATE_ELIGIBLE_DELAY ago.
        """
        return (self._last_walk + CANDIDATE_ELIGIBLE_DELAY <= now and
                (self._last_walk + self._timeout_adjustment <= now < self._last_walk + CANDIDATE_WALK_LIFETIME or
                 now < self._last_stumble + CANDIDATE_STUMBLE_LIFETIME or
                 now < self._last_intro + CANDIDATE_INTRO_LIFETIME))

    @property
    def last_walk(self):
        return self._last_walk

    @property
    def last_stumble(self):
        return self._last_stumble

    @property
    def last_intro(self):
        return self._last_intro

    def get_category(self, now):
        """
        Returns the category (u"walk", u"stumble", u"intro", or u"none") depending on the current
        time NOW.
        """
        assert isinstance(now, float), type(now)

        if self._last_walk + self._timeout_adjustment <= now < self._last_walk + CANDIDATE_WALK_LIFETIME:
            return u"walk"

        if now < self._last_stumble + CANDIDATE_STUMBLE_LIFETIME:
            return u"stumble"

        if now < self._last_intro + CANDIDATE_INTRO_LIFETIME:
            return u"intro"

        return u"none"

    def walk(self, now, timeout_adjustment):
        """
        Called when we are about to send an introduction-request to this candidate.
        """
        assert isinstance(now, float), type(now)
        assert isinstance(timeout_adjustment, float), type(timeout_adjustment)
        self._last_walk = now
        self._timeout_adjustment = timeout_adjustment

    def walk_response(self):
        """
        Called when we received an introduction-response to this candidate.
        """
        self._timeout_adjustment = 0.0

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

    def update(self, tunnel, lan_address, wan_address, connection_type):
        assert isinstance(tunnel, bool)
        assert lan_address == ("0.0.0.0", 0) or is_address(lan_address), lan_address
        assert wan_address == ("0.0.0.0", 0) or is_address(wan_address), wan_address
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
                logger.error("Either LAN %s or the WAN %s should be SOCK_ADDR %s", self._lan_address, self._wan_address, self.sock_addr)

    def __str__(self):
        if self._sock_addr == self._lan_address == self._wan_address:
            return "{%s:%d}" % self._lan_address
        elif self._sock_addr in (self._lan_address, self._wan_address):
            return "{%s:%d %s:%d}" % (self._lan_address[0], self._lan_address[1], self._wan_address[0], self._wan_address[1])
        else:
            # should not occur
            return "{%s:%d %s:%d %s:%d}" % (self._sock_addr[0], self._sock_addr[1], self._lan_address[0], self._lan_address[1], self._wan_address[0], self._wan_address[1])


class BootstrapCandidate(WalkCandidate):

    def __init__(self, sock_addr, tunnel):
        super(BootstrapCandidate, self).__init__(sock_addr, tunnel, sock_addr, sock_addr, connection_type=u"public")

    def is_eligible_for_walk(self, now):
        """
        Bootstrap nodes are, by definition, always online, hence the timeouts do not apply.
        """
        return self._last_walk + CANDIDATE_ELIGIBLE_DELAY <= now

    def is_associated(self, member):
        """
        Bootstrap nodes are, by definition, always associated hence we return true.
        """
        return True

    def __str__(self):
        return "B!" + super(BootstrapCandidate, self).__str__()


class LoopbackCandidate(Candidate):

    def __init__(self):
        super(LoopbackCandidate, self).__init__(("localhost", 0), False)
