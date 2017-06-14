"""
The Distributed Permission System, or Dispersy, is a platform to simplify the design of distributed
communities.  At the heart of Dispersy lies a simple identity and message handling system where each
community and each user is uniquely and securely identified using elliptic curve cryptography.

Since we can not guarantee each member to be online all the time, messages that they created at one
point in time should be able to retain their meaning even when the member is off-line.  This can be
achieved by signing such messages and having them propagated though other nodes in the network.
Unfortunately, this increases the strain on these other nodes, which we try to alleviate using
specific message policies, which will be described below.

Following from this, we can easily package each message into one UDP packet to simplify
connect-ability problems since UDP packets are much easier to pass though NAT's and firewalls.

Earlier we hinted that messages can have different policies.  A message has the following four
different policies, and each policy defines how a specific part of the message should be handled.

 - Authentication defines if the message is signed, and if so, by how many members.

 - Resolution defines how the permission system should resolve conflicts between messages.

 - Distribution defines if the message is send once or if it should be gossiped around.  In the
   latter case, it can also define how many messages should be kept in the network.

 - Destination defines to whom the message should be send or gossiped.

To ensure that every node handles a messages in the same way, i.e. has the same policies associated
to each message, a message exists in two stages.  The meta-message and the implemented-message
stage.  Each message has one meta-message associated to it and tells us how the message is supposed
to be handled.  When a message is send or received an implementation is made from the meta-message
that contains information specifically for that message.  For example: a meta-message could have the
member-authentication-policy that tells us that the message must be signed by a member but only the
an implemented-message will have data and this signature.

A community can tweak the policies and how they behave by changing the parameters that the policies
supply.  Aside from the four policies, each meta-message also defines the community that it is part
of, the name it uses as an internal identifier, and the class that will contain the payload.
"""
import logging
import os
from collections import defaultdict, Iterable, OrderedDict
from hashlib import sha1
from itertools import groupby, count
from pprint import pformat
from socket import inet_aton
from struct import unpack_from
from time import time

import netifaces
from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred, gatherResults, inlineCallbacks, returnValue
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure
from twisted.python.threadable import isInIOThread

from .authentication import MemberAuthentication, DoubleMemberAuthentication
from .candidate import LoopbackCandidate, WalkCandidate, Candidate
from .community import Community
from .crypto import DispersyCrypto, ECCrypto
from .destination import CommunityDestination, CandidateDestination, NHopCommunityDestination
from .discovery.community import DiscoveryCommunity
from .dispersydatabase import DispersyDatabase
from .distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution
from .endpoint import Endpoint
from .exception import CommunityNotFoundException, ConversionNotFoundException, MetaNotFoundException
from .member import DummyMember, Member
from .message import Message, DropPacket, DelayPacket
from .statistics import DispersyStatistics, _runtime_statistics
from .taskmanager import TaskManager
from .util import (attach_runtime_statistics, init_instrumentation, blocking_call_on_reactor_thread, is_valid_address,
                   get_lan_address_without_netifaces, address_is_lan_without_netifaces)


# Set up the instrumentation utilities
init_instrumentation()

FLUSH_DATABASE_INTERVAL = 60.0
STATS_DETAILED_CANDIDATES_INTERVAL = 5.0


class Dispersy(TaskManager):

    """
    The Dispersy class provides the interface to all Dispersy related commands, managing the in- and
    outgoing data for, possibly, multiple communities.
    """

    def __init__(self, endpoint, working_directory, database_filename=u"dispersy.db", crypto=ECCrypto()):
        """
        Initialise a Dispersy instance.

        @param endpoint: Instance for communication.
        @type callback: Endpoint

        @param working_directory: The directory where all files should be stored.
        @type working_directory: unicode

        @param database_filename: The database filename or u":memory:"
        @type database_filename: unicode
        """
        assert isinstance(endpoint, Endpoint), type(endpoint)
        assert isinstance(working_directory, unicode), type(working_directory)
        assert isinstance(database_filename, unicode), type(database_filename)
        assert isinstance(crypto, DispersyCrypto), type(crypto)
        super(Dispersy, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        self.running = False

        # communication endpoint
        self._endpoint = endpoint

        # where we store all data
        self._working_directory = os.path.abspath(working_directory)

        self._discovery_community = None

        self._member_cache_by_hash = OrderedDict()

        # our data storage
        if not database_filename == u":memory:":
            database_directory = os.path.join(self._working_directory, u"sqlite")
            if not os.path.isdir(database_directory):
                os.makedirs(database_directory)
            database_filename = os.path.join(database_directory, database_filename)
        self._database = DispersyDatabase(database_filename)

        self._crypto = crypto

        # indicates what our connection type is.  currently it can be u"unknown", u"public", or
        # u"symmetric-NAT"
        self._connection_type = u"unknown"

        # our LAN and WAN addresses
        self._netifaces_failed = False
        self._lan_address = self._get_lan_address(True)
        self._wan_address = ("0.0.0.0", 0)
        self._wan_address_votes = defaultdict(set)
        self._logger.debug("my LAN address is %s:%d", self._lan_address[0], self._lan_address[1])
        self._logger.debug("my WAN address is %s:%d", self._wan_address[0], self._wan_address[1])
        self._logger.debug("my connection type is %s", self._connection_type)

        # communities that can be auto loaded.  classification:(cls, args, kargs) pairs.
        self._auto_load_communities = OrderedDict()

        # loaded communities.  cid:Community pairs.
        self._communities = {}

        # progress handlers (used to notify the user when something will take a long time)
        self._progress_handlers = []

        # statistics...
        self._statistics = DispersyStatistics(self)

    @staticmethod
    def _get_interface_addresses():
        """
        Yields Interface instances for each available AF_INET interface found.

        An Interface instance has the following properties:
        - name          (i.e. "eth0")
        - address       (i.e. "10.148.3.254")
        - netmask       (i.e. "255.255.255.0")
        - broadcast     (i.e. "10.148.3.255")
        """
        class Interface(object):

            def __init__(self, name, address, netmask, broadcast):
                self.name = name
                self.address = address
                self.netmask = netmask
                self.broadcast = broadcast
                self._l_address, = unpack_from(">L", inet_aton(address))
                self._l_netmask, = unpack_from(">L", inet_aton(netmask))

            def __contains__(self, address):
                assert isinstance(address, str), type(address)
                l_address, = unpack_from(">L", inet_aton(address))
                return (l_address & self._l_netmask) == (self._l_address & self._l_netmask)

            def __str__(self):
                return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

            def __repr__(self):
                return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

        try:
            for interface in netifaces.interfaces():
                try:
                    addresses = netifaces.ifaddresses(interface)

                except ValueError:
                    # some interfaces are given that are invalid, we encountered one called ppp0
                    pass

                else:
                    for option in addresses.get(netifaces.AF_INET, []):
                        try:
                            # On Windows netifaces currently returns IP addresses as unicode,
                            # and on *nix it returns str. So, we convert any unicode objects to str.
                            unicode_to_str = lambda s: s.encode('utf-8') if isinstance(s, unicode) else s
                            yield Interface(interface,
                                            unicode_to_str(option.get("addr")),
                                            unicode_to_str(option.get("netmask")),
                                            unicode_to_str(option.get("broadcast")))

                        except TypeError:
                            # some interfaces have no netmask configured, causing a TypeError when
                            # trying to unpack _l_netmask
                            pass
        except OSError, e:
            logger = logging.getLogger("dispersy")
            logger.warning("failed to check network interfaces, error was: %r", e)

    def _address_is_lan(self, address):
        if self._netifaces_failed:
            return address_is_lan_without_netifaces(address)
        else:
            return any(address in interface for interface in self._local_interfaces)

    def _get_lan_address(self, bootstrap=False):
        """
        Attempt to get the newest lan ip of this machine, preferably with netifaces, but use the fallback if it fails
        :return: lan address
        """
        if self._netifaces_failed:
            return (get_lan_address_without_netifaces(), self._lan_address[1])
        else:
            self._local_interfaces = list(self._get_interface_addresses())
            interface = self._guess_lan_address(self._local_interfaces)
            return (interface.address if interface else get_lan_address_without_netifaces()), \
                   (0 if bootstrap else self._lan_address[1])

    def _guess_lan_address(self, interfaces, default=None):
        """
        Chooses the most likely Interface instance out of INTERFACES to use as our LAN address.

        INTERFACES can be obtained from _get_interface_addresses()
        DEFAULT is used when no appropriate Interface can be found
        """
        assert isinstance(interfaces, list), type(interfaces)
        blacklist = ["127.0.0.1", "0.0.0.0", "255.255.255.255"]

        # prefer interfaces where we have a broadcast address
        for interface in interfaces:
            if interface.broadcast and interface.address and not interface.address in blacklist:
                self._logger.debug("%s", interface)
                return interface

        # Exception for virtual machines/containers
        for interface in interfaces:
            if interface.address and not interface.address in blacklist:
                self._logger.debug("%s", interface)
                return interface

        self._logger.warning("Unable to find our public interface!")
        self._netifaces_failed = True
        return default

    @property
    def working_directory(self):
        """
        The full directory path where all dispersy related files are stored.
        @rtype: unicode
        """
        return self._working_directory

    @property
    def endpoint(self):
        """
        The endpoint object used to send packets.
        @rtype: Object with a send(address, data) method
        """
        return self._endpoint

    def _endpoint_ready(self):
        """
        Guess our LAN and WAN address from information provided by endpoint.

        This method is called immediately after endpoint.start finishes.
        """
        host, port = self._endpoint.get_address()
        self._logger.info("update LAN address %s:%d -> %s:%d",
                          self._lan_address[0], self._lan_address[1], self._lan_address[0], port)
        self._lan_address = (self._lan_address[0], port)

        # at this point we do not yet have a WAN address, set it to the LAN address to ensure we
        # have something
        assert self._wan_address == ("0.0.0.0", 0)
        self._logger.info("update WAN address %s:%d -> %s:%d",
                          self._wan_address[0], self._wan_address[1], self._lan_address[0], self._lan_address[1])
        self._wan_address = self._lan_address

        if not is_valid_address(self._lan_address):
            self._logger.info("update LAN address %s:%d -> %s:%d",
                              self._lan_address[0], self._lan_address[1], host, self._lan_address[1])
            self._lan_address = (host, self._lan_address[1])

            if not is_valid_address(self._lan_address):
                self._logger.info("update LAN address %s:%d -> %s:%d",
                                  self._lan_address[0], self._lan_address[1],
                                  self._wan_address[0], self._lan_address[1])
                self._lan_address = (self._wan_address[0], self._lan_address[1])

        # our address may not be a candidate
        for community in self._communities.itervalues():
            community.candidates.pop(self._lan_address, None)

    @property
    def lan_address(self):
        """
        The LAN address where we believe people who are inside our LAN can find us.

        Our LAN address is determined by the default gateway of our
        system and our port.

        @rtype: (str, int)
        """
        return self._lan_address

    @property
    def wan_address(self):
        """
        The wan address where we believe that we can be found from outside our LAN.

        Our wan address is determined by majority voting.  Each time when we receive a message
        that contains an opinion about our wan address, we take this into account.  The
        address with the most votes wins.

        Votes can be added by calling the wan_address_vote(...) method.

        Usually these votes are received through dispersy-introduction-request and
        dispersy-introduction-response messages.

        @rtype: (str, int)
        """
        return self._wan_address

    @property
    def connection_type(self):
        """
        The connection type that we believe we have.

        Currently the following types are recognized:
        - u'unknown': the default value until the actual type can be recognized.
        - u'public': when the LAN and WAN addresses are determined to be the same.
        - u'symmetric-NAT': when each remote peer reports different external port numbers.

        @rtype: unicode
        """
        return self._connection_type

    @property
    def database(self):
        """
        The Dispersy database singleton.
        @rtype: DispersyDatabase
        """
        return self._database

    @property
    def crypto(self):
        """
        The Dispersy crypto singleton.
        @rtype: DispersyCrypto
        """
        return self._crypto

    @property
    def statistics(self):
        """
        The Statistics instance.
        """
        return self._statistics

    def define_auto_load(self, community_cls, my_member, args=(), kargs=None, load=False):
        """
        Tell Dispersy how to load COMMUNITY if need be.

        COMMUNITY_CLS is the community class that is defined.

        MY_MEMBER is the member to be used within the community.

        ARGS an KARGS are optional arguments and keyword arguments passed to the
        community constructor.

        When LOAD is True all available communities of this type will be immediately loaded.

        Returns a list with loaded communities.
        """
        assert isInIOThread(), "Must be called from the callback thread"
        assert issubclass(community_cls, Community), type(community_cls)
        assert isinstance(args, tuple), type(args)
        assert kargs is None or isinstance(kargs, dict), type(kargs)
        assert not community_cls.get_classification() in self._auto_load_communities
        assert isinstance(load, bool), type(load)

        if kargs is None:
            kargs = {}
        self._auto_load_communities[community_cls.get_classification()] = (community_cls, my_member, args, kargs)

        communities = []
        if load:
            for master in community_cls.get_master_members(self):
                if not master.mid in self._communities:
                    self._logger.debug("Loading %s at start", community_cls.get_classification())
                    community = community_cls.init_community(self, master, my_member, *args, **kargs)
                    communities.append(community)
                    assert community.master_member.mid == master.mid
                    assert community.master_member.mid in self._communities

        return communities

    def undefine_auto_load(self, community):
        """
        Tell Dispersy to no longer load COMMUNITY.

        COMMUNITY is the community class that is defined.
        """
        assert issubclass(community, Community)
        assert community.get_classification() in self._auto_load_communities
        del self._auto_load_communities[community.get_classification()]

    def attach_community(self, community):
        # add community to communities dict
        self._communities[community.cid] = community
        self._statistics.dict_inc(u"attachment", community.cid)

        # let discovery community know
        if self._discovery_community:
            self._discovery_community.new_community(community)

    def detach_community(self, community):
        del self._communities[community.cid]

    def attach_progress_handler(self, func):
        assert callable(func), "handler must be callable"
        self._progress_handlers.append(func)

    def detach_progress_handler(self, func):
        assert callable(func), "handler must be callable"
        assert func in self._progress_handlers, "handler is not attached"
        self._progress_handlers.remove(func)

    def get_progress_handlers(self):
        return self._progress_handlers

    def get_member(self, mid="", public_key="", private_key=""):
        """Returns a Member instance associated with public_key.

        Since we have the public_key, we can create this user if it doesn't yet.  Hence, this method always succeeds.

        @param public_key: The public key of the member we want to obtain.
        @param private_key: The public/private key pair of the member we want to obtain.
        @type public_key: string
        @type private_key: string

        @return: The Member instance associated with public_key.
        @rtype: Member
        """
        assert sum(map(bool, (mid, public_key, private_key))) == 1, \
            "Only one of the three optional arguments may be passed: %s" % str((mid, public_key, private_key))
        assert isinstance(mid, str)
        assert isinstance(public_key, str)
        assert isinstance(private_key, str)
        assert not mid or len(mid) == 20, (mid.encode("HEX"), len(mid))
        assert not public_key or self.crypto.is_valid_public_bin(public_key)
        assert not private_key or self.crypto.is_valid_private_bin(private_key)

        if not mid:
            if public_key:
                mid = sha1(public_key).digest()

            elif private_key:
                _key = self.crypto.key_from_private_bin(private_key)
                mid = self.crypto.key_to_hash(_key.pub())

        member = self._member_cache_by_hash.get(mid)
        if member:
            return member

        if private_key:
            key = self.crypto.key_from_private_bin(private_key)
            public_key = self.crypto.key_to_bin(key.pub())

        elif public_key:
            key = self.crypto.key_from_public_bin(public_key)

        # both public and private keys are valid at this point

        # The member is not cached, let's try to get it from the database
        row = self.database.execute(u"SELECT id, public_key, private_key FROM member WHERE mid = ? LIMIT 1", (buffer(mid),)).fetchone()

        if row:
            database_id, public_key_from_db, private_key_from_db = row

            public_key_from_db = "" if public_key_from_db is None else str(public_key_from_db)
            private_key_from_db = "" if private_key_from_db is None else str(private_key_from_db)

            # the private key that was passed as an argument overrules everything, update db if neccesary
            if private_key:
                assert public_key
                if private_key_from_db != private_key:
                    self.database.execute(u"UPDATE member SET public_key = ?, private_key = ? WHERE id = ?",
                        (buffer(public_key), buffer(private_key), database_id))
            else:
                # the private key from the database overrules the public key argument
                if private_key_from_db:
                    key = self.crypto.key_from_private_bin(private_key_from_db)

                # the public key argument overrules anything in the database
                elif public_key:
                    if public_key_from_db != public_key:
                        self.database.execute(u"UPDATE member SET public_key = ? WHERE id = ?",
                            (buffer(public_key), database_id))

                # no priv/pubkey arguments passed, maybe use the public key from the database
                elif public_key_from_db:
                    key = self.crypto.key_from_public_bin(public_key_from_db)

                else:
                    return DummyMember(self, database_id, mid)

        # the member is not in the database, insert it
        elif public_key or private_key:
            if private_key:
                assert public_key
            # The MID or public/private keys are not in the database, store them.
            database_id = self.database.execute(
                u"INSERT INTO member (mid, public_key, private_key) VALUES (?, ?, ?)",
                (buffer(mid), buffer(public_key), buffer(private_key)), get_lastrowid=True)
        else:
            # We could't find the key on the DB, nothing else to do
            database_id = self.database.execute(u"INSERT INTO member (mid) VALUES (?)",
                (buffer(mid),), get_lastrowid=True)
            return DummyMember(self, database_id, mid)

        member = Member(self, key, database_id, mid)

        # store in cache
        self._member_cache_by_hash[member.mid] = member

        # limit cache length
        if len(self._member_cache_by_hash) > 1024:
            self._member_cache_by_hash.popitem(False)

        return member

    def get_new_member(self, securitylevel=u"medium"):
        """
        Returns a Member instance created from a newly generated public key.
        """
        assert isinstance(securitylevel, unicode), type(securitylevel)
        key = self.crypto.generate_key(securitylevel)
        return self.get_member(private_key=self.crypto.key_to_bin(key))

    def get_member_from_database_id(self, database_id):
        """
        Returns a Member instance associated with DATABASE_ID or None when this row identifier is
        not available.
        """
        assert isinstance(database_id, (int, long)), type(database_id)
        try:
            public_key, = next(self._database.execute(u"SELECT public_key FROM member WHERE id = ?", (database_id,)))
            return self.get_member(public_key=str(public_key))
        except StopIteration:
            pass

    @inlineCallbacks
    def reclassify_community(self, source, destination):
        """
        Change a community classification.

        Each community has a classification that dictates what source code is handling this
        community.  By default the classification of a community is the unicode name of the class in
        the source code.

        In some cases it may be usefull to change the classification, for instance: if community A
        has a subclass community B, where B has similar but reduced capabilities, we could
        reclassify B to A at some point and keep all messages collected so far while using the
        increased capabilities of community A.

        @param source: The community that will be reclassified.  This must be either a Community
         instance (when the community is loaded) or a Member instance giving the master member (when
         the community is not loaded).
        @type source: Community or Member

        @param destination: The new community classification.  This must be a Community class.
        @type destination: Community class
        """
        assert isinstance(source, (Community, Member))
        assert issubclass(destination, Community)
        assert type(source) is not type(destination), (type(source), type(destination))

        destination_classification = destination.get_classification()

        if isinstance(source, Member):
            self._logger.debug("reclassify <unknown> -> %s", destination_classification)
            master = source

        else:
            self._logger.debug("reclassify %s -> %s", source.get_classification(), destination_classification)
            assert source.cid in self._communities
            assert self._communities[source.cid] == source
            master = source.master_member
            yield source.unload_community()

        self._database.execute(u"UPDATE community SET classification = ? WHERE master = ?",
                               (destination_classification, master.database_id))

        if destination_classification in self._auto_load_communities:
            cls, my_member, args, kargs = self._auto_load_communities[destination_classification]
            assert cls == destination, [cls, destination]

        else:
            my_member_did, = self._database.execute(u"SELECT member FROM community WHERE master = ?",
                               (master.database_id,)).next()

            my_member = self.get_member_from_database_id(my_member_did)
            args = ()
            kargs = {}

        res = destination.init_community(self, master, my_member, *args, **kargs)
        returnValue(res)

    def has_community(self, cid):
        """
        Returns True when there is a community CID.
        """
        return cid in self._communities

    def get_community(self, cid, load=False, auto_load=True):
        """
        Returns a community by its community id.

        The community id, or cid, is the binary representation of the public key of the master
        member for the community.

        When the community is available but not currently loaded it will be automatically loaded
        when (a) the load parameter is True or (b) the auto_load parameter is True and the auto_load
        flag for this community is True (this flag is set in the database).

        @param cid: The community identifier.
        @type cid: string, of any size

        @param load: When True, will load the community when available and not yet loaded.
        @type load: bool

        @param auto_load: When True, will load the community when available, the auto_load flag is
         True, and, not yet loaded.
        @type load: bool

        @warning: It is possible, however unlikely, that multiple communities will have the same
         cid.  This is currently not handled.
        """
        assert isinstance(cid, str)
        assert isinstance(load, bool), type(load)
        assert isinstance(auto_load, bool)

        try:
            return self._communities[cid]

        except KeyError:
            if load or auto_load:
                try:
                    # have we joined this community
                    classification, auto_load_flag, master_public_key = self._database.execute(u"SELECT community.classification, community.auto_load, member.public_key FROM community JOIN member ON member.id = community.master WHERE mid = ?",
                                                                                               (buffer(cid),)).next()

                except StopIteration:
                    pass

                else:
                    if load or (auto_load and auto_load_flag):

                        if classification in self._auto_load_communities:
                            master = self.get_member(public_key=str(master_public_key)) if master_public_key else self.get_member(mid=cid)
                            cls, my_member, args, kargs = self._auto_load_communities[classification]
                            community = cls.init_community(self, master, my_member, *args, **kargs)
                            assert master.mid in self._communities
                            return community

                        else:
                            self._logger.warning("unable to auto load %s is an undefined classification [%s]",
                                                 cid.encode("HEX"), classification)

                    else:
                        self._logger.debug("not allowed to load [%s]", classification)

        raise CommunityNotFoundException(cid)

    def get_communities(self):
        """
        Returns a list with all known Community instances.
        """
        return self._communities.values()

    def get_message(self, community, member, global_time):
        """
        Returns a Member.Implementation instance uniquely identified by its community, member, and
        global_time.

        Returns None if this message is not in the local database.
        """
        assert isinstance(community, Community)
        assert isinstance(member, Member)
        assert isinstance(global_time, (int, long))
        try:
            packet, = self._database.execute(u"SELECT packet FROM sync WHERE community = ? AND member = ? AND global_time = ?",
                                             (community.database_id, member.database_id, global_time)).next()
        except StopIteration:
            return None
        else:
            return self.convert_packet_to_message(str(packet), community)

    def get_last_message(self, community, member, meta):
        assert isinstance(community, Community)
        assert isinstance(member, Member)
        assert isinstance(meta, Message)
        try:
            packet, = self._database.execute(u"SELECT packet FROM sync WHERE member = ? AND meta_message = ? ORDER BY global_time DESC LIMIT 1",
                                             (member.database_id, meta.database_id)).next()
        except StopIteration:
            return None
        else:
            return self.convert_packet_to_message(str(packet), community)

    def wan_address_unvote(self, voter):
        """
        Removes and returns one vote made by VOTER.
        """
        assert isinstance(voter, Candidate)
        for vote, voters in self._wan_address_votes.iteritems():
            if voter.sock_addr in voters:
                voters.remove(voter.sock_addr)
                if len(voters) == 0:
                    del self._wan_address_votes[vote]
                return vote

    def wan_address_vote(self, address, voter):
        """
        Add one vote and possibly re-determine our wan address.

        Our wan address is determined by majority voting.  Each time when we receive a message
        that contains anothers opinion about our wan address, we take this into account.  The
        address with the most votes wins.

        Usually these votes are received through dispersy-candidate-request and
        dispersy-candidate-response messages.

        @param address: The wan address that the voter believes us to have.
        @type address: (str, int)

        @param voter: The voter candidate.
        @type voter: Candidate
        """
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(voter, Candidate), type(voter)

        def set_lan_address(address):
            " Set LAN address when ADDRESS is different from self._LAN_ADDRESS. "
            if self._lan_address == address:
                return False
            else:
                self._logger.info("update LAN address %s:%d -> %s:%d",
                                  self._lan_address[0], self._lan_address[1], address[0], address[1])
                self._lan_address = address
                return True

        def set_wan_address(address):
            " Set WAN address when ADDRESS is different from self._WAN_ADDRESS. "
            if self._wan_address == address:
                return False
            else:
                self._logger.info("update WAN address %s:%d -> %s:%d",
                                  self._wan_address[0], self._wan_address[1], address[0], address[1])
                self._wan_address = address
                return True

        def set_connection_type(connection_type):
            " Set connection type when CONNECTION_TYPE is different from self._CONNECTION_TYPE. "
            if self._connection_type == connection_type:
                return False
            else:
                self._logger.info("update connection type %s -> %s", self._connection_type, connection_type)
                self._connection_type = connection_type
                return True

        # undo previous vote
        self.wan_address_unvote(voter)

        # ensure ADDRESS is valid
        if not is_valid_address(address):
            self._logger.debug("ignore vote for %s from %s (address is invalid)", address, voter.sock_addr)
            return

        # ignore votes from voters that we know are within any of our LAN interfaces.  these voters
        # can not know our WAN address

        if self._address_is_lan(voter.sock_addr[0]):
            self._logger.debug("ignore vote for %s from %s (voter is within our LAN)", address, voter.sock_addr)
            return

        # do vote
        self._logger.debug("add vote for %s from %s", address, voter.sock_addr)
        self._wan_address_votes[address].add(voter.sock_addr)

        #
        # check self._lan_address and self._wan_address
        #

        # change when new vote count is higher than old address vote count (don't use equal to avoid
        # alternating between two equally voted addresses)
        if len(self._wan_address_votes[address]) > len(self._wan_address_votes.get(self._wan_address, ())):
            if set_wan_address(address):
                # refresh our LAN address(es), perhaps we are running on a roaming device
                lan_address = self._get_lan_address()
                if not is_valid_address(lan_address):
                    lan_address = (self._wan_address[0], self._lan_address[1])
                set_lan_address(lan_address)
                # remove our lan/wan addresses from all communities candidate lists
                for community in self._communities.itervalues():
                    community.remove_candidate(self._wan_address)
                    community.remove_candidate(self._lan_address)

        #
        # check self._connection_type
        #

        if len(self._wan_address_votes) == 1 and self._lan_address == self._wan_address:
            # external peers are reporting the same WAN address that happens to be our LAN address
            # as well
            set_connection_type(u"public")

        elif len(self._wan_address_votes) > 1:
            for voters in self._wan_address_votes.itervalues():
                if len(set([address[0] for address in voters])) > 1:
                    # A single NAT mapping has more than one destination IP hence
                    # it cannot be a symmetric NAT
                    set_connection_type(u"unknown")
                    break
            else:
                # Our nat created a new mapping for each destination IP
                set_connection_type(u"symmetric-NAT")
        else:
            set_connection_type(u"unknown")

    def load_message(self, community, member, global_time, verify=False):
        """
        Returns the message identified by community, member, and global_time.

        Each message is uniquely identified by the community that it is created in, the member it is
        created by and the global time when it is created.  Using these three parameters we return
        the associated the Message.Implementation instance.  None is returned when we do not have
        this message or it can not be decoded.
        """
        assert isinstance(community, Community), type(community)
        assert isinstance(member, DummyMember), type(member)
        assert isinstance(global_time, (int, long)), type(global_time)

        try:
            packet_id, packet, undone = self._database.execute(u"SELECT id, packet, undone FROM sync WHERE community = ? AND member = ? AND global_time = ? LIMIT 1",
                                                       (community.database_id, member.database_id, global_time)).next()
        except StopIteration:
            return None

        message = self.convert_packet_to_message(str(packet), community, verify=verify)
        if message:
            message.packet_id = packet_id
            message.undone = undone
            return message

    def load_message_by_packetid(self, community, packet_id, verify=False):
        """
        Returns the message identified by community, member, and global_time.

        Each message is uniquely identified by the community that it is created in, the member it is
        created by and the global time when it is created.  Using these three parameters we return
        the associated the Message.Implementation instance.  None is returned when we do not have
        this message or it can not be decoded.
        """
        assert isinstance(community, Community), type(community)
        assert isinstance(packet_id, (int, long)), type(packet_id)

        try:
            packet, undone = self._database.execute(u"SELECT packet, undone FROM sync WHERE id = ?",
                                                       (packet_id,)).next()
        except StopIteration:
            return None

        message = self.convert_packet_to_message(str(packet), community, verify=verify)
        if message:
            message.packet_id = packet_id
            message.undone = undone
            return message

    def convert_packet_to_message(self, packet, community=None, load=True, auto_load=True, candidate=None, verify=True):
        """
        Returns the Message.Implementation representing the packet or None when no conversion is
        possible.
        """
        assert isinstance(packet, str), type(packet)
        assert community is None or isinstance(community, Community), type(community)
        assert isinstance(load, bool), type(load)
        assert isinstance(auto_load, bool), type(auto_load)
        assert candidate is None or isinstance(candidate, Candidate), type(candidate)

        # find associated community
        try:
            if not community:
                community = self.get_community(packet[2:22], load, auto_load)

            # find associated conversion
            conversion = community.get_conversion_for_packet(packet)
            return conversion.decode_message(LoopbackCandidate() if candidate is None else candidate, packet, verify)

        except CommunityNotFoundException:
            self._logger.warning("unable to convert a %d byte packet (unknown community)", len(packet))
        except ConversionNotFoundException:
            self._logger.warning("unable to convert a %d byte packet (unknown conversion)", len(packet))
        except (DropPacket, DelayPacket) as exception:
            self._logger.warning("unable to convert a %d byte packet (%s)", len(packet), exception)
        return None

    def convert_packets_to_messages(self, packets, community=None, load=True, auto_load=True, candidate=None, verify=True):
        """
        Returns a list with messages representing each packet or None when no conversion is
        possible.
        """
        assert isinstance(packets, Iterable), type(packets)
        assert all(isinstance(packet, str) for packet in packets), [type(packet) for packet in packets]
        return [self.convert_packet_to_message(packet, community, load, auto_load, candidate, verify) for packet in packets]

    def on_incoming_packets(self, packets, cache=True, timestamp=0.0, source=u"unknown"):
        """
        Process incoming UDP packets.

        This method is called to process one or more UDP packets.  This occurs when new packets are
        received, to attempt to process previously delayed packets, or when a member explicitly
        creates a packet to process.  The last option should only occur for debugging purposes.

        The following steps are followed:

        1. Group the packets by community.

        2. Try to obtain the community.

        3. In case 2 suceeded: Pass the packets to the community for further processing.

        """
        assert isinstance(packets, (tuple, list)), packets
        assert len(packets) > 0, packets
        assert all(isinstance(packet, tuple) for packet in packets), packets
        assert all(len(packet) == 2 for packet in packets), packets  # tuple(Candidate, datagram)
        assert all(isinstance(packet[0], Candidate) for packet in packets), packets
        assert all((is_valid_address(packet[0].sock_addr) for packet in packets)), packets
        assert all(isinstance(packet[1], str) for packet in packets), packets
        assert all(len(packet[1]) > 22 for packet in packets), [
            (str(packet[0]), repr(packet[1])) for packet in packets]
        assert isinstance(cache, bool), cache
        assert isinstance(timestamp, float), timestamp
        assert isinstance(source, unicode), source

        if self.running:
            self._statistics.total_received += len(packets)

            # Ugly hack to sort the identity messages before any other to avoid sending missing identity requests
            # for identities we have already received but not processed yet. (248 == identity message ID)
            #                                           /-------------------------------\
            sort_key = lambda tup: (tup[1][2:22], tup[1][1], 0 if tup[1][22] == chr(248) else tup[1][22])  # community ID, community version, message meta type
            groupby_key = lambda tup: tup[1][2:22]  # community ID
            for community_id, iterator in groupby(sorted(packets, key=sort_key), key=groupby_key):
                # find associated community
                try:
                    community = self.get_community(community_id)
                    community.on_incoming_packets(list(iterator), cache, timestamp, source)

                except CommunityNotFoundException:
                    packets = list(iterator)
                    candidates = set([candidate for candidate, _ in packets])
                    self._logger.warning("drop %d packets (received packet(s) for unknown community): %s",
                                         len(packets), map(str, candidates))
                    self._statistics.msg_statistics.increase_count(
                        u"drop", u"_convert_packets_into_batch:unknown community")
        else:
            self._logger.info("dropping %d packets as dispersy is not running", len(packets))

    @attach_runtime_statistics(u"Dispersy.{function_name} {1[0].name}")
    def _store(self, messages):
        """
        Store a message in the database.

        Messages with the Last- or Full-SyncDistribution policies need to be stored in the database
        to allow them to propagate to other members.

        Messages with the LastSyncDistribution policy may also cause an older message to be removed
        from the database.

        Messages created by a member that we have marked with must_store will also be stored in the
        database, and hence forwarded to others.

        @param message: The unstored message with the SyncDistribution policy.
        @type message: Message.Implementation
        """
        assert isinstance(messages, list)
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)
        assert all(isinstance(message.distribution, SyncDistribution.Implementation) for message in messages)
        # ensure no duplicate messages are present, this MUST HAVE been checked before calling this
        # method!
        assert len(messages) == len(set((message.authentication.member.database_id, message.distribution.global_time) for message in messages)), messages[0].name

        meta = messages[0].meta
        self._logger.debug("attempting to store %d %s messages", len(messages), meta.name)
        is_double_member_authentication = isinstance(meta.authentication, DoubleMemberAuthentication)
        highest_global_time = 0
        highest_sequence_number = defaultdict(int)

        # update_sync_range = set()
        for message in messages:
            # the signature must be set
            assert isinstance(message.authentication, (MemberAuthentication.Implementation, DoubleMemberAuthentication.Implementation)), message.authentication
            assert message.authentication.is_signed
            assert not message.packet[-10:] == "\x00" * 10, message.packet[-10:].encode("HEX")
            # we must have the identity message as well
            assert message.authentication.encoding in ("bin", "default") or message.authentication.member.has_identity(message.community), [message.authentication.encoding, message.community, message.authentication.member.database_id, message.name]

            self._logger.debug("%s %d@%d", message.name,
                               message.authentication.member.database_id, message.distribution.global_time)

            # add packet to database
            message.packet_id = self._database.execute(
                u"INSERT INTO sync (community, member, global_time, meta_message, packet, sequence) "
                u"VALUES (?, ?, ?, ?, ?, ?)",
               (message.community.database_id,
                message.authentication.member.database_id,
                message.distribution.global_time,
                message.database_id,
                buffer(message.packet),
                (message.distribution.sequence_number if
                 isinstance(meta.distribution, FullSyncDistribution)
                 and message.distribution.enable_sequence_number else None)
                ), get_lastrowid=True)

            # ensure that we can reference this packet
            self._logger.debug("stored message %s in database at row %d", message.name, message.packet_id)

            if is_double_member_authentication:
                member1 = message.authentication.members[0].database_id
                member2 = message.authentication.members[1].database_id
                self._database.execute(u"INSERT INTO double_signed_sync (sync, member1, member2) VALUES (?, ?, ?)",
                                       (message.packet_id, member1, member2) if member1 < member2 else (message.packet_id, member2, member1))

            # update global time
            highest_global_time = max(highest_global_time, message.distribution.global_time)
            if isinstance(meta.distribution, FullSyncDistribution) and message.distribution.enable_sequence_number:
                highest_sequence_number[message.authentication.member.database_id] = max(highest_sequence_number[message.authentication.member.database_id], message.distribution.sequence_number)


        if __debug__ and highest_sequence_number:
            # when sequence numbers are enabled, we must have exactly
            # message.distribution.sequence_number messages in the database
            for member_id, max_sequence_number in highest_sequence_number.iteritems():
                count_, = self._database.execute(u"SELECT COUNT(*) FROM sync "
                                                u"WHERE meta_message = ? AND member = ? AND sequence BETWEEN 1 AND ?",
                                                (message.database_id, member_id, max_sequence_number)).next()
                assert count_ == max_sequence_number, [count_, max_sequence_number]

        if isinstance(meta.distribution, LastSyncDistribution):
            # delete packets that have become obsolete
            items = set()
            # handle metadata message
            if meta.distribution.custom_callback:
                items = meta.distribution.custom_callback[1](messages)

            # default behaviour
            else:
                if is_double_member_authentication:
                    order = lambda member1, member2: (member1, member2) if member1 < member2 else (member2, member1)
                    for member1, member2 in set(order(message.authentication.members[0].database_id, message.authentication.members[1].database_id) for message in messages):
                        assert member1 < member2, [member1, member2]
                        all_items = list(self._database.execute(u"""
SELECT sync.id, sync.global_time
FROM sync
JOIN double_signed_sync ON double_signed_sync.sync = sync.id
WHERE sync.meta_message = ? AND double_signed_sync.member1 = ? AND double_signed_sync.member2 = ?
ORDER BY sync.global_time, sync.packet""", (meta.database_id, member1, member2)))
                        if len(all_items) > meta.distribution.history_size:
                            items.update(all_items[:len(all_items) - meta.distribution.history_size])

                else:
                    for member_database_id in set(message.authentication.member.database_id for message in messages):
                        all_items = list(self._database.execute(u"""
SELECT id, global_time
FROM sync
WHERE meta_message = ? AND member = ?
ORDER BY global_time""", (meta.database_id, member_database_id)))
                        if len(all_items) > meta.distribution.history_size:
                            items.update(all_items[:len(all_items) - meta.distribution.history_size])

            if items:
                self._database.executemany(u"DELETE FROM sync WHERE id = ?", [(syncid,) for syncid, _ in items])

                if is_double_member_authentication:
                    self._database.executemany(u"DELETE FROM double_signed_sync WHERE sync = ?", [(syncid,) for syncid, _ in items])

                # update_sync_range.update(global_time for _, _, global_time in items)

            # 12/10/11 Boudewijn: verify that we do not have to many packets in the database
            if __debug__:
                if not is_double_member_authentication and meta.distribution.custom_callback is None:
                    for message in messages:
                        history_size, = self._database.execute(u"SELECT COUNT(*) FROM sync WHERE meta_message = ? AND member = ?", (message.database_id, message.authentication.member.database_id)).next()
                        assert history_size <= message.distribution.history_size, [history_size, message.distribution.history_size, message.authentication.member.database_id]

        # update the global time
        meta.community.update_global_time(highest_global_time)

        meta.community.dispersy_store(messages)

        # if update_sync_range:
        # notify that global times have changed
        #     meta.community.update_sync_range(meta, update_sync_range)

    def estimate_lan_and_wan_addresses(self, sock_addr, lan_address, wan_address):
        """
        We received a message from SOCK_ADDR claiming to have LAN_ADDRESS and WAN_ADDRESS, returns
        the estimated LAN and WAN address for this node.

        The returns LAN and WAN addresses are either modified when we know they are incorrect (based
        on the reported sock_addr) or they remain unchanged.  Hence the returned addresses may be
        ("0.0.0.0", 0).
        """
        assert is_valid_address(sock_addr), sock_addr

        if self._address_is_lan(sock_addr[0]):
            # is SOCK_ADDR is on our local LAN, hence LAN_ADDRESS should be SOCK_ADDR
            if sock_addr != lan_address:
                self._logger.debug("estimate someones LAN address is %s (LAN was %s, WAN stays %s)",
                             sock_addr, lan_address, wan_address)
                lan_address = sock_addr

        else:
            # is SOCK_ADDR is outside our local LAN, hence WAN_ADDRESS should be SOCK_ADDR
            if sock_addr != wan_address:
                self._logger.info("estimate someones WAN address is %s (WAN was %s, LAN stays %s)",
                            sock_addr, wan_address, lan_address)
                wan_address = sock_addr

        return lan_address, wan_address

    # TODO(emilon): Now that we have removed the malicious behaviour stuff, maybe we could be a bit more relaxed with the DB syncing?
    def store_update_forward(self, possibly_messages, store, update, forward):
        """
        Usually we need to do three things when we have a valid messages: (1) store it in our local
        database, (2) process the message locally by calling the handle_callback method, and (3)
        forward the message to other nodes in the community.  This method is a shorthand for doing
        those three tasks.

        To reduce the disk activity, namely syncing the database to disk, we will perform the
        database commit not after the (1) store operation but after the (2) update operation.  This
        will ensure that any database changes from handling the message are also synced to disk.  It
        is important to note that the sync will occur before the (3) forward operation to ensure
        that no remote nodes will obtain data that we have not safely synced ourselves.

        For performance reasons messages are processed in batches, where each batch contains only
        messages from the same community and the same meta message instance.  This method, or more
        specifically the methods that handle the actual storage, updating, and forwarding, assume
        this clustering.

        @param messages: A list with the messages that need to be stored, updated, and forwarded.
         All messages need to be from the same community and meta message instance.
        @type messages: [Message.Implementation]

        @param store: When True the messages are stored (as defined by their message distribution
         policy) in the local dispersy database.  This parameter should (almost always) be True, its
         inclusion is mostly to allow certain debugging scenarios.
        @type store: bool

        @param update: When True the messages are passed to their handle_callback methods.  This
         parameter should (almost always) be True, its inclusion is mostly to allow certain
         debugging scenarios.
        @type update: bool

        @param forward: When True the messages are forwarded (as defined by their message
         destination policy) to other nodes in the community.  This parameter should (almost always)
         be True, its inclusion is mostly to allow certain debugging scenarios.
        @type store: bool
        """
        assert isinstance(possibly_messages, list)
        assert isinstance(store, bool)
        assert isinstance(update, bool)
        assert isinstance(forward, bool)

        # Let's filter out non-Message.Implementation objects
        messages = []
        for thing in possibly_messages:
            if isinstance(thing, Message.Implementation):
                messages.append(thing)

        assert len(messages) > 0
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)

        store = store and isinstance(messages[0].meta.distribution, SyncDistribution)
        if store:
            self._store(messages)

        if update:
            if self._update(possibly_messages) == False:
                return False

        # 07/10/11 Boudewijn: we will only commit if it the message was create by our self.
        # Otherwise we can safely skip the commit overhead, since, if a crash occurs, we will be
        # able to obtain the data eventually
        if store:
            my_messages = sum(message.authentication.member == message.community.my_member for message in messages)
            if my_messages:
                self._logger.debug("commit user generated message")
                self._database.commit()

                messages[0].community.statistics.increase_msg_count(u"created", messages[0].meta.name, my_messages)

        if forward:
            return self._forward(messages)

        return True

    @attach_runtime_statistics(u"Dispersy.{function_name} {1[0].name}")
    def _update(self, messages):
        """
        Call the handle callback of a list of messages of the same type.
        """
        try:
            messages[0].handle_callback(messages)
            return True
        except (SystemExit, KeyboardInterrupt, GeneratorExit, AssertionError):
            raise
        except:
            self._logger.exception("exception during handle_callback for %s", messages[0].name)
            return False

    @attach_runtime_statistics(u"Dispersy.{function_name} {1[0].name}")
    def _forward(self, messages):
        """
        Queue a sequence of messages to be sent to other members.

        First all messages that use the SyncDistribution policy are stored to the database to allow
        them to propagate when a dispersy-sync message is received.

        Second all messages are sent depending on their destination policy:

         - CandidateDestination causes a message to be sent to the addresses in
           message.destination.candidates.

         - CommunityDestination causes a message to be sent to one or more addresses to be picked
           from the database candidate table.

        @param messages: A sequence with one or more messages.
        @type messages: [Message.Implementation]
        """
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)
        assert all(message.community == messages[0].community for message in messages)
        assert all(message.meta == messages[0].meta for message in messages)

        result = True
        meta = messages[0].meta
        if isinstance(meta.destination, (CommunityDestination, CandidateDestination)):
            for message in messages:
                # Don't forward messages with a 0 TTL
                if isinstance(meta.destination, NHopCommunityDestination) and message.destination.depth == 0:
                    continue
                # CandidateDestination.candidates may be empty
                candidates = set(message.destination.candidates)
                # CommunityDestination.node_count is allowed to be zero
                if isinstance(meta.destination, CommunityDestination) and meta.destination.node_count > 0:
                    max_candidates = meta.destination.node_count + len(candidates)
                    for candidate in meta.community.dispersy_yield_verified_candidates():
                        if len(candidates) < max_candidates:
                            candidates.add(candidate)
                        else:
                            break
                result = result and self._send(tuple(candidates), [message])
        else:
            raise NotImplementedError(meta.destination)

        return result

    def _delay(self, delay, packet, candidate):
        for key in delay.match_info:
            assert len(key) == 5, key
            assert isinstance(key[0], str), type(key[0])
            assert len(key[0]) == 20, len(key[0])
            assert not key[1] or isinstance(key[1], unicode), type(key[1])
            assert not key[2] or isinstance(key[2], str), type(key[2])
            assert not key[2] or len(key[2]) == 20, len(key[2])
            assert not key[3] or isinstance(key[3], (int, long)), type(key[3])
            assert not key[4] or isinstance(key[4], list), type(key[4])


            try:
                community = self.get_community(key[0], load=False, auto_load=False)
                community._delay(key[1:], delay, packet, candidate)
            except CommunityNotFoundException:
                self._logger.error('Messages can only be delayed for loaded communities.')

    def _send(self, candidates, messages):
        """
        Send a list of messages to a list of candidates. If no candidates are specified or endpoint reported
        a failure this method will return False.

        @param candidates: A sequence with one or more candidates.
        @type candidates: [Candidate]

        @param messages: A sequence with one or more messages.
        @type messages: [Message.Implementation]
        """
        assert isinstance(candidates, (tuple, list, set)), type(candidates)
        # 04/03/13 boudewijn: CANDIDATES should contain candidates, never None
        # candidates = [candidate for candidate in candidates if candidate]
        assert all(isinstance(candidate, Candidate) for candidate in candidates)
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert all(isinstance(message, Message.Implementation) for message in messages)

        messages_send = False
        if len(candidates) and len(messages):
            packets = [message.packet for message in messages]
            messages_send = self._endpoint.send(candidates, packets)

        if messages_send:
            for message in messages:
                if message.meta.name == u"dispersy-introduction-request":
                    for candidate in candidates:
                        message.community.statistics.msg_statistics.walk_attempt_count += 1
                        message.community.statistics.increase_msg_count(u"outgoing_intro", candidate.sock_addr)

                        self.statistics.walk_attempt_count += 1
                        self.statistics.outgoing_intro_count += 1
                        self.statistics.dict_inc(u"outgoing_intro_dict", candidate.sock_addr)

                message.community.statistics.increase_msg_count(
                    u"outgoing", message.meta.name, len(candidates))

        return messages_send

    def _send_packets(self, candidates, packets, community, msg_type):
        """A wrap method to use send() in endpoint.
        """
        self._endpoint.send(candidates, packets)
        community.statistics.increase_msg_count(u"outgoing", msg_type, len(candidates) * len(packets))

    def sanity_check(self, community, test_identity=True, test_undo_other=True, test_binary=False, test_sequence_number=True, test_last_sync=True):
        """
        Check everything we can about a community.

        Note that messages that are disabled, i.e. not included in community.get_meta_messages(),
        will NOT be checked.

        This check assumes that a community has the my_member attribute and this member in a community has an identity
        associated to it (i.e. we have created a dispersy-identity message for my member).

        - the dispersy-identity for my member must be in the database
        - the dispersy-identity must be in the database for each member that has one or more messages in the database
        - all packets in the database must be valid
        - check sequence numbers for FullSyncDistribution
        - check history size for LastSyncDistribution
        """
        def select(sql, bindings):
            assert isinstance(sql, unicode)
            assert isinstance(bindings, tuple)
            limit = 1000
            for offset in (i * limit for i in count()):
                rows = list(self._database.execute(sql, bindings + (limit, offset)))
                if rows:
                    for row in rows:
                        yield row
                else:
                    break

        self._logger.debug("%s start sanity check [database-id:%d]", community.cid.encode("HEX"), community.database_id)
        enabled_messages = set(meta.database_id for meta in community.get_meta_messages())

        if test_identity:
            try:
                # ensure that the dispersy-identity for my member must be in the database
                meta_identity = community.get_meta_message(u"dispersy-identity")

                try:
                    member_id, = self._database.execute(u"SELECT id FROM member WHERE mid = ?", (buffer(community.my_member.mid),)).next()
                except StopIteration:
                    raise ValueError("unable to find the public key for my member")

                if not member_id == community.my_member.database_id:
                    raise ValueError("my member's database id is invalid", member_id, community.my_member.database_id)

                try:
                    self._database.execute(u"SELECT 1 FROM member WHERE id = ? AND private_key IS NOT NULL", (member_id,)).next()
                except StopIteration:
                    raise ValueError("unable to find the private key for my member")

                try:
                    self._database.execute(u"SELECT 1 FROM sync WHERE member = ? AND meta_message = ?", (member_id, meta_identity.database_id)).next()
                except StopIteration:
                    raise ValueError("unable to find the dispersy-identity message for my member")

                self._logger.debug("my identity is OK")

                #
                # the dispersy-identity must be in the database for each member that has one or more
                # messages in the database
                #
                A = set(id_ for id_, in self._database.execute(u"SELECT member FROM sync WHERE community = ? GROUP BY member", (community.database_id,)))
                B = set(id_ for id_, in self._database.execute(u"SELECT member FROM sync WHERE meta_message = ?", (meta_identity.database_id,)))
                if not len(A) == len(B):
                    raise ValueError("inconsistent dispersy-identity messages.", A.difference(B))

            except MetaNotFoundException:
                # identity is not enabled
                pass

        if test_undo_other:
            try:
                # ensure that we have proof for every dispersy-undo-other message
                meta_undo_other = community.get_meta_message(u"dispersy-undo-other")

                # TODO we are not taking into account that undo messages can be undone
                for undo_packet_id, undo_packet_global_time, undo_packet in select(u"SELECT id, global_time, packet FROM sync WHERE community = ? AND meta_message = ? ORDER BY id LIMIT ? OFFSET ?", (community.database_id, meta_undo_other.database_id)):
                    undo_packet = str(undo_packet)
                    undo_message = self.convert_packet_to_message(undo_packet, community, verify=False)

                    # 10/10/12 Boudewijn: the check_callback is required to obtain the
                    # message.payload.packet
                    for _ in undo_message.check_callback([undo_message]):
                        pass

                    # get the message that undo_message refers to
                    try:
                        packet, undone = self._database.execute(u"SELECT packet, undone FROM sync WHERE community = ? AND member = ? AND global_time = ?", (community.database_id, undo_message.payload.member.database_id, undo_message.payload.global_time)).next()
                    except StopIteration:
                        raise ValueError("found dispersy-undo-other but not the message that it refers to")
                    packet = str(packet)
                    message = self.convert_packet_to_message(packet, community, verify=False)

                    if not undone:
                        raise ValueError("found dispersy-undo-other but the message that it refers to is not undone")

                    if message.undo_callback is None:
                        raise ValueError("found dispersy-undo-other but the message that it refers to does not have an undo_callback")

                    # get the proof that undo_message is valid
                    allowed, proofs = community.timeline.check(undo_message)

                    if not allowed:
                        raise ValueError("found dispersy-undo-other that, according to the timeline, is not allowed")

                    if not proofs:
                        raise ValueError("found dispersy-undo-other that, according to the timeline, has no proof")

                    self._logger.debug("dispersy-undo-other packet %d@%d referring %s %d@%d is OK",
                                       undo_packet_id, undo_packet_global_time,
                                       undo_message.payload.packet.name,
                                       undo_message.payload.member.database_id,
                                       undo_message.payload.global_time)


            except MetaNotFoundException:
                # undo-other is not enabled
                pass

        if test_binary:
            #
            # ensure all packets in the database are valid and that the binary packets are consistent
            # with the information stored in the database
            #
            for packet_id, member_id, global_time, meta_message_id, packet in select(u"SELECT id, member, global_time, meta_message, packet FROM sync WHERE community = ? ORDER BY id LIMIT ? OFFSET ?", (community.database_id,)):
                if meta_message_id in enabled_messages:
                    packet = str(packet)
                    message = self.convert_packet_to_message(packet, community, verify=True)

                    if not message:
                        raise ValueError("unable to convert packet ", packet_id, "@", global_time, " to message")

                    if not member_id == message.authentication.member.database_id:
                        raise ValueError("inconsistent member in packet ", packet_id, "@", global_time)

                    if not message.authentication.member.public_key:
                        raise ValueError("missing public key for member ", member_id, " in packet ", packet_id, "@", global_time)

                    if not global_time == message.distribution.global_time:
                        raise ValueError("inconsistent global time in packet ", packet_id, "@", global_time)

                    if not meta_message_id == message.database_id:
                        raise ValueError("inconsistent meta message in packet ", packet_id, "@", global_time)

                    if not packet == message.packet:
                        raise ValueError("inconsistent binary in packet ", packet_id, "@", global_time)

                    self._logger.debug("packet %d@%d is OK", packet_id, global_time)

        if test_sequence_number:
            for meta in community.get_meta_messages():
                #
                # ensure that we have all sequence numbers for FullSyncDistribution packets
                #
                if isinstance(meta.distribution, FullSyncDistribution) and meta.distribution.enable_sequence_number:
                    counter = 0
                    counter_member_id = 0
                    exception = None
                    for packet_id, member_id, packet in select(u"SELECT id, member, packet FROM sync WHERE meta_message = ? ORDER BY member, global_time LIMIT ? OFFSET ?", (meta.database_id,)):
                        packet = str(packet)
                        message = self.convert_packet_to_message(packet, community, verify=False)
                        assert message

                        if member_id != counter_member_id:
                            counter_member_id = member_id
                            counter = 1
                            if exception:
                                break

                        if not counter == message.distribution.sequence_number:
                            self._logger.error("%s for member %d has sequence number %d expected %d\n%s",
                                               meta.name, member_id,
                                               message.distribution.sequence_number, counter, packet.encode("HEX"))
                            exception = ValueError("inconsistent sequence numbers in packet ", packet_id)

                        counter += 1

                    if exception:
                        raise exception

        if test_last_sync:
            for meta in community.get_meta_messages():
                #
                # ensure that we have only history-size messages per member
                #
                if isinstance(meta.distribution, LastSyncDistribution):
                    if meta.distribution.custom_callback:
                        continue

                    if isinstance(meta.authentication, MemberAuthentication):
                        counter = 0
                        counter_member_id = 0
                        for packet_id, member_id, packet in select(u"SELECT id, member, packet FROM sync WHERE meta_message = ? ORDER BY member ASC, global_time DESC LIMIT ? OFFSET ?", (meta.database_id,)):
                            message = self.convert_packet_to_message(str(packet), community, verify=False)
                            assert message

                            if member_id == counter_member_id:
                                counter += 1
                            else:
                                counter_member_id = member_id
                                counter = 1

                            if counter > meta.distribution.history_size:
                                raise ValueError("pruned packet ", packet_id, " still in database")

                            self._logger.debug("LastSyncDistribution for %s is OK", meta.name)

                    else:
                        assert isinstance(meta.authentication, DoubleMemberAuthentication)
                        for packet_id, member_id, packet in select(u"SELECT id, member, packet FROM sync WHERE meta_message = ? ORDER BY member ASC, global_time DESC LIMIT ? OFFSET ?", (meta.database_id,)):
                            message = self.convert_packet_to_message(str(packet), community, verify=False)
                            assert message

                            try:
                                member1, member2 = self._database.execute(u"SELECT member1, member2 FROM double_signed_sync WHERE sync = ?", (packet_id,)).next()
                            except StopIteration:
                                raise ValueError("found double signed message without an entry in the double_signed_sync table")

                            if not member1 < member2:
                                raise ValueError("member1 (", member1, ") must always be smaller than member2 (", member2, ")")

                            if not (member1 == member_id or member2 == member_id):
                                raise ValueError("member1 (", member1, ") or member2 (", member2, ") must be the message creator (", member_id, ")")

                        self._logger.debug("LastSyncDistribution for %s is OK", meta.name)

        self._logger.debug("%s success", community.cid.encode("HEX"))

    def _flush_database(self):
        """
        Periodically called to commit database changes to disk.
        """
        try:
            # flush changes to disk every 1 minutes
            self._database.commit()

        except Exception as exception:
            # OperationalError: database is locked
            self._logger.exception("%s", exception)

    # TODO(emilon): Shouldn't start() just raise an exception if something goes wrong?, that would clean up a lot of cruft
    @blocking_call_on_reactor_thread
    def start(self, autoload_discovery=True):
        """
        Starts Dispersy.

        1. opens database
        2. opens endpoint
        3. loads the DiscoveryCommunity
        """

        assert isInIOThread()

        if self.running:
            raise RuntimeError("Dispersy is already running")

        # start
        self._logger.info("starting the Dispersy core...")
        results = []

        assert all(isinstance(result, bool) for _, result in results), [type(result) for _, result in results]

        results.append((u"database", self._database.open()))
        assert all(isinstance(result, bool) for _, result in results), [type(result) for _, result in results]

        results.append((u"endpoint", self._endpoint.open(self)))
        assert all(isinstance(result, bool) for _, result in results), [type(result) for _, result in results]
        self._endpoint_ready()

        # commit changes to the database periodically
        self.register_task("flush_database", LoopingCall(self._flush_database)).start(FLUSH_DATABASE_INTERVAL)
        # output candidate statistics
        self.register_task("candidates",
                           LoopingCall(self._stats_detailed_candidates)).start(STATS_DETAILED_CANDIDATES_INTERVAL)

        # log and return the result
        if all(result for _, result in results):
            self._logger.info("Dispersy core ready (database: %s, port:%d)",
                        self._database.file_path, self._endpoint.get_address()[1])
            self.running = True

            if autoload_discovery:
                # Load DiscoveryCommunity
                self._logger.info("Dispersy core loading DiscoveryCommunity")

                # TODO: pass None instead of new member, let community decide if we need a new member or not.
                self._discovery_community = self.define_auto_load(DiscoveryCommunity, self.get_new_member(), load=True)[0]
            return True

        else:
            self._logger.error("Dispersy core unable to start all components [%s]",
                         ", ".join("{0}:{1}".format(key, value) for key, value in results))
            return False

    @blocking_call_on_reactor_thread
    @inlineCallbacks
    def stop(self, timeout=10.0):
        """
        Stops Dispersy.

        1. unload all communities
           in reverse define_auto_load order, starting with all undefined communities
        2. closes endpoint
        3. closes database

        Returns False when Dispersy isn't running, or when one of the above steps fails.  Otherwise True is returned.

        Note that attempts will be made to process each step, even if one or more steps fail.  For
        example, when 'close endpoint' reports a failure the databases still be closed.

        """
        assert isInIOThread()
        assert isinstance(timeout, float), type(timeout)
        assert 0.0 <= timeout, timeout

        if not self.running:
            raise RuntimeError("Dispersy is not running")

        self.running = False

        self.cancel_all_pending_tasks()

        @inlineCallbacks
        def unload_communities(communities):
            for community in communities:
                if community.cid in self._communities:
                    self._logger.debug("Unloading %s (the reactor has %s delayed calls scheduled)",
                                       community, len(reactor.getDelayedCalls()))
                    yield community.unload_community()
                    self._logger.debug("Unloaded  %s (the reactor has %s delayed calls scheduled now)",
                                       community, len(reactor.getDelayedCalls()))
                else:
                    self._logger.warning("Attempting to unload %s which is not loaded", community)

        self._logger.info('Stopping Dispersy Core..')
        if os.environ.get("DISPERSY_PRINT_STATISTICS", "False").lower() == "true":
            # output statistics before we stop
            if self._logger.isEnabledFor(logging.DEBUG):
                self._statistics.update()
                self._logger.debug("\n%s", pformat(self._statistics.get_dict(), width=120))
        _runtime_statistics.clear()

        self._logger.info("stopping the Dispersy core...")
        results = {}

        # unload communities that are not defined
        yield unload_communities([community
                            for community
                            in self._communities.itervalues()
                            if not community.get_classification() in self._auto_load_communities])

        # unload communities in reverse auto load order
        for classification in reversed(self._auto_load_communities):
            yield unload_communities([community
                                for community
                                in self._communities.itervalues()
                                if community.get_classification() == classification])


        # stop endpoint
        results[u"endpoint"] = maybeDeferred(self._endpoint.close, timeout)

        # stop the database
        results[u"database"] = maybeDeferred(self._database.close)

        def check_stop_status(return_values):
            failures = []
            self._logger.debug("Checking dispersy stop results")
            for name, result in zip(results.keys(), return_values):
                if isinstance(result, Failure) or not result:
                    failures.append((name, result))
            if failures:
                self._logger.error("Dispersy stop failed due to: %s", failures)
                return False
            return True

        success = yield gatherResults(results.values(), consumeErrors=True).addBoth(check_stop_status)
        returnValue(success)

    def _stats_detailed_candidates(self):
        """
        Periodically logs a detailed list of all candidates (walk, stumble, intro, none) for all
        communities.

        Enable this output by enabling DEBUG logging for a logger named
        "dispersy-stats-detailed-candidates".

        Exception: all communities with classification "PreviewChannelCommunity" are ignored.
        """
        summary = logging.getLogger("dispersy-stats-detailed-candidates")
        if summary.isEnabledFor(logging.DEBUG):
            now = time()
            summary.debug("--- %s:%d (%s:%d) %s", self.lan_address[0], self.lan_address[1], self.wan_address[0], self.wan_address[1], self.connection_type)
            summary.debug("walk-attempt %d; success %d; invalid %d",
                self._statistics.walk_attempt_count,
                self._statistics.walk_success_count,
                self._statistics.invalid_response_identifier_count)

            for community in sorted(self._communities.itervalues(), key=lambda community: community.cid):
                if community.get_classification() == u"PreviewChannelCommunity":
                    continue

                categories = {u"walk": [], u"stumble": [], u"intro": [], u"discovered": [], None: []}
                for candidate in community.candidates.itervalues():
                    if isinstance(candidate, WalkCandidate):
                        categories[candidate.get_category(now)].append(candidate)

                summary.debug("--- %s %s ---", community.cid.encode("HEX"), community.get_classification())
                summary.debug("--- [%2d:%2d:%2d:%2d]", len(categories[u"walk"]), len(categories[u"stumble"]), len(categories[u"intro"]), len(categories[u"discovered"]))

                for category, candidates in categories.iteritems():
                    aged = [(candidate.age(now, category), candidate) for candidate in candidates]
                    for age, candidate in sorted(aged):
                        summary.debug("%5.1fs %s%s %-7s %-13s %s",
                                      min(age, 999.0),
                                      "O" if candidate.get_category(now) is None else " ",
                                      "E" if candidate.is_eligible_for_walk(now) else " ",
                                      category,
                                      candidate.connection_type,
                                      candidate)
        else:
            self.cancel_pending_task("candidates")
