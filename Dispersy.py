"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from Bloomfilter import BloomFilter
from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from DispersyDatabase import DispersyDatabase
from Distribution import SyncDistribution, FullSyncDistribution, LastSyncDistribution, DirectDistribution
from Member import MyMember
from Message import DelayPacket, DropPacket, DelayMessage, DelayMessageBySequence, DropMessage
from Permission import PermitPermission
from Singleton import Singleton
from Destination import CommunityDestination, AddressDestination

if __debug__:
    from Print import dprint

class DummySocket(object):
    def send(address, data):
        pass
        
class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self, working_directory):
        # where we store all data
        self._working_directory = working_directory

        # our data storage
        self._database = DispersyDatabase.get_instance(working_directory)

        try:
            public_pem = str(self._database.execute(u"SELECT value FROM option WHERE key == 'my_public_pem' LIMIT 1").next()[0])
            private_pem = None
        except StopIteration:
            # one of the keys was not found in the database, we need
            # to generate a new one
            rsa = rsa_generate_key(512)
            public_pem = rsa_to_public_pem(rsa)
            private_pem = rsa_to_private_pem(rsa)
            self._database.execute(u"INSERT INTO option VALUES('my_public_pem', ?)", (buffer(public_pem),))
            
        # this is yourself
        self._my_member = MyMember.get_instance(public_pem, private_pem)

        # all available communities.  cid:Community pairs.
        self._communities = {}

        # outgoing communication
        self._socket = DummySocket()

        # messages that are delayed (because previous messages were
        # missing)
        self._delayed = {}
        self._check_delayed_map = {FullSyncDistribution.Implementation:self._check_delayed_full_sync_distribution,
                                   LastSyncDistribution.Implementation:self._check_delayed_last_sync_distribution,
                                   DirectDistribution.Implementation:self._check_delayed_direct_distribution}

        self._incoming_distribution_map = {FullSyncDistribution.Implementation:self._check_incoming_full_sync_distribution,
                                           LastSyncDistribution.Implementation:self._check_incoming_last_sync_distribution,
                                           DirectDistribution.Implementation:self._check_incoming_direct_distribution}

    @property
    def working_directory(self):
        return self._working_directory

    @property
    def socket(self):
        return self._socket

    def set_socket(self, socket):
        self._socket = socket

    @property
    def my_member(self):
        return self._my_member

    @property
    def database(self):
        """
        Returns the Dispersy database.

        This is the same as: DispersyDatabase.get_instance([working_directory])
        """
        return self._database

    def add_community(self, community):
        if __debug__:
            from Community import Community
        assert isinstance(community, Community)
        assert not community.cid in self._communities
        self._communities[community.cid] = community

    def get_community(self, cid):
        assert isinstance(cid, str)
        return self._communities[cid]

    def _delay_packet(self, address, packet, delay):
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(delay, DelayPacket)
        dprint(delay)

    def _delay_message(self, address, packet, message, delay):
        if __debug__:
            from Message import Message
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(message, Message)
        assert isinstance(delay, DelayMessage)
        if isinstance(delay, DelayMessageBySequence):
            key = "community:{0.community.database_id} user:{0.signed_by.database_id} privilege:{0.permission.privilege.database_id} sequence:{1.missing_high}".format(message, delay)
            if not key in self._delayed:
                dprint(delay)
                dprint(key)
                self._delayed[key] = (address, packet, message)

                # request the missing data
                message.community.permit(PermitPermission(message.community.get_privilege(u"dispersy-missing-sequence"), {"user":message.signed_by.pem, "privilege":message.permission.privilege.name, "missing_low":delay.missing_low, "missing_high":delay.missing_high}), destination=(address,), update_locally=False)
                
        else:
            raise NotImplementedError(delay)

    def _check_delayed_full_sync_distribution(self, message):
        key = "community:{0.community.database_id} user:{0.signed_by.database_id} privilege:{0.permission.privilege.database_id} sequence:{0.distribution.sequence_number}".format(message)
        if __debug__:
            if key in self._delayed:
                dprint(key)
        return self._delayed.pop(key, None)

    def _check_delayed_last_sync_distribution(self, message):
        pass

    def _check_delayed_direct_distribution(self, message):
        pass

    def _check_delayed_OTHER_distribution(self, message):
        raise NotImplementedError(message.distribution)

    def _check_incoming_full_sync_distribution(self, message):
        try:
            sequence, = self._database.execute(u"""
SELECT sequence
FROM sync_full
LEFT JOIN privilege ON (sync_full.privilege = privilege.id)
WHERE sync_full.user = ? AND privilege.community = ?
ORDER BY sequence DESC
LIMIT 1""",
                                              (message.signed_by.database_id,
                                               message.community.database_id)).next()
        except StopIteration:
            sequence = 0
            
        # (1) we already have this message (drop)
        if sequence >= message.distribution.sequence_number:
            raise DropMessage("duplicate message")

        # (3) we have the previous message (process)
        elif sequence + 1 == message.distribution.sequence_number:
            return

        # (2) we do not have the previous message (delay and request)
        else:
            raise DelayMessageBySequence(sequence+1, message.distribution.sequence_number-1)

        assert False

    def _check_incoming_last_sync_distribution(self, message):
        try:
            self._database.execute(u"""
SELECT 1
FROM sync_last
WHERE user = ? AND privilege = ? AND global > ?
LIMIT 1""",
                                   (message.signed_by.database_id,
                                    message.permission.privilege.database_id,
                                    message.distribution.global_time)).next()
        except StopIteration:
            return
        raise DropMessage("duplicate or older message")

    def _check_incoming_direct_distribution(self, message):
        return

    def _check_incoming_OTHER_distribution(self, message):
        raise NotImplementedError(message.distribution)

    def on_incoming_packets(self, packets):
        """
        Incoming PACKETS were received.

        PACKETS is a list containing one or more (ADDRESS, DATA) pairs
        where ADDRESS is a (HOST, PORT) tuple and DATA is a string.
        """
        assert isinstance(packets, (tuple, list))
        assert len(packets) > 0
        assert not filter(lambda x: not len(x) == 2, packets)

        for address, packet in packets:
            assert isinstance(address, tuple)
            assert isinstance(address[0], str)
            assert isinstance(address[1], int)
            assert isinstance(packet, str)

            #
            # Find associated community
            #
            try:
                community = self.get_community(packet[:20])
            except KeyError:
                dprint("drop a ", len(packet), " byte packet (received packet for unknown community) from ", address[0], ":", address[1])
                continue

            #
            # Find associated conversion
            #
            try:
                conversion = community.get_conversion(packet[:25])
            except KeyError:
                dprint("drop a ", len(packet), " byte packet (received packet for unknown conversion) from ", address[0], ":", address[1])
                continue

            try:
                #
                # Converty binary date to internal Message
                #
                message = conversion.decode_message(packet)

                #
                # Update routing table.  We know that some peer (not
                # necessarily message.signed_by) exists at this
                # address.
                #
                self._database.execute(u"INSERT OR REPLACE INTO routing(community, host, port, time) VALUES(?, ?, ?, DATETIME())",
                                       (message.community.database_id, unicode(address[0]), address[1]))

                #
                # Filter messages based on distribution (usually
                # duplicate or old messages)
                #
                self._incoming_distribution_map.get(type(message.distribution), self._check_incoming_OTHER_distribution)(message)

                while True:
                    #
                    # Allow community code to handle the message
                    #
                    if __debug__: dprint("incoming ", message.permission.privilege.name, "^", message.permission.name, " (", len(packet), " bytes)")
                    community.on_incoming_message(address, packet, message)

                    #
                    # Sync messages need to be stored (so they can be
                    # synced later)
                    #
                    if isinstance(message.distribution, SyncDistribution.Implementation):
                        self._store(packet, message)

                    #
                    # This message may 'trigger' a previously delayed message
                    #
                    tup = self._check_delayed_map.get(type(message.distribution), self._check_delayed_OTHER_distribution)(message)
                    if tup:
                        address, packet, message = tup
                    else:
                        break

            except DropPacket as exception:
                dprint("drop a ", len(packet), " byte packet (", exception, ") from ", address[0], ":", address[1])
                continue

            except DelayPacket as delay:
                self._delay_packet(address, packet, delay)
                continue

            except DropMessage as exception:
                dprint("drop a ", len(packet), " byte message (", exception, ") from ", address[0], ":", address[1])
                continue
            
            except DelayMessage as delay:
                self._delay_message(address, packet, message, delay)
                continue

    def _store(self, packet, message):
        distribution = message.distribution
        if isinstance(distribution, FullSyncDistribution.Implementation):
            self._database.execute(u"INSERT INTO sync_full(user, privilege, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                   (message.signed_by.database_id,
                                    message.permission.privilege.database_id,
                                    distribution.global_time,
                                    distribution.sequence_number,
                                    buffer(packet)))

        elif isinstance(distribution, LastSyncDistribution.Implementation):
            self._database.execute(u"INSERT OR REPLACE INTO sync_last(user, privilege, global, packet) VALUES(?, ?, ?, ?)",
                                   (message.signed_by.database_id,
                                    message.permission.privilege.database_id,
                                    distribution.global_time,
                                    buffer(packet)))

        elif isinstance(distribution, DirectDistribution.Implementation):
            # we do not store for DirectDistribution
            pass
        
        else:
            raise NotImplementedError(distribution)

    def store_and_forward(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes.
        """
        if __debug__:
            from Message import Message
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert not filter(lambda x: not isinstance(x, Message), messages)

        addresses = [(str(host), port) for host, port in self._database.execute(u"SELECT DISTINCT host, port FROM routing ORDER BY time DESC LIMIT 10")]

        for message in messages:
            packet = message.community.get_conversion().encode_message(message)

            # Store
            self._store(packet, message)

            # Forward
            if isinstance(message.destination, CommunityDestination.Implementation):
                for address in addresses:
                    if __debug__: dprint(message.permission.privilege.name, "^", message.permission.name, " (", len(packet), " bytes) to ", address[0], ":", address[1])
                    self._socket.send(address, packet)

            elif isinstance(message.destination, AddressDestination.Implementation):
                if __debug__: dprint(message.permission.privilege.name, "^", message.permission.name, " (", len(packet), " bytes) to ", message.destination.address[0], ":", message.destination.address[1])
                self._socket.send(message.destination.address, packet)

            else:
                raise NotImplementedError(message.destination)

    def on_sync_message(self, address, message):
        # todo: ensure that the payload is correct
        if __debug__:
            from Message import Message
        assert isinstance(message, Message)

        packets = []
        for privilege_name, bloom in message.permission.payload:
            privilege = message.community.get_privilege(privilege_name)
            distribution = privilege.distribution
            if isinstance(distribution, FullSyncDistribution):
                for packet, in self._database.execute(u"SELECT packet FROM sync_full WHERE privilege = ? ORDER BY global, sequence", (privilege.database_id,)):
                    packet = str(packet)
                    if not packet in bloom:
                        packets.append(packet)
            else:
                raise NotImplementedError(distribution)

        # Send
        dprint("Syncing ", len(packets), " packets to ", address[0], ":", address[1])
        for packet in packets:
            dprint("Syncing ", len(packet), " bytes to " , address[0], ":", address[1])
            self._socket.send(address, packet)

    def periodically_disperse(self):
        yield 1.0

        while True:
            yield 1.0

            addresses = [(str(host), port) for host, port in self._database.execute(u"SELECT DISTINCT host, port FROM routing ORDER BY time LIMIT 10")]

            sending_global_time = 0
            sending_packet = None

            #
            # Advertise the packages that we sync.  This means sending
            # a 'sync' message containing one or more bloom filters.
            #
            # Todo: currently we construct the bloomfilter on the fly,
            # this should be updated in memory instead.
            for community in self._communities.itervalues():
                payload = []
                for privilege in community.get_privileges():
                    distribution = privilege.distribution
                    if isinstance(distribution, SyncDistribution):
                        # todo: we are ignoring privilege.distribution.stepping for now
                        bloom = BloomFilter(distribution.capacity, distribution.error_rate)

                        if isinstance(distribution, FullSyncDistribution):
                            for packet, in self._database.execute(u"SELECT packet FROM sync_full WHERE privilege = ?", (privilege.database_id,)):
                                bloom.add(str(packet))
                        elif isinstance(distribution, LastSyncDistribution):
                            for packet, in self._database.execute(u"SELECT packet FROM sync_last WHERE privilege = ?", (privilege.database_id,)):
                                bloom.add(str(packet))
                        else:
                            raise NotImplementedError(distribution)

                        payload.append((privilege.name, str(bloom)))

                community.permit(PermitPermission(community.get_privilege(u"dispersy-sync"), tuple(payload)), update_locally=False)


