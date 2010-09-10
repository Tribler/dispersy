"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from Crypto import rsa_generate_key, rsa_to_public_pem, rsa_to_private_pem
from DispersyDatabase import DispersyDatabase
from Singleton import Singleton
from Member import MyMember
from Message import DelayPacket, DropPacket, DelayMessage, DelayMessageBySequence, DropMessage, SyncDistribution, FullSyncDistribution, LastSyncDistribution
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

    def get_working_directory(self):
        return self._working_directory

    def get_socket(self):
        return self._socket

    def set_socket(self, socket):
        self._socket = socket

    def get_my_member(self):
        return self._my_member

    def get_database(self):
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
        dprint(delay)

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

            #
            # Converty binary date to internal Message
            #
            try:
                message = conversion.decode_message(packet)

            except DropPacket as exception:
                dprint("drop a ", len(packet), " byte packet (", exception, ") from ", address[0], ":", address[1])
                continue

            except DelayPacket:
                self._delay_packet(address, packet, exception)
                continue

            #
            # Update routing table.  We know that some peer (not
            # necessarily message.signed_by) exists at this address.
            #
            self._database.execute(u"INSERT OR REPLACE INTO routing(community, host, port, time) VALUES(?, ?, ?, DATETIME())",
                                   (message.community.database_id, unicode(address[0]), address[1]))

            try:
                community.on_incoming_message(address, packet, message)

            except DropMessage as exception:
                dprint("drop a ", len(packet), " byte message (", exception, ") from ", address[0], ":", address[1])
                continue
                                
            except DelayMessage as exception:
                self._delay_message(address, packet, message, exception)
                continue

            #
            # Sync messages need to be stored and forwarded
            #
            if isinstance(message.distribution, SyncDistribution):
                self._store(packet, message)

    def _store(self, packet, message):
        distribution = message.distribution
        if isinstance(distribution, FullSyncDistribution):
            self._database.execute(u"INSERT INTO sync_full(user, community, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                   (message.signed_by.database_id,
                                    message.community.database_id,
                                    distribution.global_time,
                                    distribution.sequence_number,
                                    buffer(packet)))

        elif isinstance(distribution, LastSyncDistribution):
            self._database.execute(u"INSERT OR REPLACE INTO sync_last(community, user, privilege, global, packet) VALUES(?, ?, ?, ?, ?)",
                                   (message.community.database_id,
                                    message.signed_by.database_id,
                                    message.permission.privilege.name,
                                    distribution.global_time,
                                    buffer(packet)))

        else:
            raise NotImplementedError()

    def store_and_forward(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes.
        """
        if __debug__:
            from Message import Message
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert not filter(lambda x: not isinstance(x, Message), messages)

        addresses = [(str(host), port) for host, port in self._database.execute(u"SELECT DISTINCT host, port FROM routing ORDER BY time LIMIT 10")]

        for message in messages:
            packet = message.community.get_conversion().encode_message(message)

            # Store
            self._store(packet, message)

            # Forward
            for address in addresses:
                dprint("Try sending ", len(packet), " bytes to ", address[0], ":", address[1])
                self._socket.send(address, packet)


    def periodically_disperse(self):
        # yield False

        while True:

            addresses = [(str(host), port) for host, port in self._database.execute(u"SELECT DISTINCT host, port FROM routing ORDER BY time LIMIT 10")]

            sending_global_time = 0
            sending_packet = None

            try:
                global_time, packet = self._database.execute(u"SELECT global, packet FROM sync_full ORDER BY global DESC LIMIT 1").next()
            except StopIteration:
                global_time = 0
            if global_time > sending_global_time:
                sending_global_time = global_time
                sending_packet = packet

            try:
                global_time, packet = self._database.execute(u"SELECT global, packet FROM sync_minimal ORDER BY global DESC LIMIT 1").next()
            except StopIteration:
                global_time = 0
            if global_time > sending_global_time:
                sending_global_time = global_time
                sending_packet = packet

            try:
                global_time, packet = self._database.execute(u"SELECT global, packet FROM sync_last ORDER BY global DESC LIMIT 1").next()
            except StopIteration:
                global_time = 0
            if global_time > sending_global_time:
                sending_global_time = global_time
                sending_packet = packet

            if sending_global_time > 0:
                for address in addresses:
                    dprint("Try sending ", len(packet), " bytes to ", address[0], ":", address[1])
                    self._socket.send(address, packet)

            yield 30.0


