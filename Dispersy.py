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
from Message import DelayPacket, DropPacket, DelayMessage, DelayMessageBySequence, DropMessage, FullSyncDistribution
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
        assert not community.get_cid() in self._communities
        self._communities[community.get_cid()] = community

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
            from Message import MessageBase
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(message, MessageBase)
        assert isinstance(delay, DelayMessage)
        dprint(delay)

    def _drop_message(self, address, packet, message, drop):
        if __debug__:
            from Message import MessageBase
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(message, MessageBase)
        assert isinstance(delay, DropMessage)
        dprint("drop a ", len(packet), " byte message")

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
                dprint("received packet for unknown community")
                continue

            #
            # Find associated conversion
            #
            try:
                conversion = community.get_conversion(packet[:25])
            except KeyError:
                dprint("received packet for unknown conversion")
                continue

            #
            # Converty binary date to internal Message
            #
            try:
                message = conversion.decode_message(packet)

            except DropPacket as exception:
                dprint("drop a ", len(packet), " byte packet", exception=True)
                continue

            except DelayPacket as exception:
                self._delay_packet(address, packet, exception)
                continue

            #
            # Drop duplicate messages
            #

            # todo: message.distribution specific!
            try:
                self._database.execute(u"SELECT 1 FROM sync_full WHERE user = ? and community = ? and sequence = ? LIMIT 1",
                                       (message.signed_by.get_database_id(), message.community.get_database_id(), message.distribution.sequence_number)).next()
            except StopIteration:
                # We have not received this message yet, this is good.
                pass
            else:
                dprint("drop a ", len(packet), " byte message. %s")
                continue

            #
            # Update routing table.  We know that some peer (not
            # necessarily message.signed_by) exists at this address.
            #
            self._database.execute(u"INSERT OR REPLACE INTO routing(user, host, port, time) VALUES(?, ?, ?, DATETIME())",
                                   (message.signed_by.get_database_id(),
                                    unicode(address[0]),
                                    address[1]))

            try:
                if message.is_dispersy_specific:
                    community.on_incoming_dispersy_message(address, packet, message)
                else:
                    community.on_incoming_message(address, packet, message)

            except DropMessage as exception:
                self._drop_message(address, packet, message, exception)
                continue
                                
            except DelayMessage as exception:
                self._delay_message(address, packet, message, exception)
                continue

    def queue_outgoing_messages(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes and oneself.
        """
        if __debug__:
            from Message import MessageBase
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert not filter(lambda x: not isinstance(x, MessageBase), messages)

        for message in messages:
            packet = message.community.get_conversion().encode_message(message)
            distribution = message.distribution

            if isinstance(distribution, FullSyncDistribution):
                self._database.execute(u"INSERT INTO sync_full(user, community, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                       (message.signed_by.get_database_id(),
                                        message.community.get_database_id(),
                                        distribution.global_time,
                                        distribution.sequence_number,
                                        buffer(packet)))

            else:
                raise NotImplemented()

            # todo: use self._socket so send

    def periodically_disperse(self):
        while True:
            for host, port in self._database.execute(u"SELECT host, port FROM routing ORDER BY time"):
                dprint("Try: ", host, ":", port)
                # message = DirectMessage

                yield 1.0

            yield 5.0


