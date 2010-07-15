"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from os import path
from traceback import print_exc

from Crypto import rsa_generate_key, rsa_to_private_pem
from DispersyDatabase import DispersyDatabase
from Singleton import Singleton
from Member import MyMember
from Message import DelayPacket, DelayMessage, DelayMessageBySequence, DropMessage, FullSyncDistribution

class DummySocket(object):
    def send(address, data):
        pass
        
class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self, statedir):
        # our data storage
        self._database = DispersyDatabase.get_instance(path.join(statedir, u"dispersy.db"))

        try:
            pem = self._database.execute(u"SELECT value FROM option WHERE key == 'my_key_pair' LIMIT 1").next()[0]
        except StopIteration:
            # one of the keys was not found in the database, we need
            # to generate a new one
            pem = rsa_to_private_pem(rsa_generate_key(512))
            self._database.execute(u"INSERT INTO option VALUES('my_key_pair', ?)", (pem,))
            
        # this is yourself
        self._my_member = MyMember(pem)

        # all available communities.  cid:Community pairs.
        self._communities = {}

        # outgoing communication
        self._socket = DummySocket()

    def set_socket(self, socket):
        self._socket = socket

    def get_my_member(self):
        return self._my_member

    def get_database(self):
        """
        Returns the Dispersy database.

        This is the same as: DispersyDatabase.get_instance()
        """
        return self._database

    def add_community(self, community):
        if __debug__:
            from Community import Community
            assert isinstance(community, Community)
        self._communities[community.get_cid()] = community

    def get_community(self, cid):
        assert isinstance(cid, buffer)
        return self._communities[cid]

    def _delay_packet(self, address, packet, delay):
        assert isinstance(address, tuple)
        assert len(address) == 2
        assert isinstance(address[0], str)
        assert isinstance(address[1], int)
        assert isinstance(packet, str)
        assert isinstance(delay, DelayPacket)
        print "Dispersy._delay_packet:", delay

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
        print "Dispersy._delay_message:", delay

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
        print "Dispersy.on_incoming_packets: drop a %d byte message. %s" % (len(packet), exception)

    def _check_sequence_numbers(self, message):
        """
        Raises an exception when the sequence_number or global_time is
        invalid.

        DropMessage when values are invalid.
        DelayMessage when value can't be verified (yet).
        """
            
        # last_global_time, last_sequence_number = message.signed_by.get_last_received()

        # if message.distribution.sequence_number <= last_sequence_number:
        #     raise DropMessage("Duplicate message")

        # if message.distribution.sequence_number > last_sequence_number + 1:
        #     raise DelayMessageBySequence(last_sequence_number + 1)

        # if not (message.distribution.global_time >= last_global_time):
        #     raise DropMessage("Manipulating global time")

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
                community = self.get_community(buffer(packet[:20]))
            except KeyError:
                print "Dispersy.on_incoming_packets: received packet for unknown community"
                continue

            #
            # Find associated conversion
            #
            try:
                conversion = community.get_conversion(packet[:25])
            except KeyError:
                print "Dispersy.on_incoming_packets: received packet for unknown conversion"
                continue

            #
            # Converty binary date to internal Message
            #
            try:
                message = conversion.decode_message(packet)

            except DropPacket as exception:
                print "Dispersy.on_incoming_packets: drop a %d byte packet. %s" % (len(packet), exception)
                continue

            except DelayPacket as exception:
                self._delay_packet(address, packet, exception)
                continue

            #
            # Drop duplicate messages
            #
            try:
                self._database.execute(u"SELECT 1 FROM sync WHERE user = ? and community = ? and sequence = ? LIMIT 1",
                                       (message.signed_by.get_database_id(), message.community.get_database_id(), message.distribution.sequence_number)).next()
            except StopIteration:
                # We have not received this message yet, this is good.
                pass
            else:
                print "Dispersy.on_incoming_packets: drop a %d byte message. %s" % (len(packet), exception)
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
                self._database.execute(u"INSERT INTO sync(user, community, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                       (message.signed_by.get_database_id(),
                                        message.community.get_database_id(),
                                        distribution.global_time,
                                        distribution.sequence_number,
                                        buffer(packet)))

            else:
                raise NotImplemented()

            # todo: use self._socket so send
