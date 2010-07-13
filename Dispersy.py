"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from traceback import print_exc

from Crypto import rsa_generate_key, rsa_to_private_pem
from DispersyDatabase import DispersyDatabase
from Singleton import Singleton
from Member import MyMember
from Conversion import DelayMessage
from Message import FullSyncDistribution
        
class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self):
        # our data storage
        self._database = DispersyDatabase.get_instance(":memory:")

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
            
            try:
                community = self.get_community(buffer(packet[:20]))
            except KeyError:
                print "Received packet for unknown community"
            else:

                try:
                    conversion = community.get_conversion(packet[:25])
                except KeyError:
                    print "Received packet for unknown conversion"
                else:

                    try:
                        message = conversion.decode_message(packet)
                    except DelayMessage:
                        # todo: get some trigger from DelayMessage and
                        # store the message until the trigger occurs.
                        print "TODO: Delay packet, %d bytes" % len(packet)

                    except:
                        print "Dropped packet, %d bytes" % len(packet)
                        print_exc()
                    else:

                        try:
                            if message.is_dispersy_specific:
                                community.on_incoming_dispersy_message(address, packet, message)
                            else:
                                community.on_incoming_message(address, packet, message)
                        except DelayMessage:
                            # todo: get some trigger from DelayMessage and
                            # store the message until the trigger occurs.
                            print "TODO: Delay packet, %d bytes" % len(packet)
                            
                        except:
                            print "Dropped message while processing, %d bytes" % len(packet)
                            print_exc()

    def queue_outgoing_messages(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes and oneself.
        """
        if __debug__:
            from Message import MessageBase
        assert isinstance(messages, (tuple, list))
        assert len(messages) > 0
        assert not filter(lambda x: not isinstance(x, MessageBase), messages)

        # inform oneself
        addresses = [("localhost", 0)] * len(messages)
        packets = [message.community.get_conversion().encode_message(message) for message in messages]
        self.on_incoming_packets(zip(addresses, packets))

        # todo: send packets according to the message policy
        for message, packet in zip(messages, packets):
            distribution = message.distribution

            if isinstance(distribution, FullSyncDistribution):
                self._database.execute(u"INSERT INTO full_sync(user, community, global, sequence, packet) VALUES(?, ?, ?, ?, ?)",
                                       (message.signed_by.get_database_id(),
                                        message.community.get_database_id(),
                                        distribution.global_time,
                                        distribution.sequence_number,
                                        buffer(packet)))

            else:
                raise NotImplemented()
