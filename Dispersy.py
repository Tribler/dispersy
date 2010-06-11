"""
To manage social communities in a distributed way, we need to maintain
a list of users and what they are permitted.

This DIStributed PERmission SYstem (or DISPERSY) uses public/private
key cryptography to sign permission grants, allows, and revocations.
When a user has obtained all permission rules the current state of the
community is revealed.
"""

from .Singleton import Singleton
from .Member import Member

class Dispersy(Singleton):
    """
    The Dispersy class provides the interface to all Dispersy related
    commands.  It manages the in- and outgoing data for, possibly,
    multiple communities.
    """

    def __init__(self):
        # our data storage
        database = Database.get_instance()

        # this is yourself
        cursor = database.get_cursor()
        my_public_key = database.execute("SELECT value FROM option WHERE key == 'my_public_key' LIMIT 1").next()[0]
        my_private_key = database.execute("SELECT value FROM option WHERE key == 'my_private_key' LIMIT 1").next()[0]
        self._member = Member(my_public_key, my_private_key)

    def on_incoming_packets(self, packets):
        """
        Incoming PACKETS were received.

        PACKETS is a list containing one or more (ADDRESS, DATA) pairs
        where ADDRESS is a (HOST, PORT) tuple and DATA is a string.
        """
        assert isinstance(packets, list)
        assert len(packets) > 0
        assert not filter(lambda packet: isinstance(packet, tuple) and len(packet) == 2, and isinstance(packet[0], tuple) and isinstance(packet[1], str), packets)

    def queue_outgoing_messages(self, messages):
        """
        Queue MESSAGES to be dispersed to other nodes.

        MESSAGES is a list containing DATA payloads where DATA is a
        string.
        """
        assert isinstance(messages, list)
        assert len(messages) > 0
        assert not filter(lambda data: isinstance(data, str), messages)

    
