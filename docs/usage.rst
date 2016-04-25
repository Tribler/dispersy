*****
Usage
*****

To start using Dispersy you need to first have the Dispersy library in your project. You can find instructions for that
in the installation section.

Payload
=======

The payload in Dispersy defines the individual messages that get send across the network. This is an example of what a
payload can look like:

**A payload with a property 'text'**

.. code-block:: python

    from dispersy.payload import Payload

    class ExamplePayload(Payload):
        class Implementation(Payload.Implementation):
            def __init__(self, meta, text):
                assert isinstance(text, string)
                super(ExamplePayload.Implementation, self).__init__(meta)
                self._text = text

            @property
            def text(self):
                return self._text

In this example we only use a single attribute to store in the payload. You can add more attributes by adding extra
arguments to the *__init__* and making a function to access it. Like showed in the following example:

**A payload with an extra property 'amount'**

.. code-block:: python

    def __init__(self, meta, text, amount):
        assert isinstance(text, string)
        assert isinstance(amount, integer)
        super(ExamplePayload.Implementation, self).__init__(meta)
        self._text = text
        self._amount = amount

    ...

    @property
    def amount(self):
        return self._amount

In the payload you can do validation and type checking. Type checking was already showed in the previous examples by
checking if the attributes are instances of one of the builtin python types. You could also check for the max length for
the 'text' attribute or check if the amount is in between two numbers.

**An unicode text payload with a maximum length of 255 characters**

.. code-block:: python

    from dispersy.payload import Payload

    class TextPayload(Payload):
        class Implementation(Payload.Implementation):
            def __init__(self, meta, text):
                assert isinstance(text, unicode)
                assert len(text.encode("UTF-8")) <= 255
                super(TextPayload.Implementation, self).__init__(meta)
                self._text = text

            @property
            def text(self):
                return self._text

When a message is received this text property is available at message.payload.text

Conversion
==========

The conversion is used to handle the conversion between the Message.Implementation instances used in the code and the
binary string representation on the wire. It also allows you to convert between different versions of the community.

**Example of a conversion**

.. code-block:: python

    from Tribler.Core.Utilities.encoding import encode, decode
    from dispersy.conversion import BinaryConversion
    from dispersy.message import DropPacket


    class ExampleConversion(BinaryConversion):

        def __init__(self, community):
            super(ExampleConversion, self).__init__(community, "\x01")
            self.define_meta_message(chr(1), community.get_meta_message(u"example"), self._encode_example, self._decode_example)

        def _encode_example(self, message):
            packet = encode((message.payload.text, message.payload.amount))
            return packet,

        def _decode_example(self, placeholder, offset, data):
            try:
                offset, payload = decode(data, offset)
            except ValueError:
                raise DropPacket("Unable to decode the example-payload")

            if not isinstance(payload, tuple):
                raise DropPacket("Invalid payload type")

            text, amount = payload
            if not isinstance(text, string):
                raise DropPacket("Invalid 'text' type")
            if not isinstance(amount, integer):
                raise DropPacket("Invalid 'amount' type")

            return offset, placeholder.meta.payload.implement(text, amount)

.. code-block:: python

    super(MarketConversion, self).__init__(community, "\x01")

This line marks the version of the community.
The values '\x00' and '\xff' cannot be used, because they are used to indicate the default conversion and for when
more than one byte is needed to indicate the version respectively. So you start your conversion with '\x01' and when you
need to change something when it is already in use, you need to increase your version number to '\x02'

.. code-block:: python

    self.define_meta_message(chr(1), community.get_meta_message(u"example"), self._encode_example, self._decode_example)

This line is used to indicate how different payload classes should be converted. For each payload you have you need to
add a *define_meta_message* statement. The 'chr(1)' is used to have a small indicator for this payload across the wire.
So each different *define_meta_message* has a different indicator (e.g. chr(2)).
The *community.get_meta_message(u"example")* gets the metadata for the specific payload implementations. It should use
the same name as defined in the community. So in this case the message defined as *example* is retrieved from the
community. The third and the fourth parameter are for specifying the encode and decode functions respectively. In this
case the functions are called *_encode_example* and *_decode_example*. The two functions have the following arguments:

.. code-block:: python

    def _encode_example(self, message):

    def _decode_example(self, placeholder, offset, data):

To make it easier to implement the functions, the following class can be used:
`Encoding utility class <https://github.com/Tribler/tribler/blob/devel/Tribler/Core/Utilities/encoding.py>`_.
It provides functions to convert the data to binary. The encode functions accepts a single object or a tuple of objects
depending on the number of properties in the payload. So a payload with one property would have a encode function like:

**Example of an encode function for one property named 'text'**

.. code-block:: python

    def _encode_example(self, message):
        packet = encode(message.payload.text)
        return packet,

A payload with two properties would have an encode function like this:

**Example of an encode function for two properties named 'text' and 'amount'**

.. code-block:: python

    def _encode_example(self, message):
        packet = encode((message.payload.text, message.payload.amount))
        return packet,

If the payload has more properties then add these to the tuple. The decode functions for the two examples would be:

**Example of a decode function for one property named 'text'**

.. code-block:: python

    def _decode_example(self, placeholder, offset, data):
        try:
            offset, payload = decode(data, offset)
        except ValueError:
            raise DropPacket("Unable to decode the example-payload")

        text = payload

        if not isinstance(text, string):
            raise DropPacket("Invalid 'text' type")

        return offset, placeholder.meta.payload.implement(text)

**Example of a decode function for two properties named 'text' and 'amount'**

.. code-block:: python

    def _decode_example(self, placeholder, offset, data):
        try:
            offset, payload = decode(data, offset)
        except ValueError:
            raise DropPacket("Unable to decode the example-payload")

        if not isinstance(payload, tuple):
            raise DropPacket("Invalid payload type")

        text, amount = payload
        if not isinstance(text, string):
            raise DropPacket("Invalid 'text' type")
        if not isinstance(amount, integer):
            raise DropPacket("Invalid 'amount' type")

        return offset, placeholder.meta.payload.implement(text, amount)

The same validation is used as in the payload to check for malformed messages and drop the packet if found.

Community
=========

A community in Dispersy defines the overlay used for the communication within the network.

**An example of a community**

.. code-block:: python

    import logging

    from .conversion import ExampleConversion
    from .payload import ExamplePayload

    from dispersy.authentication import MemberAuthentication
    from dispersy.community import Community
    from dispersy.conversion import DefaultConversion
    from dispersy.destination import CommunityDestination
    from dispersy.distribution import DirectDistribution
    from dispersy.message import Message, DelayMessageByProof
    from dispersy.resolution import PublicResolution

    logger = logging.getLogger(__name__)


    class ExampleCommunity(Community):

        @classmethod
        def get_master_members(cls, dispersy):
            master_key = "<public-key>".decode("HEX")
            master = dispersy.get_member(public_key=master_key)
            return [master]

        def initialize(self):
            super(ExampleCommunity, self).initialize()
            logger.info("Example community initialized")

        def initiate_meta_messages(self):
            return super(ExampleCommunity, self).initiate_meta_messages() + [
                Message(self, u"example",
                        MemberAuthentication(encoding="sha1"),
                        PublicResolution(),
                        DirectDistribution(),
                        CommunityDestination(node_count=10),
                        ExamplePayload(),
                        self.check_message,
                        self.on_example),
            ]

        def initiate_conversions(self):
            return [DefaultConversion(self), ExampleConversion(self)]

        def check_message(self, messages):
            for message in messages:
                allowed, _ = self._timeline.check(message)
                if allowed:
                    yield message
                else:
                    yield DelayMessageByProof(message)

        def send_example(self, text, amount, store=True, update=True, forward=True):
            logger.debug("sending example")
            meta = self.get_meta_message(u"example")
            message = meta.impl(authentication=(self.my_member,),
                                distribution=(self.claim_global_time(),),
                                payload=((price, quantity, timeout),))
            self.dispersy.store_update_forward([message], store, update, forward)

        def on_example(self, messages):
            for message in messages:
                logger.debug("received example message")

The community consists out of a couple different elements:

Master member
-------------

Each community must define a master member. This member is just a normal Dispersy member that is only used to identify
the community uniquely across the overlay. To create a master member, a public/private cryptography keypair has to be
generated first, which has to be known to all nodes attempting to join.. This can be done with the *createkey.py* tool
located under the *tool* package. Using this tool a *curves* argument can be given to create a key to the strength of
your liking. The recommended curve to use is *high*:

.. code-block:: python

    python createkey.py curves=high

When the key is generated, the pub 170 bits identifier should be copied and put in place of the *<public-key>* in the
following template:

.. code-block:: python

    master_key = "<public-key>".decode("HEX")
    master = dispersy.get_member(public_key=master_key)

There are two ways to add the master member to the community. The first one showed here is the preferred way:

**First approach: Added as part of the definition of the community**

.. code-block:: python

    @classmethod
    def get_master_members(cls, dispersy):
        master_key = "<public-key>".decode("HEX")
        master = dispersy.get_member(public_key=master_key)
        return [master]

With this approach the community has to be created in this way:

.. code-block:: python

    # arguments(<community>, <dispersy_member>, <load: if the community should be loaded>)
    dispersy.define_auto_load(ExampleCommunity, my_member, load=True)


**Second approach: Added when the community is created**

.. code-block:: python

    master_key = "<public-key>".decode("HEX")
    master = dispersy.get_member(public_key=master_key)

    # arguments(<dispersy>, <master_member>, <dispersy_member>)
    community = ExampleCommunity.init_community(dispersy, master, my_member)
    dispersy.attach_community(community)

The first approach is preferred because is stores the identifier as part of the definition of the community and allows
it to be a separate module.

Initialize
----------

The initialize method can be used to perform some tasks right after the community is created. This method is
automatically called.

Initiate meta messages
----------------------

The *initiate_meta_messages* is used to define the different messages that can be send over the overlay.

.. code-block:: python

    def initiate_meta_messages(self):
        return super(ExampleCommunity, self).initiate_meta_messages() + [
            <messages>
        ]

The messages need to be defined between the list brackets and be comma separated. An example of a message is shown
below:

.. code-block:: python

    Message(self, u"example",
            MemberAuthentication(encoding="sha1"),
            PublicResolution(),
            DirectDistribution(),
            CommunityDestination(node_count=10),
            ExamplePayload(),
            self.check_message,
            self.on_example)

Messages
--------

Messages are application dependent, however Dispersy adds optional headers describing if
and to whom this message needs to be synchronized, the id and or signature of the
creator, etc.

A message has the following four different policies (headers), and each policy defines how a specific part of the
message should be handled.

 - Authentication defines if the message is signed, and if so, by how many members.

 - Resolution defines how the permission system should resolve conflicts between messages.

 - Distribution defines if the message is send once or if it should be gossiped around.  In the
   latter case, it can also define how many messages should be kept in the network.

 - Destination defines to whom the message should be send or gossiped.

To ensure that every node handles a messages in the same way, i.e. has the same policies associated
to each message, a message exists in two stages.  The meta-message and the implemented-message
stage.  Each message has one meta-message associated to it and tells us how the message is supposed
to be handled.  When a message is sent or received an implementation is made from the meta-message
that contains information specifically for that message.  For example: a meta-message could have the
member-authentication-policy that tells us that the message must be signed by a member but only the
an implemented-message will have data and this signature.

Authentication
^^^^^^^^^^^^^^

Each Dispersy message that is send has an Authentication policy associated to it.  This policy
dictates how the message is authenticated, i.e. how the message is associated to the sender or
creator of this message.

NoAuthentication
""""""""""""""""

The NoAuthentication policy can be used when a message is not owned, i.e. signed, by anyone.

A message that uses the no-authentication policy does not contain any identity information nor a
signature.  This makes the message smaller --from a storage and bandwidth point of view-- and
cheaper --from a CPU point of view-- to generate.  However, the message becomes less secure as
everyone can generate and modify it as they please.  This makes this policy ill suited for
gossiping purposes.

MemberAuthentication
""""""""""""""""""""

The MemberAuthentication policy can be used when a message is owned, i.e. signed, by one member.

A message that uses the member-authentication policy will add an identifier to the message that
indicates the creator of the message.  This identifier can be either the public key or the sha1
digest of the public key.  The former is relatively large but uniquely identifies the member,
while the latter is relatively small but might not uniquely identify the member, although, this
will uniquely identify the member when combined with the signature.

Furthermore, a signature over the entire message is appended to ensure that no one else can
modify the message or impersonate the creator.  Using the default curve, NID-sect233k1, each
signature will be 58 bytes long.

The member-authentication policy is used to sign a message, associating it to a specific member.
This lies at the foundation of Dispersy where specific members are permitted specific actions.
Furthermore, permissions can only be obtained by having another member, who is allowed to do so,
give you this permission in the form of a signed message.

DoubleMemberAuthentication
""""""""""""""""""""""""""

A message that uses the double-member-authentication policy is signed by two member.  Similar to
the member-authentication policy the message contains two identifiers where the first indicates
the creator and the second indicates the members that added her signature.

Dispersy is responsible for obtaining the signatures of the different members and handles this
using the messages dispersy-signature-request and dispersy-signature-response, defined below.
Creating a double signed message is performed using the following steps: first Alice creates a
message (M) where M uses the double-member-authentication policy.  At this point M consists of
the community identifier, the conversion identifier, the message identifier, the member
identifier for both Alice and Bob, optional resolution information, optional distribution
information, optional destination information, the message payload, and \0 bytes for the two
signatures.

Message M is then wrapped inside a dispersy-signature-request message (R) and send to Bob.  When
Bob receives this request he can optionally apply changes to M2 and add his signature.  Assuming
that he does the new message M2, which now includes Bob's signature while Alice's is still \0,
is wrapped in a dispersy-signature-response message (E) and sent back to Alice.  If Alice agrees
with the (possible) changes in M2 she can add her own signature and M2 is stored, updated, and
forwarded to other nodes in the community.

Resolution
^^^^^^^^^^

Resolution is used for determining who can create the message. This is part of the permission system
in Dispersy. There are three types of resolutions:

PublicResolution
""""""""""""""""

Public resolution allows any member to create a message. This is the most common type used.

LinearResolution
""""""""""""""""

Linear resolution allows only members that have a specific permission to create a message. This resolution type
checks the public identifier against the permission list to see if that user is allowed to create that message.

DynamicResolution
"""""""""""""""""

Dynamic resolution allows the resolution policy to change. A special dispersy-dynamic-settings message
needs to be created and distributed to change the resolution policy.  Currently the policy can dynamically
switch between either PublicResolution and LinearResolution.

Distribution
^^^^^^^^^^^^

Distibution determines how a message gets distributed across the network. There are five types of distibutions
packaged in Dispersy:

SyncDistribution
""""""""""""""""

Sync distribution allows gossiping and synchronization of messages throughout the community.

The PRIORITY value ranges [0:255] where the 0 is the lowest priority and 255 the highest.  Any
messages that have a priority below 32 will not be synced.  These messages require a mechanism
to request missing messages whenever they are needed.

The PRIORITY was introduced when we found that the dispersy-identity messages are the majority
of gossiped messages while very few are actually required.  The dispersy-missing-identity
message is used to retrieve an identity whenever it is needed.

FullSyncDistibution
"""""""""""""""""""

Full-sync distribution allows gossiping and synchronization of messages throughout the community.

Sequence numbers can be enabled or disabled per meta-message.  When disabled the sequence number
is always zero.  When enabled the claim_sequence_number method can be called to obtain the next
sequence number in sequence.

Currently there is one situation where disabling sequence numbers is required.  This is when the
message will be signed by multiple members.  In this case the sequence number is claimed but may
not be used (if the other members refuse to add their signature).  This causes a missing
sequence message.  This in turn could be solved by creating a placeholder message, however, this
is not currently, and my never be, implemented.

LastSyncDistribution
""""""""""""""""""""

Last-sync distribution does the same as SyncDistribution but only for the last n messages. This number is determined
by a input parameter.

DirectDistribution
""""""""""""""""""

Direct distibution is used to send a message to a node directly, without syncing the information. The information is
processed and then thrown away.

RelayDistribution
"""""""""""""""""

Relay distribution does the same as DirectDistribution

Destination
^^^^^^^^^^^

The destination determines where or who the message is going to. There are two types of destination policies:

CandidateDestination
""""""""""""""""""""

A destination policy where the message is sent to one or more specified candidates.

CommunityDestination
""""""""""""""""""""

A destination policy where the message is sent to one or more community members selected from
the current candidate list.

At the time of sending at most NODE_COUNT addresses are obtained using
community.yield_random_candidates(...) to receive the message.

Running Dispersy
================

Dispersy uses Twisted for all low level network communications. It is not recommended to run twisted on a separate
thread. A Dispersy based program should be async and use twisted, even better if it's a twisted plugin. That saves
having to take care of the reactor lifetime, log rotation, pid file and suchlike.

Run Twisted in the main thread
------------------------------

To run Twisted in the main thread, just start Dispersy in your main thread

.. code-block:: python

    from twisted.internet import reactor

    def main():
        reactor.exitCode = 0
        reactor.run()

        dispersy = Dispersy(StandaloneEndpoint(port, '0.0.0.0'), unicode(<data_dir>), u'dispersy.db')
        dispersy.statistics.enable_debug_statistics(True)
        dispersy.start(autoload_discovery=True)

        my_member = self.get_new_member()
        master_memeber = self.get_member(public_key=<master_key>)

        community = <Community>.init_community(self, master_member, my_member)

        exit(reactor.exitCode)

    if __name__ == "__main__":
        main()

The variables between <> have to be replaced with values/objects belonging to your own project.