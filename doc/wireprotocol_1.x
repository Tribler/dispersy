#+TITLE: Dispersy wire protocol\\version 1.3
#+OPTIONS: toc:nil ^:nil author:nil
#+LATEX_HEADER: \usepackage{enumitem}
#+LATEX_HEADER: \setlist{nolistsep}

# This document is written using orgmode.  
# Allowing easy text editing and export to various formats.

* Introduction
This document describes the Dispersy on the wire message protocol and
its intended behaviors.

All values are big endian encoded.

** 30/05/2012 version 1.0
Initial public release.

** ??/??/2012 version 1.1
- added tunnel bit to dispersy-introduction-request
- added tunnel bit to dispersy-introduction-response

** 12/10/2012 version 1.3
- added dispersy-signature-request message
- added dispersy-signature-response message

* <<<dispersy-identity>>> (#248)
Contains the public key for a single member.  This message is the
response to a dispersy-missing-identity request.

The dispersy-identity message is not disseminated through bloom filter
synchronization.  Furthermore, only the dispersy-identity message with
the highest global time per member is used.

|-------+-------+--------------------+----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION          |
|-------+-------+--------------------+----------------------|
|     1 |    00 | unsigned char      | dispersy version     |
|     1 |    01 | unsigned char      | community version    |
|    20 |       | char[]             | community identifier |
|     1 |    f8 | unsigned char      | message identifier   |
|     2 |       | unsigned short     | public key length    |
|       |       | char[]             | public key           |
|     8 |       | unsigned long long | global time          |
|       |       | char[]             | signature            |
|-------+-------+--------------------+----------------------|

** possible future changes
Historically the most recent IP address of a member was stored in the
payload of its dispersy-identity message.  This required the message
to be stored and have a signature.  Since this is no longer the case,
the message can be simplified by replacing dispersy-identity with a
non-signed response to a dispersy-missing-identity message.

* <<<dispersy-authorize>>> (#234)
Grants one or more permissions.  This message can be the response to a
dispersy-missing-proof request.  (TODO: reference a document
describing the permission system.)

The dispersy-authorize message is disseminated through bloom filter
synchronization in ascending global time order with priority 128.
Each dispersy-authorize message has a sequence number that is unique
per member, ensuring that members are unable to create dispersy-revoke
messages out of order.  A dispersy-authorize message can not be
undone.

|----+-------+-------+--------------------+------------------------|
| +  | BYTES | VALUE | C-TYPE             | DESCRIPTION            |
|----+-------+-------+--------------------+------------------------|
|    |     1 |    00 | unsigned char      | dispersy version       |
|    |     1 |    01 | unsigned char      | community version      |
|    |    20 |       | char[]             | community identifier   |
|    |     1 |    f3 | unsigned char      | message identifier     |
|    |    20 |       | char[]             | member identifier      |
|    |     8 |       | unsigned long long | global time            |
|    |     4 |       | unsigned long      | sequence number        |
| +  |     2 |       | unsigned short     | public key length      |
| +  |       |       | char[]             | public key             |
| +  |     1 |       | unsigned char      | permission pair length |
| ++ |     1 |       | unsigned char      | message identifier     |
| ++ |     1 |       | unsigned char      | permission bits        |
|    |       |       | char[]             | signature              |
|----+-------+-------+--------------------+------------------------|

The dispersy-authorize message payload contains repeating elements.
One or more public key length, public key, permission pair length
pairs may be given.  Each of these pairs has one or more message
identifier, permissing bits pairs.

The permission bits are defined as follows:
- 0000.0001 grants the 'permit' permission
- 0000.0010 grants the 'authorize' permission
- 0000.0100 grants the 'revoke' permission
- 0000.1000 grants the 'undo' permission

** possible future changes
Currently the permissions are granted on global times after the
dispersy-authorize message was created.  To improve flexibility a
global time value can be included in this message that describes
another global time from where the permission applies.

Furthermore, the synchronization ordering and priority may be removed.
This feature adds complexity while not providing the intended result
once the overlay has enough messages to require multiple bloom filter
ranges.

* <<<dispersy-revoke>>> (#242)
Revokes one or more permissions.  This message can be the response to
a dispersy-missing-proof request.  (TODO: reference a document
describing the permission system.)

The dispersy-revoke message is disseminated through bloom filter
synchronization in ascending global time order with priority 128.
Each dispersy-revoke message has a sequence number that is unique per
member, ensuring that members are unable to create dispersy-revoke
messages out of order.  A dispersy-revoke message can not be undone.

|----+-------+-------+--------------------+------------------------|
| +  | BYTES | VALUE | C-TYPE             | DESCRIPTION            |
|----+-------+-------+--------------------+------------------------|
|    |     1 |    00 | unsigned char      | dispersy version       |
|    |     1 |    01 | unsigned char      | community version      |
|    |    20 |       | char[]             | community identifier   |
|    |     1 |    f2 | unsigned char      | message identifier     |
|    |    20 |       | char[]             | member identifier      |
|    |     8 |       | unsigned long long | global time            |
|    |     4 |       | unsigned long      | sequence number        |
| +  |     2 |       | unsigned short     | public key length      |
| +  |       |       | char[]             | public key             |
| +  |     1 |       | unsigned char      | permission pair length |
| ++ |     1 |       | unsigned char      | message identifier     |
| ++ |     1 |       | unsigned char      | permission bits        |
|    |       |       | char[]             | signature              |
|----+-------+-------+--------------------+------------------------|

They dispersy-revoke message payload contains repeating elements.  One
or more public key length, public key, permission pair length pairs
may be given.  Each of these pairs has one or more message identifier,
permissing bits pairs.

The permission bits are defined as follows:
- 0000.0001 revokes the 'permit' permission
- 0000.0010 revokes the 'authorize' permission
- 0000.0100 revokes the 'revoke' permission
- 0000.1000 revokes the 'undo' permission

** possible future changes
Currently the permissions are granted on global times after the
dispersy-authorize message was created.  To improve flexibility a
global time value can be included in this message that describes
another global time from where the permission applies.

Furthermore, the synchronization ordering and priority may be removed.
This feature adds complexity while not providing the intended result
once the overlay has enough messages to require multiple bloom filter
ranges.

* <<<dispersy-undo-own>>> (#238)
Marks an older message with an undone flag.  This allows a member to
undo her own previously created message.  Undo messages can only be
created for messages that have an undo defined for them.

The dispersy-undo-own message is disseminated through bloom filter
synchronization in ascending global time order with priority 128.
Each dispersy-undo-own message has a sequence number that is unique
per member, ensuring that members are unable to create
dispersy-undo-own messages out of order.  A dispersy-undo-own message
can not be undone.

|-------+-------+--------------------+----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION          |
|-------+-------+--------------------+----------------------|
|     1 |    00 | unsigned char      | dispersy version     |
|     1 |    01 | unsigned char      | community version    |
|    20 |       | char[]             | community identifier |
|     1 |    ee | unsigned char      | message identifier   |
|    20 |       | char[]             | member identifier    |
|     8 |       | unsigned long long | global time          |
|     4 |       | unsigned long      | sequence number      |
|     8 |       | unsigned long long | target global time   |
|       |       | char[]             | signature            |
|-------+-------+--------------------+----------------------|

The dispersy-undo-own message contains a target global time which,
together with the community identifier and the member identifier,
uniquely identifies the message that is being undone.

To impose a limit on the number of dispersy-undo-own messages that can
be created, a dispersy-undo-own message may only be accepted when the
message that it points to is available and no dispersy-undo-own has
yet been created for it.

** possible future changes
The synchronization ordering and priority may be removed.  This
feature adds complexity while not providing the intended result once
the overlay has enough messages to require multiple bloom filter
ranges.

* <<<dispersy-undo-other>>> (#237)
Marks an older message with an undone flag.  This allows a member to
undo a message made by someone else.  Undo messages can only be
created for messages that have an undo defined for them.

The dispersy-undo-other message is disseminated through bloom filter
synchronization in ascending global time order with priority 128.
Each dispersy-undo-other message has a sequence number that is unique
per member, ensuring that members are unable to create
dispersy-undo-own messages out of order.  A dispersy-undo-other
message can not be undone.

|-------+-------+--------------------+--------------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION              |
|-------+-------+--------------------+--------------------------|
|     1 |    00 | unsigned char      | dispersy version         |
|     1 |    01 | unsigned char      | community version        |
|    20 |       | char[]             | community identifier     |
|     1 |    ed | unsigned char      | message identifier       |
|    20 |       | char[]             | member identifier        |
|     8 |       | unsigned long long | global time              |
|     4 |       | unsigned long      | sequence number          |
|     2 |       | unsigned short     | target public key length |
|       |       | char[]             | target public key        |
|     8 |       | unsigned long long | target global time       |
|       |       | char[]             | signature                |
|-------+-------+--------------------+--------------------------|

The dispersy-undo-other message contains a target public key and
target global time which, together with the community identifier,
uniquely identifies the message that is being undone.

A dispersy-undo-other message may only be accepted when the message
that it points to is available.  In contrast to a dispersy-undo-own
message, it is allowed to have multiple dispersy-undo-other messages
targeting the same message.  To impose a limit on the number of
dispersy-undo-other messages that can be created, a member must have
an undo permission for the target message.

** possible future changes
The synchronization ordering and priority may be removed.  This
feature adds complexity while not providing the intended result once
the overlay has enough messages to require multiple bloom filter
ranges.

* <<<dispersy-dynamic-settings>>> (#236)
Changes one or more message policies.  When a message has two or more
policies of a specific type defined, i.e. both PublicResolution and
LinearResolution, the dispersy-dynamic-settings message switches
between them.

The dispersy-dynamic-settings message is disseminated through bloom
filter synchronization in descending global time order with
priority 191.  Each dispersy-dynamic-settings message has a sequence
number that is unique per member, ensuring that members are unable to
create dispersy-dynamic-settings messages out of order.  A
dispersy-dynamic-settings message can not be undone.

|---+-------+-------+--------------------+---------------------------|
| + | BYTES | VALUE | C-TYPE             | DESCRIPTION               |
|---+-------+-------+--------------------+---------------------------|
|   |     1 |    00 | unsigned char      | dispersy version          |
|   |     1 |    01 | unsigned char      | community version         |
|   |    20 |       | char[]             | community identifier      |
|   |     1 |    ec | unsigned char      | message identifier        |
|   |    20 |       | char[]             | member identifier         |
|   |     8 |       | unsigned long long | global time               |
|   |     4 |       | unsigned long      | sequence number           |
| + |     1 |       | unsigned char      | target message identifier |
| + |     1 |    72 | char               | target policy type        |
| + |     1 |       | unsigned char      | target policy index       |
|   |       |       | char[]             | signature                 |
|---+-------+-------+--------------------+---------------------------|

The target policy type is currently always HEX 72.  This equates to
the character 'r', i.e. resolution policy, which is currently the only
policy type that supports dynamic settings.  The target policy index
indicates the index of the new policy in the list of predefined
policies.  The policy change is applied from the next global time
after the global time given by the dispersy-dynamic-settings message.

** possible future changes
Currently it is only possible to switch between PublicResolution and
LinearResolution policies.  Switching between other policies should
also be implemented.

Furthermore, the synchronization ordering and priority may be removed.
This feature adds complexity while not providing the intended result
once the overlay has enough messages to require multiple bloom filter
ranges.

* <<<dispersy-destroy-community>>> (#244)
Forces an overlay to go offline.  An overlay can be either soft killed
or hard killed.

A soft killed overlay is frozen.  All the currently available data
will be kept, however, messages with a global time that is higher than
the global-time of the dispersy-destroy-community message will be
refused.  Responses to dispersy-introduction-request messages will be
send as normal.  Currently soft killing an overlay is not supported.

A hard killed overlay is destroyed.  All messages will be removed,
except the dispersy-destroy-community message and the authorize chain
that is required to verify its validity.

The dispersy-destroy-community message is disseminated through bloom
filter synchronization in ascending global time order with
priority 192.  A dispersy-destroy-community message can not be undone.
Hence it is very important to ensure that only trusted peers have the
permission to create this message.

|-------+-------+--------------------+----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION          |
|-------+-------+--------------------+----------------------|
|     1 |    00 | unsigned char      | dispersy version     |
|     1 |    01 | unsigned char      | community version    |
|    20 |       | char[]             | community identifier |
|     1 |    f4 | unsigned char      | message identifier   |
|    20 |       | char[]             | member identifier    |
|     8 |       | unsigned long long | global time          |
|       |       | char               | degree (soft/hard)   |
|       |       | char[]             | signature            |
|-------+-------+--------------------+----------------------|

The kill degree can be either soft (HEX 73, i.e. character 's') or
hard (HEX 68, i.e. character 'h').

** possible future changes
Implement the soft killed strategy.

* <<<dispersy-signature-request>>> (#252)
Requests a signature for an included message.  The included message
may be modified before adding the signature.  May respond with a
dispersy-signature-response message.

The dispersy-signature-request message is not disseminated through
bloom filter synchronization.  Instead it is created whenever a double
signed signature is required.

|-------+-------+----------------+----------------------|
| BYTES | VALUE | C-TYPE         | DESCRIPTION          |
|-------+-------+----------------+----------------------|
|     1 |    00 | unsigned char  | dispersy version     |
|     1 |    01 | unsigned char  | community version    |
|    20 |       | char[]         | community identifier |
|     1 |    fc | unsigned char  | message identifier   |
|     2 |       | unsigned short | request identifier   |
|       |       | char[]         | message              |
|-------+-------+----------------+----------------------|

The request identifier must be part of the
dispersy-signature-response.  The message must be a valid dispersy
message except that both signatures must be set to null bytes.

** version 1.2
The dispersy-signature-request message was added.

* <<<dispersy-signature-response>>> (#251)
Response to a dispersy-signature-request message.  The included
message may have been modified from the message in the request.

The dispersy-signature-response message is not disseminated through
bloom filter synchronization.  Instead it is created whenever a double
signed signature is required.

|-------+-------+----------------+----------------------|
| BYTES | VALUE | C-TYPE         | DESCRIPTION          |
|-------+-------+----------------+----------------------|
|     1 |    00 | unsigned char  | dispersy version     |
|     1 |    01 | unsigned char  | community version    |
|    20 |       | char[]         | community identifier |
|     1 |    fb | unsigned char  | message identifier   |
|     2 |       | unsigned short | response identifier  |
|       |       | char[]         | message              |
|-------+-------+----------------+----------------------|

The response identifier must be equal to the request identifier of the
dispersy-signature-request message.  The message must be a valid
dispersy message except that only the sender's signature is set while
the receiver's signature must be set to null bytes.

** version 1.2
The dispersy-signature-response message was added.

* <<<dispersy-introduction-request>>> (#246)
The dispersy-introduction-request message is part of the semi-random
walker.  It asks the destination peer to introduce the source peer to
a semi-random neighbor.  Sending this request should result in a
dispersy-introduction-response to the sender and a
[[dispersy-puncture-request]] to the semi-random neighbor.  (TODO:
reference a document describing the semi-random walker.)

The dispersy-introduction-request message is not disseminated through
bloom filter synchronization.  Instead it is periodically created to
maintain a semi-random overlay.

|---+-------+-------+--------------------+-----------------------------|
| + | BYTES | VALUE | C-TYPE             | DESCRIPTION                 |
|---+-------+-------+--------------------+-----------------------------|
|   |     1 |    00 | unsigned char      | dispersy version            |
|   |     1 |    01 | unsigned char      | community version           |
|   |    20 |       | char[]             | community identifier        |
|   |     1 |    f6 | unsigned char      | message identifier          |
|   |    20 |       | char[]             | member identifier           |
|   |     8 |       | unsigned long long | global time                 |
|   |     6 |       | char[]             | destination address         |
|   |     6 |       | char[]             | source LAN address          |
|   |     6 |       | char[]             | source WAN address          |
|   |     1 |       | unsigned char      | option bits                 |
|   |     2 |       | unsigned short     | request identifier          |
| + |     8 |       | unsigned long long | sync global time low        |
| + |     8 |       | unsigned long long | sync global time high       |
| + |     2 |       | unsigned short     | sync modulo                 |
| + |     2 |       | unsigned short     | sync offset                 |
| + |     1 |       | unsigned char      | sync bloom filter functions |
| + |     2 |       | unsigned short     | sync bloom filter size      |
| + |     1 |       | unsigned char      | sync bloom filter prefix    |
| + |       |       | char[]             | sync bloom filter           |
|   |       |       | char[]             | signature                   |
|---+-------+-------+--------------------+-----------------------------|

The option bits are defined as follows:
- 0000.0001 request an introduction
- 0000.0010 request contains optional sync bloom filter
- 0000.0100 source is behind a tunnel
- 0000.1000 source connection type
- 1000.0000 source has a public address
- 1100.0000 source is behind a symmetric NAT

The dispersy-introduction-request message contains optional elements.
When the 'request contains optional sync bloom filter' bit is set, all
of the sync fields must be given.  In this case the destination peer
should respond with messages that are within the set defined by sync
global time low, sync global time high, sync modulo, and sync offset
and which are not in the sync bloom filter.  However, the destination
peer is allowed to limit the number of messages it responds with.
Sync bloom filter size is given in bits and corresponds to the length
of the sync bloom filter.  Responses should take into account the
message priority.  Otherwise ordering is by either ascending or
descening global time.

** version 1.1
The tunnel bit was introduced.

** possible future changes
There is no feature that requires cryptography on this message.  Hence
it may be removed to reduce message size and processing cost.

There is not enough version information in this message.  More should
be added to allow the source and destination peers to determine the
optimal wire protocol to use.  Having a three-way handshake would
allow consensus between peers on what version to use.

Sometimes the source peer may want to receive fewer sync responses
(i.e. to ensure low CPU usage), adding a max bandwidth value allows to
limit the returned packages.

The walker should be changed into a three-way handshake to secure the
protocol against IP spoofing attacks.

* <<<dispersy-introduction-response>>> (#245)
The dispersy-introduction-response message is part of the semi-random
walker and should be given as a response when a
dispersy-introduction-request is received.  (TODO: reference a
document describing the semi-random walker.)

The dispersy-introduction-response message is not disseminated through
bloom synchronization.

|-------+-------+--------------------+-----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION           |
|-------+-------+--------------------+-----------------------|
|     1 |    00 | unsigned char      | dispersy version      |
|     1 |    01 | unsigned char      | community version     |
|    20 |       | char[]             | community identifier  |
|     1 |    f5 | unsigned char      | message identifier    |
|    20 |       | char[]             | member identifier     |
|     8 |       | unsigned long long | global time           |
|     6 |       | char[]             | destination address   |
|     6 |       | char[]             | source LAN address    |
|     6 |       | char[]             | source WAN address    |
|     6 |       | char[]             | introduce LAN address |
|     6 |       | char[]             | introduce WAN address |
|     1 |       | unsigned char      | option bits           |
|     2 |       | unsigned short     | response identifier   |
|       |       | char[]             | signature             |
|-------+-------+--------------------+-----------------------|

The option bits are defined as follows:
- 0000.0100 source is behind a tunnel
- 0000.1000 source connection type
- 1000.0000 source has a public address
- 1100.0000 source is behind a symmetric NAT

When no neighbor is introduced the introduce LAN address and introduce
WAN address will both be set to null.  Otherwise they correspond to
an, at the very least recently, existing neighbor.  A
[[dispersy-puncture-request]] should have been send to this neighbor for
NAT puncturing purposes.

The response identifier is set to the value given in the
dispersy-introduction-request.

** version 1.2
The tunnel bit was introduced.

** possible future changes
See possible future changes described at the
dispersy-introduction-request message.

* <<<dispersy-puncture-request>>> (#250)
The [[dispersy-puncture-request]] is part of the semi-random walker.  A
dispersy puncture should be send when this message is received for NAT
puncturing purposes.  (TODO: reference a document describing the
semi-random walker.)

The [[dispersy-puncture-request]] message is not disseminated through
bloom synchronization.

|-------+-------+--------------------+----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION          |
|-------+-------+--------------------+----------------------|
|     1 |    00 | unsigned char      | dispersy version     |
|     1 |    01 | unsigned char      | community version    |
|    20 |       | char[]             | community identifier |
|     1 |    fa | unsigned char      | message identifier   |
|     8 |       | unsigned long long | global time          |
|     6 |       | char[]             | target LAN address   |
|     6 |       | char[]             | target WAN address   |
|     2 |       | unsigned short     | response identifier  |
|-------+-------+--------------------+----------------------|

The target LAN address and target WAN address correspond to the source
LAN address and source WAN address of the
dispersy-introduction-request message that caused this
[[dispersy-puncture-request]] to be send.  These values may have been
modified to the best of the senders knowledge.

The response identifier is set to the value given in the
dispersy-introduction-request and dispersy-introduction-response.

** possible future changes
See possible future changes described at the
dispersy-introduction-request message.

* <<<dispersy-puncture>>> (#249)
The dispersy-puncture is part of the semi-random walker.  It is the
result of, but not a response to, a [[dispersy-puncture-request]] message.
(TODO: reference a document describing the semi-random walker.)

The dispersy-puncture message is not disseminated through bloom
synchronization.  Instead is is send to the target LAN address or
target WAN address given by the corresponding
[[dispersy-puncture-request]] message.

|-------+-------+--------------------+----------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION          |
|-------+-------+--------------------+----------------------|
|     1 |    00 | unsigned char      | dispersy version     |
|     1 |    01 | unsigned char      | community version    |
|    20 |       | char[]             | community identifier |
|     1 |    f9 | unsigned char      | message identifier   |
|     8 |       | unsigned long long | global time          |
|     6 |       | char[]             | source LAN address   |
|     6 |       | char[]             | source WAN address   |
|     2 |       | unsigned short     | response identifier  |
|-------+-------+--------------------+----------------------|

The response identifier is set to the value given in the
dispersy-introduction-request, dispersy-introduction-response, and
[[dispersy-puncture-request]].

** possible future changes
See possible future changes described at the
dispersy-introduction-request message.
* <<<dispersy-missing-identity>>> (#247)
Requests the public keys associated to a member identifier.  Sending
this request should result in one or more dispersy-identity message
responses.

The dispersy-missing-identity message is not disseminated through
bloom filter synchronization.  Instead it is created whenever a
message is received for which no public key is available to perform
the signature verification.

|---+-------+-------+--------------------+--------------------------|
|   | BYTES | VALUE | C-TYPE             | DESCRIPTION              |
|---+-------+-------+--------------------+--------------------------|
|   |     1 |    00 | unsigned char      | dispersy version         |
|   |     1 |    01 | unsigned char      | community version        |
|   |    20 |       | char[]             | community identifier     |
|   |     1 |    f7 | unsigned char      | message identifier       |
|   |     8 |       | unsigned long long | global time              |
|   |    20 |       | char[]             | target member identifier |
|---+-------+-------+--------------------+--------------------------|

** possible future changes
See possible future changes described at the dispersy-identity
message.

* <<<dispersy-missing-sequence>>> (#254)
Requests messages in a sequence number range.  Sending this request
should result in one or more message responses.

The dispersy-missing-sequence message is not disseminated through
bloom filter synchronization.  Instead it is created whenever a
message is received with a sequence number that leaves a sequence
number gap.

|-------+-------+--------------------+-----------------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION                 |
|-------+-------+--------------------+-----------------------------|
|     1 |    00 | unsigned char      | dispersy version            |
|     1 |    01 | unsigned char      | community version           |
|    20 |       | char[]             | community identifier        |
|     1 |    fe | unsigned char      | message identifier          |
|     8 |       | unsigned long long | global time                 |
|    20 |       | char[]             | target member identifier    |
|     1 |       | unsigned char      | target message identifier   |
|     4 |       | unsigned long      | target sequence number low  |
|     4 |       | unsigned long      | target sequence number high |
|-------+-------+--------------------+-----------------------------|

The messages sent in response should include sequence numbers starting
at target sequence number low up to, and including, target sequence
number high.

The destination peer is allowed to limit the number of messages it
responds with, however, the responses should always be ordered by the
sequence numbers.

** possible future changes
Sometimes the source peer may want to receive fewer responses (i.e. to
ensure low CPU usage), adding a max bandwidth value allows to limit
the returned packages.

* <<<dispersy-missing-message>>> (#239)
Requests one or more specific messages identified by a community
identifier, member identifier, and one or more global times.  This
request should result in one or more message responses.

The dispersy-missing-message message is not disseminated through bloom
filter synchronization.  Instead it is created whenever one or more
messages are missing.

|---+-------+-------+--------------------+--------------------------|
| + | BYTES | VALUE | C-TYPE             | DESCRIPTION              |
|---+-------+-------+--------------------+--------------------------|
|   |     1 |    00 | unsigned char      | dispersy version         |
|   |     1 |    01 | unsigned char      | community version        |
|   |    20 |       | char[]             | community identifier     |
|   |     1 |    ef | unsigned char      | message identifier       |
|   |     8 |       | unsigned long long | global time              |
|   |     2 |       | unsigned short     | target public key length |
|   |       |       | char[]             | target public key        |
| + |     8 |       | unsigned long long | target global time       |
|---+-------+-------+--------------------+--------------------------|

The target global time in the dispersy-missing-message message payload
is a repeating element.  One or more global time values may be given.
Each uniquely identifies a message.

* <<<dispersy-missing-last-message>>> (#235)
Requests one or more specific messages identified by a community
identifier, member identifier, and one or more global times.  This
request should result in one or more message responses.

The dispersy-missing-last-message message is not disseminated through
bloom filter synchronization.  Instead it is created whenever one or
more messages are missing.

|-------+-------+--------------------+---------------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION               |
|-------+-------+--------------------+---------------------------|
|     1 |    00 | unsigned char      | dispersy version          |
|     1 |    01 | unsigned char      | community version         |
|    20 |       | char[]             | community identifier      |
|     1 |    eb | unsigned char      | message identifier        |
|     8 |       | unsigned long long | global time               |
|     2 |       | unsigned short     | target public key length  |
|       |       | char[]             | target public key         |
|     1 |       | unsigned char      | target message identifier |
|     1 |       | unsigned char      | max count                 |
|-------+-------+--------------------+---------------------------|

* <<<dispersy-missing-proof>>> (#253)
Requests one or more parents of a message in the permission tree.
This request should result in one or more dispersy-authorize and/or
dispersy-revoke messages.  (TODO: reference a document describing the
permission system.)

The dispersy-missing-proof message is not disseminated through bloom
filter synchronization.  Instead it is created whenever one or more
messages are received that are invalid according to our current
permission tree.

|-------+-------+--------------------+--------------------------|
| BYTES | VALUE | C-TYPE             | DESCRIPTION              |
|-------+-------+--------------------+--------------------------|
|     1 |    00 | unsigned char      | dispersy version         |
|     1 |    01 | unsigned char      | community version        |
|    20 |       | char[]             | community identifier     |
|     1 |    fd | unsigned char      | message identifier       |
|     8 |       | unsigned long long | global time              |
|     8 |       | unsigned long long | target global time       |
|     2 |       | unsigned short     | target public key length |
|       |       | char[]             | target public key        |
|-------+-------+--------------------+--------------------------|
