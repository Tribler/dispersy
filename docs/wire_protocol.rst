*************
Wire Protocol
*************

This document describes the Dispersy wire protocol version 2 and its intended behaviors.  Version 2 is **not** backwards compatible.  The most notable changes when compared with the previous version are the use of `google protocol buffers`_ for the wire format, protection against IP spoofing, and session usage. Messages can be divided in two categories:

* Temporary message: A control message that is not stored on disk. Messages of this type are immediately discarded after they are processed.
* Persistent message: A message that contains information that must be retained across sessions.  Effectively this includes every message that must be disseminated through the network.

.. _`google protocol buffers`: https://developers.google.com/protocol-buffers

Global time
===========

Global time is a lamport clock used to provide message ordering withing a community.  Using global time, every message can be uniquely identified using community, member, and global time.

Dispersy stores global time values using, at most, 64 bits.  Therefore there is a finite number of global time values available.  To avoid malicious peers from quickly pushing the global time value to the point where none are left, peers will only accept messages with a global time that is within a locally evaluated limit.  This limit is set to the median of the neighbors' global time values plus a predefined margin.

Persistent messages that are not within the acceptable global time range are ignored.

Dispersy message types
======================

Dispersy-message
----------------

Protocol Buffers allows messages to be defined, encoded, and finally decoded again.  However, the way that we intend to use protocol buffers caused two issues to arise:

* Multiple different messages over the same communication channel requires a method to distinguish message type.  The recommended method, as described by Google in `self describing messages`_, is to encapsulate the message by a message that contains all possible messages as optional fields;
* Adding one or more signatures to a message requires the entire message (including the message type) to be serialized and passed to the cryptography layer, resulting signatures can only be placed in a wrapping message.

.. _`self describing messages`: https://developers.google.com/protocol-buffers/docs/techniques#self-description

This wrapping message must store the message in binary. Otherwise changes to protocol buffers' internal implementation may cause one client to produce a different, yet compatible, binary representation.  This would make it impossible to verify the signature.

Therefore, the Dispersy protocol will use two wrapping messages:

* **Descriptor** will allow message types to be assigned
* **Message** will contain the raw message bytes and optional signatures.

.. code-block:: python

	message Message {
	   extensions 1024 to max;
	   required bytes descriptor;
	   repeated bytes signatures;
	}

Descriptor limitations:

* Every temporary or persistent message must have an optional field in the Descriptor message.  Community messages must use the field values assigned to extensions.
* A dispersy-message may only contain one message, i.e. only one optional field may be set.

.. code-block:: python

	message Descriptor {
	   enum Type {
	      // frequent temporary messages (uses <15 values)
	      INTRODUCTIONREQUEST = 1;
	      INTRODUCTIONRESPONSE = 2;
	      SESSIONREQUEST = 3;
	      SESSIONRESPONSE = 4;
	      PUNCTUREREQUEST = 5;
	      PUNCTURERESPONSE = 6;
	      COLLECTION = 7;
	      IDENTITY = 8;

	      // infrequent temporary messages (uses >15 values)
	      MISSINGIDENTITY = 16;
	      MISSINGSEQUENCE = 17;
	      MISSINGMESSAGE = 18;
	      MISSINGLASTMESSAGE = 19;
	      MISSINGPROOF = 20;
	      SIGNATUREREQUEST = 21;
	      SIGNATURERESPONSE = 22;

	      // persistent messages (uses >63 values)
	      AUTHORIZE = 64;
	      REVOKE = 65;
	      UNDOOWN = 66;
	      UNDOOTHER = 67;
	      DYNAMICSETTINGS = 68;
	      DESTROYCOMMUNITY = 69;
	   }
	   extensions 1024 to max;
	   optional IntroductionRequest introduction_request = 1;
	   optional IntroductionResponse introduction_response = 2;
	   optional SessionRequest session_request = 3;
	   optional SessionResponse session_response = 4;
	   optional PunctureRequest puncture_request = 5;
	   optional PunctureResponse puncture_response = 6;
	   optional Collection collection = 7;
	   optional Identity identity = 8;

	   optional MissingIdentity missing_identity = 16;
	   optional MissingSequence missing_sequence = 17;
	   optional MissingMessage missing_message = 18;
	   optional MissingLastMessage missing_last_message = 19;
	   optional MissingProof missing_proof = 20;
	   optional SignatureRequest signature_request = 21;
	   optional SignatureResponse signature_response = 22;

	   optional Authorize authorize = 64;
	   optional Revoke revoke = 65;
	   optional UndoOwn undo_own = 66;
	   optional UndoOther undo_other = 67;
	   optional DynamicSettings dynamic_settings = 68;
	   optional DestroyCommunity destroy_community = 69;
	}

Note that field numbers that are higher than 15 are encoded using two bytes, whereas lower field numbers require one byte, see `defining a message type`_ . Hence the fields that are most common should use low field numbers.

.. _`defining a message type`: https://developers.google.com/protocol-buffers/docs/proto#simple

Dispersy-collection
-------------------

A temporary message that contains one or more persistent Dispersy messages. It is required because persistent Dispersy messages do not have a session identifier.

Collection limitations:

* Collection.session is associated with the source address.
* Collection.messages contains one or more messages.

.. code-block:: python

	message Collection {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   repeated Message messages = 2;
	}

Dispersy-identity
-----------------

A temporary message that contains the public key for a single member. This message is the response to a `dispersy-missing-identity`_ request.

Identity limitations:

* Identity.session is associated with the source address.
* Identity.member must be no larger than 1024 bytes.
* Identity.member must be a valid ECC public key.

.. code-block:: python

	message Identity {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required bytes member = 2;
	}

Dispersy-authorize
------------------

A persistent message that grants permissions (permit, authorize, revoke, or undo) for one or more messages to one or more public keys. This message must be wrapped in a `dispersy-collection`_ and is a response to a `dispersy-introduction-request`_ or a `dispersy-missing-proof`_.

Authorize limitations:

* Authorize.version is 1.
* Authorize.community must be 20 bytes.
* Authorize.member must be no larger than 1024 bytes.
* Authorize.member must be a valid EEC public key.
* Authorize.global_time must be one or higher and up to the local acceptable global time range.
* Authorize.sequence_number must follow already processed Authorize messages from Authorize.member. Sequence numbers start at one. No sequence number may be skipped.
* Authorize.targets must contain one or more entries.
* Authorize.targets[].member must be no larger than 1024 bytes.
* Authorize.targets[].member must be a valid EEC public key.
* Authorize.targets[].permissions must contain one or more entries.
* Authorize.targets[].permissions[].message must represent a known message in the community.
* Can not be undone using `dispersy-undo-own`_ or `dispersy-undo-other`_.
* Requires a signature matching the Authorize.member.

.. code-block:: python

	message Authorize {
	   enum Type {
	      PERMIT = 1;
	      AUTHORIZE = 2;
	      REVOKE = 3;
	      UNDO = 4;
	   }
	   message Permission {
	      required Message.Type message = 1;
	      required Type permission = 2;
	   }
	   message Target {
	      required uint64 global_time = 1;
	      required bytes member = 2;
	      repeated Permission permissions = 3;
	   }
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required uint32 sequence_number = 5;
	   repeated Target targets = 6;
	}

Dispersy-revoke
---------------

A persistent message that revokes permissions (permit, authorize, revoke, or undo) for one or more messages from one or more public keys. This message must be wrapped in a `dispersy-collection`_ and is a response to a `dispersy-introduction-request`_ or a `dispersy-missing-proof`_.

Revoke limitations:

* Revoke.version is 1.
* Revoke.community must be 20 bytes.
* Revoke.member must be no larger than 1024 bytes.
* Revoke.member must be a valid EEC public key.
* Revoke.global_time must be one or higher and up to the local acceptable global time range.
* Revoke.sequence_number must follow already processed Revoke messages from Revoke.member. Sequence numbers start at one. No sequence number may be skipped.
* Revoke.targets must contain one or more entries.
* Revoke.targets[].member must be no larger than 1024 bytes.
* Revoke.targets[].member must be a valid EEC public key.
* Revoke.targets[].permissions must contain one or more entries.
* Revoke.targets[].permissions[].message must represent a known message in the community.
* Can not be undone using `dispersy-undo-own`_ or `dispersy-undo-other`_.
* Requires a signature matching the Revoke.member.

.. code-block:: python

	message Revoke {
	   enum Type {
	      PERMIT = 1;
	      AUTHORIZE = 2;
	      REVOKE = 3;
	      UNDO = 4;
	   }
	   message Permission {
	      required Message.Type message = 1;
	      required Type permission = 2;
	   }
	   message Target {
	      required uint64 global_time = 1;
	      required bytes member = 2;
	      repeated Permission permissions = 3;
	   }
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required uint32 sequence_number = 5;
	   repeated Target targets = 6;
	}

Dispersy-undo-own
-----------------

A persistent message that marks an older message with an undone flag. This allows a member to undo her own previously created messages. This message must be wrapped in a `dispersy-collection`_ and is a response to `dispersy-introduction-request`_ or a `dispersy-missing-proof`_. Undo messages can only be created for messages that allow being undone.

The dispersy-undo-own message contains a target global time which, together with the community identifier and the member identifier, uniquely identifies the message that is being undone. This message target must allow being undone.

To impose a limit on the number of dispersy-undo-own messages that can be created, a dispersy-undo-own message may only be accepted when the message that it points to is available and no dispersy-undo-own has yet been created for it.

UndoOwn limitations:

* UndoOwn.version is 1.
* UndoOwn.community must be 20 bytes.
* UndoOwn.member must be no larger than 1024 bytes.
* UndoOwn.member must be a valid EEC public key.
* UndoOwn.global_time must be one or higher and up to the local acceptable global time range.
* UndoOwn.sequence_number must follow already processed UndoOwn messages from UndoOwn.member. Sequence numbers start at one. No sequence number may be skipped.
* UndoOwn.target_global_time must be one or higher and smaller than UndoOwn.global_time.
* Can not be undone using dispersy-undo-own or `dispersy-undo-other`_.
* Requires a signature matching the UndoOwn.member.

.. code-block:: python

	message UndoOwn {
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required uint32 sequence_number = 5;
	   required uint64 target_global_time = 5;
	}

Dispersy-undo-other
-------------------

A persistent message that marks an older message with an undone flag. This allows a member to undo a previously created messages created by someone else. This message must be wrapped in a `dispersy-collection`_ and is a response to `dispersy-introduction-request`_ or a `dispersy-missing-proof`_. Undo messages can only be created for messages that allow being undone.

The dispersy-undo-other message contains a target public key and target global time which, together with the community identifier, uniquely identifies the message that is being undone. This target message must allow being undone.

A dispersy-undo-other message may only be accepted when the message that it points to is available. In contrast to a `dispersy-undo-own`_ message, it is allowed to have multiple dispersy-undo-other messages targeting the same message. To impose a limit on the number of dispersy-undo-other messages that can be created, a member must have the undo permission for the target message.

UndoOther limitations:

* UndoOther.version is 1.
* UndoOther.community must be 20 bytes.
* UndoOther.member must be no larger than 1024 bytes.
* UndoOther.member must be a valid EEC public key.
* UndoOther.global_time must be one or higher and up to the local acceptable global time range.
* UndoOther.sequence_number must follow already processed UndoOther messages from UndoOther.member. Sequence numbers start at one. No sequence number may be skipped.
* UndoOther.target_global_time must be one or higher and smaller than UndoOther.global_time.
* UndoOther.target_member must be no larger than 1024 bytes.
* UndoOther.target_member must be a valid EEC public key.
* Can not be undone using `dispersy-undo-own`_ or dispersy-undo-other.
* Requires a signature matching the UndoOther.member.

.. code-block:: python

	message UndoOther {
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required uint32 sequence_number = 5;
	   required uint64 target_global_time = 6;
	   required bytes target_member = 7;
	}

Dispersy-dynamic-settings
-------------------------

A persistent message that changes one or more message policies. When a message has two or more policies of a specific type defined, i.e. both PublicResolution and LinearResolution, the dispersy-dynamic-settings message allows switching between them. This message must be wrapped in a `dispersy-collection`_ and is a response to a `dispersy-introduction-request`_ or a `dispersy-missing-proof`_.

The policy change is applied from the next global time increment after the global time given by the dispersy-dynamic-settings message.

DynamicSettings limitations:

* DynamicSettings.version is 1.
* DynamicSettings.community must be 20 bytes.
* DynamicSettings.member must be no larger than 1024 bytes.
* DynamicSettings.member must be a valid EEC public key.
* DynamicSettings.global_time must be one or higher and up to the local acceptable global time range.
* DynamicSettings.sequence_number must follow already processed DynamicSettings messages from DynamicSettings.member. Sequence numbers start at one. No sequence number may be skipped.
* DynamicSettings.target_message must represent a known message in the community.
* DynamicSettings.target_policy must be a policy that has dynamic settings enabled.
* DynamicSettings.target_index must be an existing index in the available dynamic settings.
* Can not be undone using `dispersy-undo-own`_ or `dispersy-undo-other`_.
* Requires a signature matching the DynamicSettings.member.

.. code-block:: python

	message DynamicSettings {
	   enum Policy {
	      AUTHENTICATION = 1;
	      RESOLUTION = 2;
	      DISTRIBUTION = 3;
	      DESTINATION = 4;
	      PAYLOAD = 5;
	   }
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required uint32 sequence_number = 5;
	   required Message.Type target_message = 6;
	   required Policy target_policy = 7;
	   required uint32 target_index = 8;
	}

Dispersy-destroy-community
--------------------------

A persistent message that forces an overlay to go offline. An overlay can be either soft killed or hard killed. This message must be wrapped in a `dispersy-collection`_ and is a response to `dispersy-introduction-request`_ (for soft kill) or a response to any temporary message (for hard kill).

A soft killed overlay is frozen. All existing persistent messages with global time lower or equal to DestroyCommunity.target_global_time will be retained but all other persistent messages are undone (where possible) and removed.  New persistent messages with global time lower or equal to DestroyCommunity.target_global_time are accepted and processed but all other persistent messages are ignored. Temporary messages are not effected.

A hard killed overlay is destroyed.  All persistent messages will be removed without undo, except the dispersy-destroy-community message and the authorize chain that is required to verify its validity. New persistent messages are ignored and temporary messages result in the dispersy-destroy-community and the authorize chain that is required to verify its validity.

A dispersy-destroy-community message can not be undone.  Hence it is very important to ensure that only trusted peers have the permission to create this message.

DestroyCommunity limitations:

* DestroyCommunity.version is 1.
* DestroyCommunity.community must be 20 bytes.
* DestroyCommunity.member must be no larger than 1024 bytes.
* DestroyCommunity.member must be a valid EEC public key.
* DestroyCommunity.global_time must be one or higher and up to the local acceptable global time range.
* Can not be undone using `dispersy-undo-own`_ or `dispersy-undo-other`_.
* Requires a signature matching the DestroyCommunity.member.

.. code-block:: python

	message DestroyCommunity {
	   enum Degree {
	      SOFT = 1;
	      HARD = 2;
	   }
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required bytes community = 2;
	   required bytes member = 3;
	   required uint64 global_time = 4;
	   required Degree degree = 5;
	}

Dispersy-signature-request
--------------------------

A temporary message to request a signature for an included message from another member. The included message may be modified before adding the signature. May respond with a `dispersy-signature-response`_ message.

SignatureRequest limitations:

* SignatureRequest.session is associated with the source address.
* SignatureRequest.request is a random number.
* SignatureRequest.message.signatures may not be set.

.. code-block:: python

	message SignatureRequest {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 request = 2;
	   required Message message = 3;
	}

Dispersy-signature-response
---------------------------

A temporary message to respond to a `dispersy-signature-request`_ from another member. The included message may be different from the message given in the associated request.

SignatureResponse limitations:

* SignatureResponse.session is associated with the source address.
* SignatureResponse.request is SignatureRequest.request
* SignatureResponse.message.signatures must contain one signature.

.. code-block:: python

	message SignatureResponse {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 request = 2;
	   required Message message = 3;
	}

Dispersy-introduction-request
-----------------------------

A temporary message to contact a peer that we may or may not have visited already. This message has two tasks:

* To maintain a semi-random overlay by obtaining one possibly locally unknown peer.
* To obtain eventual consistency by obtaining zero or more unknown persistent messages.

The dispersy-introduction-request, `dispersy-introduction-response`_, `dispersy-session-request`_, `dispersy-session-response`_, `dispersy-puncture-request`_, and `dispersy-puncture`_ messages are used together. The following schema describes the interaction between peers A, B, and C for a typical walk. Where we call A the initiator, B the invitor and C the invitee.

1. A → B: dispersy-introduction-request
        * {shared\ :sub:`AB`\ , identifier\ :sub:`walk`\ , address\ :sub:`B`\ , LAN\ :sub:`A`\ , WAN\ :sub:`A`\ , bloom\ :sub:`A`\ }
2. B → A: `dispersy-session-request`_ (new session only)
        * {random\ :sub:`B`\, identifier\ :sub:`walk`\ , address\ :sub:`A`\ , LAN\ :sub:`B`\ , WAN\ :sub:`B`\ }
3. A → B: `dispersy-session-response`_ (new session only)
        * random\ :sub:`A`\ , identifier\ :sub:`walk`\ }
4. B → C: `dispersy-puncture-request`_
        * {shared\ :sub:`BC`\, identifier\ :sub:`walk`\, LAN\ :sub:`A`\ , WAN\ :sub:`A`\ }
5. B → A: `dispersy-introduction-response`_
        * {shared\ :sub:`AB`\ , identifier\ :sub:`walk`\ , LAN\ :sub:`C`\ , WAN\ :sub:`C`\ }
6. B → A: `dispersy-collection`_
        * {shared\ :sub:`AB`\ , missing messages\}
7. C → A: `dispersy-puncture`_
        * {shared\ :sub:`AC`\ , identifier\ :sub:`walk`\ , LAN\ :sub:`C`\ , WAN\ :sub:`C`\ }

IntroductionRequest limitations:

* IntroductionRequest.session is associated with the source address or zero to initiate a new session.
* IntroductionRequest.community must be 20 bytes.
* IntroductionRequest.global_time must be one or higher and up to the local acceptable global time range.
* IntroductionRequest.random must be a non-zero random value used for PunctureRequest.random and Puncture.random.
* IntroductionRequest.destination is the IPv4 address where the IntroductionRequest is sent.
* IntroductionRequest.source_lan is the senders IPv4 LAN address.
* IntroductionRequest.source_wan is the senders IPv4 WAN address.
* IntroductionRequest.connection_type is the senders connection type. The connection_type is only given when it is known.
* IntroductionRequest.synchronization contains a bloomfilter representation of a subset of the senders known persistent messages. It is only given when the sender wants to obtain new persistent messages.

.. code-block:: python

	message IntroductionRequest {
	   enum ConnectionType {
	      public = 1;
	      unknown_NAT = 2;
	   }
	   message Address {
	      optional fixed32 ipv4_host = 1;
	      optional uint32 ipv4_port = 2;
	      optional ConnectionType type = 3;
	   }
	   message Synchronization {
	      required uint64 low = 1 [default = 1];
	      required uint64 hight = 2 [default = 1];
	      required uint32 modulo = 3 [default = 1];
	      required uint64 offset = 4;
	      required bytes bloomfilter = 5;
	   }
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 walk = 2;
	   required bytes community = 3;
	   required uint64 global_time = 4;
	   required Address destination = 5;
	   repeated Address sources = 6;
	   optional Synchronization synchronization = 9;
	}

Dispersy-introduction-response
------------------------------

A temporary message to introduce a, possibly new, peer to the receiving peer. This message is a response to a `dispersy-introduction-request`_ (when a session exists) or a `dispersy-session-response`_ (when a session was negotiated).

SessionResponse limitations:

* SessionResponse.walk is IntroductionRequest.walk.

.. code-block:: python

	message IntroductionResponse {
	   enum ConnectionType {
	      public = 1;
	      unknown_NAT = 2;
	   }
	   message Address {
	      optional fixed32 ipv4_host = 1;
	      optional uint32 ipv4_port = 2;
	      optional ConnectionType type = 3;
	   }
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 walk = 4;
	   required uint64 global_time = 4;
	   repeated Address invitee = 5;
	}

Dispersy-session-request
------------------------

A temporary message to negotiate a session identifier.  This message is a response to a `dispersy-introduction-request`_ when the session is zero or unknown.

Negotiating a session identifier will prevent a malicious peer M from spoofing the address of peer A to deliver a `dispersy-introduction-request`_ to peer B because A will only accept packets from LAN\ :sub:`B`\  or WAN\ :sub:`B`\  containing random\ :sub:`A`\ . Where random\ :sub:`A`\  is a random number generated by A.  This will prevent DOS attacks through IP spoofing.

SessionRequest limitations:

.. code-block:: python

	message SessionRequest {
	   enum ConnectionType {
	      public = 1;
	      unknown_NAT = 2;
	   }
	   message Address {
	      optional fixed32 ipv4_host = 1;
	      optional uint32 ipv4_port = 2;
	      optional ConnectionType type = 3;
	   }
	   extensions 1024 to max;
	   required uint32 version = 1;
	   repeated uint32 version_blacklist = 3;
	   required uint32 walk = 4;
	   required uint32 random_b = 5;
	   required Address destination = 5;
	   repeated Address source = 6;
	}

Dispersy-session-response
-------------------------

A temporary message to negotiate a session identifier. This message is a response to a `dispersy-session-request`_.

Once this message has been received both sides can compute the session identifier $session = (random\ :sub:`A`\  + random\ :sub:`B`\)  mod 2\ :sup:`32`\ . This session identifier is present in all temporary messages, except for `dispersy-session-request`_ and dispersy-session-response.

SessionResponse limitations:

* SessionResponse.walk is IntroductionRequest.walk.

.. code-block:: python

	message SessionResponse {
	   extensions 1024 to max;
	   required uint32 version = 1;
	   required uint32 walk = 4;
	   required uint32 random_a = 5;
	}


Dispersy-puncture-request
-------------------------

A temporary message to request the destination peer to puncture a hole in it's NAT.  This message is a consequence introducing a two peers after receiving a `dispersy-introduction-request`_.

PunctureRequest limitations:

* PunctureRequest.walk is IntroductionRequest.walk.
* PunctureRequest.initiator is one or more addresses corresponding to a single peer.  These addresses may be modified to the best of the senders knowledge.

.. code-block:: python

	message PunctureRequest {
	   enum ConnectionType {
	      public = 1;
	      unknown_NAT = 2;
	   }
	   message Address {
	      optional fixed32 ipv4_host = 1;
	      optional uint32 ipv4_port = 2;
	      optional ConnectionType type = 3;
	   }
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 walk = 4;
	   required uint64 global_time = 4;
	   repeated Address initiator = 5;
	}

Dispersy-puncture
-----------------

A temporary message to puncture a hole in the senders NAT. This message is the consequence of being introduced to a peer after receiving a `dispersy-puncture-request`_.

Puncture limitations:

* Puncture.walk is IntroductionRequest.walk.

.. code-block:: python

	message PunctureRequest {
	   enum ConnectionType {
	      public = 1;
	      unknown_NAT = 2;
	   }
	   message Address {
	      optional fixed32 ipv4_host = 1;
	      optional uint32 ipv4_port = 2;
	      optional ConnectionType type = 3;
	   }
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 walk = 4;
	   repeated Address source = 5;
	}

Dispersy-missing-identity
-------------------------

A temporary message to requests the public keys associated to a member identifier. Receiving this request should result in a `dispersy-collection`_ message containing one or more `dispersy-identity`_ messages.

DispersyMissingIdentity limitations:

* DispersyMissingIdentity.session must be associated with the source address.
* DispersyMissingIdentity.random must be a non-zero random value used to identify the response `dispersy-collection`_.
* DispersyMissingIdentity.member must be no larger than 1024 bytes.
* DispersyMissingIdentity.member must be a valid EEC public key.

.. code-block:: python

	message DispersyMissingIdentity {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 random = 2;
	   required bytes member = 3;
	}


Dispersy-missing-sequence
-------------------------

A temporary message to requests messages in a sequence number range. Receiving this request should result in a `dispersy-collection`_ message containing one or more messages matching the request.

DispersyMissingSequence limitations:

* DispersyMissingSequence.session must be associated with the source address.
* DispersyMissingSequence.random must be a non-zero random value used to identify the response `dispersy-collection`_.
* DispersyMissingSequence.member must be no larger than 1024 bytes.
* DispersyMissingSequence.member must be a valid EEC public key.
* DispersyMissingSequence.descriptor must be the persistent message identifier.
* DispersyMissingSequence.sequence_low must be the first sequence number that is being requested.
* DispersyMissingSequence.sequence_high must be the last sequence number that is being requested.

.. code-block:: python
    
	message DispersyMissingSequence {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 random = 2;
	   required bytes member = 3;
	   required Descriptor.Type descriptor = 4;
	   required uint32 sequence_low = 5;
	   required uint32 sequence_high = 6;
	} 


Dispersy-missing-message
------------------------

A temporary message to requests one or more messages identified by a community identifier, member identifier, and one or more global times. This request should result in a `dispersy-collection`_ message containing one or more message messages matching the request.

DispersyMissingMessage limitations:

* DispersyMissingMessage.session must be associated with the source address.
* DispersyMissingMessage.random must be a non-zero random value used to identify the response `dispersy-collection`_.
* DispersyMissingMessage.member must be no larger than 1024 bytes.
* DispersyMissingMessage.member must be a valid EEC public key.
* DispersyMissingMessage.global_times must be one or more global_time values.

.. code-block:: python
    
	message DispersyMissingMessage {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 random = 2;
	   required bytes member = 3;
	   repeated uint64 global_times = 4;
	} 

Dispersy-missing-last-message
-----------------------------

A temporary message to requests one or more most recent messages identified by a community identifier and member. This request should result in a `dispersy-collection`_ message containing one or more messages matching the request.

DispersyMissingLastMessage limitations:

* DispersyMissingLastMessage.session must be associated with the source address.
* DispersyMissingLastMessage.random must be a non-zero random value used to identify the response `dispersy-collection`_.
* DispersyMissingLastMessage.member must be no larger than 1024 bytes.
* DispersyMissingLastMessage.member must be a valid EEC public key.
* DispersyMissingLastMessage.descriptor must be the persistent message identifier.

.. code-block:: python
    
	message DispersyMissingLastMessage {
	   extensions 1024 to max;
	   required uint32 session = 1;
	   required uint32 random = 2;
	   required bytes member = 3;
	   required Descriptor.Type descriptor = 4;
	} 


Dispersy-missing-proof
----------------------

A temporary message to requests one or more persistent messages from the permission tree that prove that that a given message is allowed. This request should result in a `dispersy-collection`_ message containing one or more `dispersy-authorize`_ and/or `dispersy-revoke`_ messages.

DispersyMissingProof limitations:

* DispersyMissingProof.session must be associated with the source address.
* DispersyMissingProof.random must be a non-zero random value used to identify the response `dispersy-collection`_.
* DispersyMissingProof.member must be no larger than 1024 bytes.
* DispersyMissingProof.member must be a valid EEC public key.
* DispersyMissingProof.global_times must be one or more global_time values.

.. code-block:: python
    
    message DispersyMissingProof {
       extensions 1024 to max;
       required uint32 session = 1;
       required uint32 random = 2;
       required bytes member = 3;
       repeated uint64 global_times = 4;
    } 
