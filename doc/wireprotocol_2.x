#+TITLE: Dispersy wire protocol\\version 2.0
#+OPTIONS: toc:nil ^:{} author:nil
#+LATEX_HEADER: \usepackage{enumitem}
#+LATEX_HEADER: \setlist{nolistsep}
#+LaTeX_HEADER: \usepackage{framed}
#+LaTeX_HEADER: \usepackage{xcolor}
#+LaTeX_HEADER: \definecolor{shadecolor}{gray}{.9}

# This document uses orgmode (http://orgmode.org) formatting.

#+LATEX: \begin{shaded}
* Choices and discussions
** Using sessions
Dispersy 1.x did not have a session.  This meant that every message
required basic information such as version and community identifier.
By negotiating a session identifier during the 'walking' process we no
longer need to include these values in every message.

Available options are:
- Sessions: :: All walker messages will include version and community
               identification and results in a session identifier (per
               community per peer pair).  All non-walker temporary
               messages use this session identifier.
- Sessionless: :: All temporary messages will include version and
                  community identification.  Response version and
                  community is chosen independently from previous
                  messages.  Obviously no session identifier is
                  negotiated by the walker.
- Hybrid: :: Protocol Buffers support optional fields in messages.
             This allows us to optionally negotiate a session
             identifier (use sessions).  If no session is available
             all non-walker temporary messages must include optional
             version and community identification (sessionless).

*** 09/01/2013 Boudewijn
I prefer to use *sessions*.  There is a lot of session specific
information available (version, community identity, connection-type,
tunnel, encryption, compression).  All of this information can be
negotiated once and will reduce overhead in the non-walker temporary
messages.

Sessions also make sense from a security perspective, where the
session identifier represents a secure number that only the two
communicating parties know.  However, properly doing this requires
some crypto at the expense of CPU cycles.  While a crypto handshake
has a very low priority it can be includes easily when sessions are
used.

I am against using *hybrid*.  While this is the most flexible option
it will also require the most code to create and maintain.  I consider
this bloatware.

*** 11/01/2013 Elric                                                                                         
I'm OK with *sessions*, it doesn't look as it would be too hard to
mantain and will allow us cut on bandwith usage.

*** 10/01/2013 Decision
Currently we use *sessions*.  However, this is subject to change until
more opinions are received.

** Consensus on a real time clock
We can add the local real time clock to every temporary message that
also contains the local global time.  This can allow peers to estimate
the average real time in the overlay.

Having this estimate also allows us to assign real times to received
messages without relying the local time that potential malicious peer
provide.

This can be usefull for the effort overlay (i.e. for consensus on the
current cycle) and channel overlay (i.e. for consensus on the creation
time of a post, torrent, etc.).

Available options are:
- Rely on people: :: We can assume that the local time of all
     computers is set correctly, either by the user or by an OS
     provided mechanism.
- Use time server: :: Synchronizing time is a well known problem.  A
     well known solution is for each peer to contact one of many
     available time servers periodically to obtain the current time.
- Use Dispersy: :: Use a consensus mechanism in Dispersy by adding
                   local real time to messages containing global
                   times.

*** 11/01/2013 Boudewijn
Relying on people to keep their local time up to date is asking for
problems.  Using a time server is the simplest solution, but we would
need to perform this check periodically or at startup.  Using Dispersy
is distributed and hence more complicated.

Using a time server feels like cheating.  Let me explain by comparing
it with the global time.  Currently each peer collects the global time
values from other peers around it.  This results in every peer having
more or less the same global time.  We could just as well use the
bootstrap servers to aggregate global times from peers.  Each peer
could then simply ask the bootstrap servers for the current global
time periodically.  Yet, we choose to let every peer find the average
global time in a distributed manner.  I would argue that we should
also let peers compute the average real time in a distributed manner
for the same reasons.  Hence, I prefer to *use Dispersy*.

I do believe that it will not be possible to prove that a message was
creates at a certain time.  However, I suspect that we -will- be able
to prove that a message was created in a certain time range.  Proving
this may, in itself, be an interested paper topic.

*** 11/01/2013 Elric                                                   
I agree on using consensus to decide on the common real time.  Of
course taking off the unrealistic values from the sample before
averaging it and finding the proper way to check the result with the
system's local time to validate the result.

*** 05/02/2013 Johan
Because of financial reasons it is not possible to spend time on this.
The least effort solution should be used.  I choose *use time server*.

*** 10/01/2013 Decision
We should use a time server.  It is the responsibility of the
community to contact one.  Hence, from Dispersies perspective we
will *rely on the user*, or the community programmer.

** Announcing the local global time
Dispersy uses a [[http://dl.acm.org/citation.cfm?id=359563][lamport clock]] to ensure that we retain the partial
ordering of all persistent messages in the overlay, i.e. our global
time.  

Available options are:
- Minimal announce: :: We announce our local global time only with the
     walker messages.
- Maximal announce: :: We announce our local global time in every
     temporary message.
- Optional announce: :: We can add an optional global time field in
     every temporary message.

*** 10/01/2013 Boudewijn
The walker messages, most likely, trigger other temporary
missing-something messages.  As such, including our local global time
in those missing-something messages would not improve the performance
of the lamport clock.  Hence, I prfer to use *minimal announce*.

*** 10/01/2013 Decision
Currently we use *minimal announce*.  To be precise, only the
dispersy-introduction-request and dispersy-introduction-response
message are used to announce local global time to the neighborhood.
However, this is subject to change until more opinions are received.

** Encoding signatures into a message
The cryptographic signatures must be transferred as part of a message
in some way.  

Available options are:
- Concat: :: We add the signature directly behind the serialized
             message.  This requires us to also add a message length
             field because otherwise we can not unserialize it again
             (protocol buffers will assume the signature is an
             optional field in the message).
- Optional signature field: :: We add an optional signature field into
     the Message container.  We must serialize the submessage, create
     the signature from that, and serialize the container message.
- SignedMessage: :: We distinct between Message and SignedMessage
                    containers.  We would still need to serialize both
                    the submessage and container message.

*** 14/01/2013 Boudewijn
Adding an *optional signature field* seems the simplest by far.  It
also results in only one container message instead of two.  One
disadvantage that I forsee is that we will slowly start to extend the
Message container with optional fields, and that is definately not my
intention.

However, there is one issue that remains.  The Message container (not
the submessage) contains the message type, hence the signature would
-not- include the message type.  Therefore, a small change must be the
inclusion of another container message that has two fields: binary
message and binary signature.  We explicity use the binary
representation of the message because another machine may serialize
the message differently (OS, protocol buffer version, etc) and we can
not afford this to invalidate the signature.

The concat option is also easy to do, however, I dislike spending a
few bytes for the message length and concatting the length, message,
and signature together.  Messing with the bytes should all be done by
protocol buffers.

*** 14/01/2013 Decision
Currently we use *optional signature field* that is modifier with the
additional message wrapper, see dispersy-message.  However, this is
subject to change until more opinions are received.

** Synchronization bloom filters
In Dispersy 1 we create the bloomfilter by hashing {prefix,
binary-packet}.  There are two choices to make:

First choice.  Using either prefix or postfix:
- Prefix: :: Allows you to cache the hashed prefix.  Requires: one
             cache and N+1 hashes to build one N sized bloom filter.
- Postfix (partial cache): :: Allows you to cache each packet.  Every
     postfix must be hashed.  Requires: M hashes to build M caches
     once.  And N hashes to build one N sized bloom filter.
- Postfix (full cache): :: Allows you to cache each packet + postfix
     combination.  Requires: M hashes to build M caches once.  Cache
     storage is potentially cheaper than the partial cache.

Second choice.  How do we represent the message:
- Binary packet: :: The simplest and method is to hash the binary
                    packet.  The packet is unique, even if the data
                    encoded in the packet results in duplicate data.
- Identifying information only: :: The most minimalistic method is to
     hash only the member identifier and global time.  This, combined
     with the current community, must uniquely identify every packet.

*** 17/01/2013 Boudewijn
After several 'timeit' runs I obtained the following statistics:

#+BEGIN_EXAMPLE
0.003818                   # hash one byte                             
0.005269  +0.001451  138%  # hash 300 bytes                            
0.006416  +0.002598  168%  # one byte cache and N times 300 byte update
0.004613  +0.000795  120%  # 300 bytes cache and N times 1 byte update 
0.006080  +0.002262  159%  # 1 + 300 bytes concat hash                 
#+END_EXAMPLE

In these statistics the 168\% represents postfix and 120\% represents
postfix (partial cache).  Obviously the postfix is faster because
fewer bytes need to be hashed.  However, the difference is only
0.001803 seconds for $N=2000$.  Taking into account that the faster
option will require more memory, code, and decision making
(i.e. choosing the subset of packets that we want to cache) does not
justify implementing a cache for every packet.

However, hashing a simple string concatenation, i.e. using no cache at
all, is slightly faster than using a cached prefix.  While the
difference is negligible we can use this strategy with a postfix.
This will allow us too (1) cache often used packets for maximal
performance or (2) implements something simple (concat) but allow the
postfix cache to be added later.  Hence, I prefer *postfix without
caching*.

As for what we hash, I prefer *binary packets*.  We know that it is
the slower of the two options, yet it is the only one that quarantees
dissemination of all data, even when mistakes are made such as one
member creating multiple messages with the same global time.  We've
actually seen this problem occuring (it caused high amounts of
additional traffic) in the effort community.  Granted, this was a bug,
but it allowed us to easily observe the problem and fix it.  Hence it
saved us a lot of development time.

** Protocol buffer version control
One option to make protocol buffers easy to upgrade to new versions,
is to make most fields optional.

#+LATEX: \end{shaded}

* Introduction
This document describes the Dispersy wire protocol version 2 and its
intended behaviors.  Version 2 is *not* backwards compatible.  The
most notable changes are the use of [[https://developers.google.com/protocol-buffers][google protocol buffers]] for the
wire format, protection against IP spoofing, and session usage.  A
complete list of changes is available in following sections.

** 01/01/2013 version 2.0
Changes compared to version 1.3 are:
- Dispersy version, community version, and community identifier have
  been replaced with session identifier for temporary messages
- new message dispersy-collection
- new message dispersy-session-request
- new message dispersy-session-response

* Terminology
- Temporary message: :: A control message that is not stored on disk.
     Messages of this type are immediately discarded after they are
     processed.
- Persistent message: :: A message that contains information that must
     be retained across sessions.  Effectively this includes every
     message that must be disseminated through the network.

* Mechanisms
** Global time
Global time is a lamport clock used to provide message ordering
withing a community.  Using global time, every message can be uniquely
identified using community, member, and global time.

Dispersy stores global time values using, at most, 64 bits.  Therefore
there is a finite number of global time values available.  To avoid
malicious peers from quickly pushing the global time value to the
point where none are left, peers will only accept messages with a
global time that is within a locally evaluated limit.  This limit is
set to the median of the neighbors' global time values plus a
predefined margin.

Persistent messages that are not within the acceptable global time
range are ignored.

* <<<dispersy-message>>>
Protocol Buffers allows messages to be defined, encoded, and finally
decoded again.  However, the way that we intend to use protocol
buffers caused two issues to arise:
1. Multiple different messages over the same communication channel
   requires a method to distinguish message type.  The recommended
   method, as described by Google in [[https://developers.google.com/protocol-buffers/docs/techniques#self-description][self-describing messages]], is to
   encapsulate the message by a message that contains all possible
   messages as optional fields;
2. Adding one or more signatures to a message requires the entire
   message (including the message type) to be serialized and passed to
   the cryptography layer, resulting signatures can only be placed in
   a wrapping message.

   This wrapping message must store the message in binary.  Otherwise
   changes to protocol buffers' internal implementation may cause one
   client to produce a different, yet compatible, binary
   representation.  This would make it impossible to verify the
   signature.

Therefore, the Dispersy protocol will use two wrapping messages.
/Descriptor/ will allow message types to be assigned, while /Message/
will contain the raw message bytes and optional signatures.

#+BEGIN_SRC protocol
message Message {
   extensions 1024 to max;
   required bytes descriptor;
   repeated bytes signatures;
}
#+END_SRC

Descriptor limitations:
- Every temporary or persistent message must have an optional field in
  the Descriptor message.  Community messages must use the field
  values assigned to extensions.
- A dispersy-message may only contain one message, i.e. only one
  optional field may be set.

#+BEGIN_SRC protocol
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
#+END_SRC

Note that field numbers that are higher than 15 are encoded using two
bytes, whereas lower field numbers require one byte, see [[https://developers.google.com/protocol-buffers/docs/proto#simple][defining a
message type]].  Hence the fields that are most common should use low
field numbers.

* <<<dispersy-collection>>>
A temporary message that contains one or more persistent Dispersy
messages.  It is required because persistent Dispersy messages do not
have a session identifier.

Collection limitations:
- Collection.session is associated with the source address.
- Collection.messages contains one or more messages.

#+BEGIN_SRC protocol
message Collection {
   extensions 1024 to max;
   required uint32 session = 1;
   repeated Message messages = 2;
}
#+END_SRC

* <<<dispersy-identity>>>
A temporary message that contains the public key for a single member.
This message is the response to a dispersy-missing-identity request.

Identity limitations:
- Identity.session is associated with the source address.
- Identity.member must be no larger than 1024 bytes.
- Identity.member must be a valid ECC public key.

#+BEGIN_SRC protocol
message Identity {
   extensions 1024 to max;
   required uint32 session = 1;
   required bytes member = 2;
}
#+END_SRC

* <<<dispersy-authorize>>>
A persistent message that grants permissions (permit, authorize,
revoke, or undo) for one or more messages to one or more public keys.
This message must be wrapped in a dispersy-collection and is a
response to a dispersy-introduction-request or dispersy-missing-proof.
(TODO: reference a document describing the permission system.)

Authorize limitations:
- Authorize.version is 1.
- Authorize.community must be 20 bytes.
- Authorize.member must be no larger than 1024 bytes.
- Authorize.member must be a valid EEC public key.
- Authorize.global_time must be one or higher and up to the local
  acceptable global time range.
- Authorize.sequence_number must follow already processed Authorize
  messages from Authorize.member.  Sequence numbers start at one.  No
  sequence number may be skipped.
- Authorize.targets must contain one or more entries.
- Authorize.targets[].member must be no larger than 1024 bytes.
- Authorize.targets[].member must be a valid EEC public key.
- Authorize.targets[].permissions must contain one or more entries.
- Authorize.targets[].permissions[].message must represent a known
  message in the community.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the Authorize.member.

#+BEGIN_SRC protocol
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
#+END_SRC

* <<<dispersy-revoke>>>
A persistent message that revokes permissions (permit, authorize,
revoke, or undo) for one or more messages from one or more public
keys.  This message must be wrapped in a dispersy-collection and is a
response to a dispersy-introduction-request or dispersy-missing-proof.
(TODO: reference a document describing the permission system.)

Revoke limitations:
- Revoke.version is 1.
- Revoke.community must be 20 bytes.
- Revoke.member must be no larger than 1024 bytes.
- Revoke.member must be a valid EEC public key.
- Revoke.global_time must be one or higher and up to the local
  acceptable global time range.
- Revoke.sequence_number must follow already processed Revoke messages
  from Revoke.member.  Sequence numbers start at one.  No sequence
  number may be skipped.
- Revoke.targets must contain one or more entries.
- Revoke.targets[].member must be no larger than 1024 bytes.
- Revoke.targets[].member must be a valid EEC public key.
- Revoke.targets[].permissions must contain one or more entries.
- Revoke.targets[].permissions[].message must represent a known
  message in the community.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the Revoke.member.

#+BEGIN_SRC protocol
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
#+END_SRC

* <<<dispersy-undo-own>>>
A persistent message that marks an older message with an undone flag.
This allows a member to undo her own previously created messages.
This message must be wrapped in a dispersy-collection and is a
response to dispersy-introduction-request or dispersy-missing-proof.
Undo messages can only be created for messages that allow being
undone.  (TODO: reference a document describing the permission
system.)

The dispersy-undo-own message contains a target global time which,
together with the community identifier and the member identifier,
uniquely identifies the message that is being undone.  This message
target must allow being undone.

To impose a limit on the number of dispersy-undo-own messages that can
be created, a dispersy-undo-own message may only be accepted when the
message that it points to is available and no dispersy-undo-own has
yet been created for it.

UndoOwn limitations:
- UndoOwn.version is 1.
- UndoOwn.community must be 20 bytes.
- UndoOwn.member must be no larger than 1024 bytes.
- UndoOwn.member must be a valid EEC public key.
- UndoOwn.global_time must be one or higher and up to the local
  acceptable global time range.
- UndoOwn.sequence_number must follow already processed UndoOwn
  messages from UndoOwn.member.  Sequence numbers start at
  one.  No sequence number may be skipped.
- UndoOwn.target_global_time must be one or higher and smaller than
  UndoOwn.global_time.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the UndoOwn.member.

#+BEGIN_SRC protocol
message UndoOwn {
   extensions 1024 to max;
   required uint32 version = 1;
   required bytes community = 2;
   required bytes member = 3;
   required uint64 global_time = 4;
   required uint32 sequence_number = 5;
   required uint64 target_global_time = 5;
}
#+END_SRC protocol

* <<<dispersy-undo-other>>>
A persistent message that marks an older message with an undone flag.
This allows a member to undo a previously created messages created by
someone else.  This message must be wrapped in a dispersy-collection
and is a response to dispersy-introduction-request or
dispersy-missing-proof.  Undo messages can only be created for
messages that allow being undone.  (TODO: reference a document
describing the permission system.)

The dispersy-undo-other message contains a target public key and
target global time which, together with the community identifier,
uniquely identifies the message that is being undone.  This target
message must allow being undone.

A dispersy-undo-other message may only be accepted when the message
that it points to is available.  In contrast to a dispersy-undo-own
message, it is allowed to have multiple dispersy-undo-other messages
targeting the same message.  To impose a limit on the number of
dispersy-undo-other messages that can be created, a member must have
the undo permission for the target message.

UndoOther limitations:
- UndoOther.version is 1.
- UndoOther.community must be 20 bytes.
- UndoOther.member must be no larger than 1024 bytes.
- UndoOther.member must be a valid EEC public key.
- UndoOther.global_time must be one or higher and up to the local
  acceptable global time range.
- UndoOther.sequence_number must follow already processed UndoOther
  messages from UndoOther.member.  Sequence numbers start
  at one.  No sequence number may be skipped.
- UndoOther.target_global_time must be one or higher and smaller than
  UndoOther.global_time.
- UndoOther.target_member must be no larger than 1024 bytes.
- UndoOther.target_member must be a valid EEC public key.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the UndoOther.member.

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-dynamic-settings>>>
A persistent message that changes one or more message policies.  When
a message has two or more policies of a specific type defined,
i.e. both PublicResolution and LinearResolution, the
dispersy-dynamic-settings message allows switching between them.  This
message must be wrapped in a dispersy-collection and is a response to
a dispersy-introduction-request or dispersy-missing-proof.

The policy change is applied from the next global time increment after
the global time given by the dispersy-dynamic-settings message.

DynamicSettings limitations:
- DynamicSettings.version is 1.
- DynamicSettings.community must be 20 bytes.
- DynamicSettings.member must be no larger than 1024 bytes.
- DynamicSettings.member must be a valid EEC public key.
- DynamicSettings.global_time must be one or higher and up to the
  local acceptable global time range.
- DynamicSettings.sequence_number must follow already processed
  DynamicSettings messages from DynamicSettings.member.
  Sequence numbers start at one.  No sequence number may be skipped.
- DynamicSettings.target_message must represent a known message in the
  community.
- DynamicSettings.target_policy must be a policy that has dynamic
  settings enabled.
- DynamicSettings.target_index must be an existing index in the
  available dynamic settings.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the DynamicSettings.member.

#+BEGIN_SRC protocol
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
#+END_SRC

* <<<dispersy-destroy-community>>>
A persistent message that forces an overlay to go offline.  An overlay
can be either soft killed or hard killed.  This message must be
wrapped in a dispersy-collection and is a response to
dispersy-introduction-request (for soft kill) or a response to any
temporary message (for hard kill).

A soft killed overlay is frozen.  All existing persistent messages
with global time lower or equal to DestroyCommunity.target_global_time
will be retained but all other persistent messages are undone (where
possible) and removed.  New persistent messages with global time lower
or equal to DestroyCommunity.target_global_time are accepted and
processed but all other persistent messages are ignored.  Temporary
messages are not effected.

A hard killed overlay is destroyed.  All persistent messages will be
removed without undo, except the dispersy-destroy-community message
and the authorize chain that is required to verify its validity.  New
persistent messages are ignored and temporary messages result in the
dispersy-destroy-community and the authorize chain that is required to
verify its validity.

A dispersy-destroy-community message can not be undone.  Hence it is
very important to ensure that only trusted peers have the permission
to create this message.

DestroyCommunity limitations:
- DestroyCommunity.version is 1.
- DestroyCommunity.community must be 20 bytes.
- DestroyCommunity.member must be no larger than 1024 bytes.
- DestroyCommunity.member must be a valid EEC public key.
- DestroyCommunity.global_time must be one or higher and up to the
  local acceptable global time range.
- Can not be undone using dispersy-undo-own or dispersy-undo-other.
- Requires a signature matching the DestroyCommunity.member.

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-signature-request>>>
A temporary message to request a signature for an included message
from another member.  The included message may be modified before
adding the signature.  May respond with a dispersy-signature-response
message.

SignatureRequest limitations:
- SignatureRequest.session is associated with the source address.
- SignatureRequest.request is a random number.
- SignatureRequest.message.signatures may not be set.

#+BEGIN_SRC protocol
message SignatureRequest {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 request = 2;
   required Message message = 3;
}
#+END_SRC protocol

* <<<dispersy-signature-response>>>
A temporary message to respond to a signature request from another
member.  The included message may be different from the message given
in the associated request.

SignatureResponse limitations:
- SignatureResponse.session is associated with the source address.
- SignatureResponse.request is SignatureRequest.request
- SignatureResponse.message.signatures must contain one signature.

#+BEGIN_SRC protocol
message SignatureResponse {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 request = 2;
   required Message message = 3;
}
#+END_SRC protocol



# The dispersy-introduction-request message is not disseminated through
# bloom filter synchronization.  Instead it is periodically created to
# maintain a semi-random overlay.

# - supported versions in dispersy version, community version pairs
# - random number
# - possibly suggested cipher suites
# - possibly suggested compression methods
# - possibly session identifier

# ** Dispersy 1: no:sessions, no:ip-spoofing, yes:public-key, yes:signature (steps: 5/9)
# 1. A -> B introduction-req [Ahash, Arandom, Baddr, Alan, Awan, Atype, Abloom, Asig]
# 2. (first-contact) B -> A missing-key [Ahash]
# 3. (first-contact) A -> B key [Akey]
# 4. B -> C puncture-req [Arandom, Alan, Awan]
# 5. B -> A introduction-resp  [Bhash, Arandom, Aaddr, Blan, Bwan, Btype, Clan, Cwan, Bsig]
# 6. B -> A missing-messages
# 7. (first-contact) A -> B missing-key [Bhash]
# 8. (first-contact) B -> A key [Akey]
# 9. C -> A puncture [Chash, Arandom, Clan, Cwan, Csig]

# This strategy *will not* prevent M from spoofing A's address to
# deliver an introduction-req to B.  This attack would cause B to
# respond with, possibly the maximum of allowed bandwidth, to A.
# Resulting in a DOS attack.

# *** IP spoofing attack
# 1. M -> B introduction-req [Ahash, Arandom, Baddr, Alan, Awan, Atype, Abloom, Asig]
# 2. All other steps follow the origional

# This can be used as a DOS attack, where M is the attacker who pretends
# (spoofs) to be A and where A and B are the victim.

# ** Dispersy 2 simple a: yes:sessions, yes:ip-spoofing (steps: 5/7)
# 1. A -> B introduction-req [Arandom, Brandom, Prandom, Baddr, Alan, Awan, Atype, Abloom]
# 2. (new-session) B -> A session-req [Arandom, Brandom, Aaddr, Blan, Bwan, Btype]
# 3. (new-session) A -> B session-res [Brandom]
# 4. B -> C puncture-req [Crandom, Prandom, Alan, Awan, Atype]
# 5. B -> A introduction-resp  [Arandom, Prandom, Clan, Cwan, Ctype]
# 6. B -> A synchronize-res [Arandom, missing-messages]
# 7. C -> A puncture [Prandom, Clan, Cwan, Ctype]

# This strategy *will* prevent M from spoofing A's address to deliver an
# introduction-req to B because A will only accept packets from
# Blan/Bwan containing Arandom.  Where Arandom is a random number
# generated by A.

# This strategy *will not* prevent M, after it intercepts Brandom, from
# spoofing A's address to deliver an introduction-req to B.  Resulting
# in a DOS attack.

# This strategy *will not* prevent man in the middle attacks.  However,
# there is no proof that any non-centralized system can prevent such an
# attack.

# *** Discussion
# Steps 2 and 3 can be extended with Bkey and Akey, respectively.  We
# can also go further and add Bsig and Asig, although this can not
# prevent any attacks.

# #+LATEX: \begin{shaded}
# ** Dispersy 2 simple b: yes:sessions, yes:ip-spoofing (steps: 5/7)
# 1. A -> B introduction-req [ABshared, Prandom, Baddr, Alan, Awan, Atype, Abloom]
# 2. (new-session) B -> A session-req [Brandom, Aaddr, Blan, Bwan, Btype]
# 3. (new-session) A -> B session-res [Arandom]
# 4. B -> C puncture-req [BCshared, Prandom, Alan, Awan, Atype]
# 5. B -> A introduction-resp  [ABshared, Prandom, Clan, Cwan, Ctype]
# 6. B -> A synchronize-res [ABshared, missing-messages]
# 7. C -> A puncture [ACshared, Prandom, Clan, Cwan, Ctype]

# Having consensus on a shared session identifier reduces the complexity
# and memory consumption as Arandom and Brandom are only required during
# steps 2 and 3.

# This strategy *will* prevent M from spoofing A's address to deliver an
# introduction-req to B because A will only accept packets from
# Blan/Bwan containing ABshared.  Where ABshared = (Arandom + Brandom)
# mod 2^{32}.

# This strategy *will not* prevent M, after it intercepts ABshared, from
# spoofing A's address to deliver an introduction-req to B.  Resulting
# in a DOS attack.

# This strategy *will not* prevent man in the middle attacks.  However,
# there is no proof that any non-centralized system can prevent such an
# attack.

# *** Discussion
# Steps 2 and 3 can be extended with Bkey and Akey, respectively.  We
# can also go further and add Bsig and Asig, although this can not
# prevent any attacks.
# #+LATEX: \end{shaded}

# ** Dispersy 2 diffie-hellman: yes:sessions, yes:ip-spoofing (steps: 5/7)
# 1. A -> B introduction-req [ABshared, Prandom, Baddr, Alan, Awan, Atype, Abloom]
# 2. (new-session) B -> A session-req [DH{AB}p, DH{AB}q, DH{AB}b*, Aaddr, Blan, Bwan, Btype]
# 3. (new-session) A -> B session-res [DH{AB}a*]
# 4. B -> C puncture-req [BCshared, Prandom, Alan, Awan, Atype]
# 5. B -> A introduction-resp  [ABshared, Prandom, Clan, Cwan, Ctype]
# 6. B -> A synchronize-res [ABshared, missing-messages]
# 7. C -> A puncture [ACshared, Prandom, Clan, Cwan, Ctype]

# Discussion: steps 2 and 3 can be extended with Bkey and Akey,
# respectively.  We can also go further and add Bsig and Asig, although
# this can not prevent any attacks.

# ** Stuffs
# |---+-------+-------+--------------------+-----------------------------|
# |   | BYTES | VALUE | C-TYPE             | DESCRIPTION                 |
# |---+-------+-------+--------------------+-----------------------------|
# |   |     4 |       | unsigned long      | session identifier          |
# |   |     1 | fb    | unsigned char      | message identifier          |
# |   |     4 |       | unsigned long      | random number A             |
# |   |    20 |       | char[]             | community identifier        |
# |   |     1 |       | unsigned char      | version pair count          |
# | + |       |       | unsigned char      | supported dispersy version  |
# | + |       |       | unsigned char      | supported community version |
# |   |     8 |       | unsigned long long | global time                 |
# |   |     6 |       | char[]             | destination address         |
# |   |     6 |       | char[]             | source LAN address          |
# |   |     6 |       | char[]             | source WAN address          |
# |---+-------+-------+--------------------+-----------------------------|

# |---+-------+-------+--------------------+----------------------|
# |   | BYTES | VALUE | C-TYPE             | DESCRIPTION          |
# |---+-------+-------+--------------------+----------------------|
# |   |     4 |       | unsigned long      | session identifier   |
# |   |     1 | fb    | unsigned char      | message identifier   |
# |   |     4 |       | unsigned long      | random number B      |
# |   |     1 |       | unsigned char      | chosen version       |
# |   |    20 |       | char[]             | community identifier |
# |   |    20 |       | char[]             | member identifier    |
# |   |     8 |       | unsigned long long | global time          |
# |   |     6 |       | char[]             | destination address  |
# |   |     6 |       | char[]             | source LAN address   |
# |   |     6 |       | char[]             | source WAN address   |
# |---+-------+-------+--------------------+----------------------|

# |---+-------+-------+--------------------+-------------------------------------------------|
# |   | BYTES | VALUE | C-TYPE             | DESCRIPTION                                     |
# |---+-------+-------+--------------------+-------------------------------------------------|
# |   |     4 |       | unsigned long      | session identifier                              |
# |   |     1 | fb    | unsigned char      | message identifier                              |
# |   |     4 |       | unsigned long      | (random number A + random number B) modulo 2^32 |
# |   |    20 |       | char[]             | member identifier                               |
# |---+-------+-------+--------------------+-------------------------------------------------|


# |---+-------+-------+--------------------+-----------------------------|
# | + | BYTES | VALUE | C-TYPE             | DESCRIPTION                 |
# |---+-------+-------+--------------------+-----------------------------|
# |   |     4 |       | unsigned long      | session identifier          |
# |   |     1 | f6    | unsigned char      | message identifier          |
# |   |     1 | 00    | unsigned char      | message version             |
# |   |    20 |       | char[]             | community identifier        |
# |   |    20 |       | char[]             | member identifier           |
# |   |     8 |       | unsigned long long | global time                 |
# |   |     6 |       | char[]             | destination address         |
# |   |     6 |       | char[]             | source LAN address          |
# |   |     6 |       | char[]             | source WAN address          |
# |   |     4 |       | unsigned long      | option bits                 |
# |   |     2 |       | unsigned short     | request identifier          |
# | + |     8 |       | unsigned long long | sync global time low        |
# | + |     8 |       | unsigned long long | sync global time high       |
# | + |     2 |       | unsigned short     | sync modulo                 |
# | + |     2 |       | unsigned short     | sync offset                 |
# | + |     1 |       | unsigned char      | sync bloom filter functions |
# | + |     2 |       | unsigned short     | sync bloom filter size      |
# | + |     1 |       | unsigned char      | sync bloom filter prefix    |
# | + |       |       | char[]             | sync bloom filter           |
# |   |       |       | char[]             | signature                   |
# |---+-------+-------+--------------------+-----------------------------|

# The option bits are defined as follows:
# - 0000.0001 request an introduction
# - 0000.0010 request contains optional sync bloom filter
# - 0000.0100 source is behind a tunnel
# - 0000.1000 source connection type
# - 1000.0000 source has a public address
# - 1100.0000 source is behind a symmetric NAT

# The dispersy-introduction-request message contains optional elements.
# When the 'request contains optional sync bloom filter' bit is set, all
# of the sync fields must be given.  In this case the destination peer
# should respond with messages that are within the set defined by sync
# global time low, sync global time high, sync modulo, and sync offset
# and which are not in the sync bloom filter.  However, the destination
# peer is allowed to limit the number of messages it responds with.
# Sync bloom filter size is given in bits and corresponds to the length
# of the sync bloom filter.  Responses should take into account the
# message priority.  Otherwise ordering is by either ascending or
# descening global time.

# ** version 1.1
# The tunnel bit was introduced.

# ** possible future changes
# There is no feature that requires cryptography on this message.  Hence
# it may be removed to reduce message size and processing cost.

# There is not enough version information in this message.  More should
# be added to allow the source and destination peers to determine the
# optimal wire protocol to use.  Having a three-way handshake would
# allow consensus between peers on what version to use.

# Sometimes the source peer may want to receive fewer sync responses
# (i.e. to ensure low CPU usage), adding a max bandwidth value allows to
# limit the returned packages.

# The walker should be changed into a three-way handshake to secure the
# protocol against IP spoofing attacks.



* <<<dispersy-introduction-request>>>
A temporary message to contact a peer that we may or may not have
visited already.  This message has two tasks:
1. To maintain a semi-random overlay by obtaining one possibly locally
   unknown peer (TODO: reference a document describing the semi-random
   walker);
2. To obtain eventual consistency by obtaining zero or more unknown
   persistent messages (TODO: reference a document describing the
   bloom filter synchronization).

#+LATEX: \begin{shaded}
The dispersy-introduction-request, dispersy-introduction-response,
dispersy-session-request, dispersy-session-response,
[[dispersy-puncture-request]], and dispersy-puncture messages are used
together.  The following schema describes the interaction between
peers A, B, and C for a typical walk.  Where we call A: initiator, B:
invitor, and C: invitee.

1. A -> B dispersy-introduction-request \\
   \{shared_{AB}, identifier_{walk}, address_{B}, LAN_{A}, WAN_{A}, bloom_{A}\}

2. B -> A dispersy-session-request (new session only) \\
   \{random_{B}, identifier_{walk}, address_{A}, LAN_{B}, WAN_{B}\}

3. A -> B dispersy-session-response (new session only) \\
   \{random_{A}, identifier_{walk}\}

4. B -> C [[dispersy-puncture-request]] \\
   \{shared_{BC}, identifier_{walk}, LAN_{A}, WAN_{A}\}

5. B -> A dispersy-introduction-response \\
   \{shared_{AB}, identifier_{walk}, LAN_{C}, WAN_{C}\}

6. B -> A dispersy-collection \\
   \{shared_{AB}, missing messages\}

7. C -> A dispersy-puncture \\
   \{shared_{AC}, identifier_{walk}, LAN_{C}, WAN_{C}\}
#+LATEX: \end{shaded}

IntroductionRequest limitations:
- IntroductionRequest.session is associated with the source address or
  zero to initiate a new session.
- IntroductionRequest.community must be 20 bytes.
- IntroductionRequest.global_time must be one or higher and up to the
  local acceptable global time range.
- IntroductionRequest.random must be a non-zero random value used for
  PunctureRequest.random and Puncture.random.
- IntroductionRequest.destination is the IPv4 address where the
  IntroductionRequest is sent.
- IntroductionRequest.source_lan is the senders IPv4 LAN address.
- IntroductionRequest.source_wan is the senders IPv4 WAN address.
- IntroductionRequest.connection_type is the senders connection type.
  The connection_type is only given when it is known.
- IntroductionRequest.synchronization contains a bloomfilter
  representation of a subset of the senders known persistent messages.
  It is only given when the sender wants to obtain new persistent
  messages.

#+BEGIN_SRC protocol
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
#+END_SRC protocol

** TODO add optional tunnel flag
** TODO add optional bootstrap flag

* <<<dispersy-session-request>>>
A temporary message to negotiate a session identifier.  This message
is a response to a dispersy-introduction-request when the session is
zero or unknown.  TODO: reference a document describing the
semi-random walker.

Negotiating a session identifier will prevent a malicious peer M from
spoofing the address of peer A to deliver a
dispersy-introduction-request to peer B because A will only accept
packets from LAN_{B} or WAN_{B} containing random_{A}.  Where
random_{A} is a random number generated by A.  This will prevent DOS
attacks through IP spoofing.

SessionRequest limitations:
- TODO

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-session-response>>>
A temporary message to negotiate a session identifier.  This message
is a response to a dispersy-session-request.  TODO: reference a
document describing the semi-random walker.

Once this message has been received both sides can compute the session
identifier $session = random_{A} + random_{B} ~(mod ~2^{32})$.  This
session identifier is present in all temporary messages, except for
dispersy-session-request and dispersy-session-response.

SessionResponse limitations:
- SessionResponse.walk is IntroductionRequest.walk.
- TODO

#+BEGIN_SRC protocol
message SessionResponse {
   extensions 1024 to max;
   required uint32 version = 1;
   required uint32 walk = 4;
   required uint32 random_a = 5;
}
#+END_SRC protocol

* <<<dispersy-introduction-response>>>
A temporary message to introduce a, possibly new, peer to the
receiving peer.  This message is a response to a
dispersy-introduction-request (when a session exists) or a
dispersy-session-response (when a session was negotiated). TODO:
reference a document describing the semi-random walker.

Limitation:
- SessionResponse.walk is IntroductionRequest.walk.
- TODO

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-puncture-request>>>
A temporary message to request the destination peer to puncture a hole
in it's NAT.  This message is a consequence introducing a two peers
after receiving a dispersy-introduction-request.  TODO: reference a
document describing the semi-random walker.

PunctureRequest limitations:
- PunctureRequest.walk is IntroductionRequest.walk.
- PunctureRequest.initiator is one or more addresses corresponding to
  a single peer.  These addresses may be modified to the best of the
  senders knowledge.
- TODO

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-puncture>>>
A temporary message to puncture a hole in the senders NAT.  This
message is the consequence of being introduced to a peer after
receiving a [[dispersy-puncture-request]], TODO: reference a document
describing the semi-random walker.

Puncture limitations:
- Puncture.walk is IntroductionRequest.walk.
- TODO

#+BEGIN_SRC protocol
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
#+END_SRC protocol

* <<<dispersy-missing-identity>>>
A temporary message to requests the public keys associated to a member
identifier.  Receiving this request should result in a
dispersy-collection message containing one or more dispersy-identity
messages.

DispersyMissingIdentity limitations:
- DispersyMissingIdentity.session must be associated with the source
  address.
- DispersyMissingIdentity.random must be a non-zero random value used
  to identity the response dispersy-collection.
- DispersyMissingIdentity.member must be no larger than 1024 bytes.
- DispersyMissingIdentity.member must be a valid EEC public key.

TODO: dispersy-collection should be renamed into something along the
lines of dispersy-bulk.  This message will contain additional
information to facilitate a bulk transfer, for this message it will
likely not be used, but it will be used for the bulk bloomfilter sync.

#+BEGIN_SRC protocol
message DispersyMissingIdentity {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 random = 2;
   required bytes member = 3;
} 
#+END_SRC protocol

* <<<dispersy-missing-sequence>>>
A temporary message to requests messages in a sequence number range.
Receiving this request should result in a dispersy-collection message
containing one or more messages matching the request.

DispersyMissingSequence limitations:
- DispersyMissingSequence.session must be associated with the source
  address.
- DispersyMissingSequence.random must be a non-zero random value used
  to identity the response dispersy-collection.
- DispersyMissingSequence.member must be no larger than 1024 bytes.
- DispersyMissingSequence.member must be a valid EEC public key.
- DispersyMissingSequence.descriptor must be the persistent message
  identifier.
- DispersyMissingSequence.sequence_low must be the first sequence
  number that is being requested.
- DispersyMissingSequence.sequence_high must be the last sequence
  number that is being requested.

#+BEGIN_SRC protocol
message DispersyMissingSequence {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 random = 2;
   required bytes member = 3;
   required Descriptor.Type descriptor = 4;
   required uint32 sequence_low = 5;
   required uint32 sequence_high = 6;
} 
#+END_SRC protocol

* <<<dispersy-missing-message>>>
A temporary message to requests one or more messages identified by a
community identifier, member identifier, and one or more global times.
This request should result in a dispersy-collection message containing
one or more message messages matching the request.

DispersyMissingMessage limitations:
- DispersyMissingMessage.session must be associated with the source
  address.
- DispersyMissingMessage.random must be a non-zero random value used
  to identity the response dispersy-collection.
- DispersyMissingMessage.member must be no larger than 1024 bytes.
- DispersyMissingMessage.member must be a valid EEC public key.
- DispersyMissingMessage.global_times must be one or more global_time
  values.

#+BEGIN_SRC protocol
message DispersyMissingMessage {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 random = 2;
   required bytes member = 3;
   repeated uint64 global_times = 4;
} 
#+END_SRC protocol

* <<<dispersy-missing-last-message>>>
A temporary message to requests one or more most recent messages
identified by a community identifier and member.  This request should
result in a dispersy-collection message containing one or more
messages matching the request.

DispersyMissingLastMessage limitations:
- DispersyMissingLastMessage.session must be associated with the
  source address.
- DispersyMissingLastMessage.random must be a non-zero random value used
  to identity the response dispersy-collection.
- DispersyMissingLastMessage.member must be no larger than 1024 bytes.
- DispersyMissingLastMessage.member must be a valid EEC public key.
- DispersyMissingLastMessage.descriptor must be the persistent message
  identifier.

#+BEGIN_SRC protocol
message DispersyMissingLastMessage {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 random = 2;
   required bytes member = 3;
   required Descriptor.Type descriptor = 4;
} 
#+END_SRC protocol

* <<<dispersy-missing-proof>>> (#253)
A temporary message to requests one or more persistent messages from
the permission tree that prove that that a given message is allowed.
This request should result in a dispersy-collection message containing
one or more dispersy-authorize and/or dispersy-revoke messages.
(TODO: reference a document describing the permission system.)

DispersyMissingProof limitations:
- DispersyMissingProof.session must be associated with the source
  address.
- DispersyMissingProof.random must be a non-zero random value used to
  identity the response dispersy-collection.
- DispersyMissingProof.member must be no larger than 1024 bytes.
- DispersyMissingProof.member must be a valid EEC public key.
- DispersyMissingProof.global_times must be one or more global_time
  values.

#+BEGIN_SRC protocol
message DispersyMissingProof {
   extensions 1024 to max;
   required uint32 session = 1;
   required uint32 random = 2;
   required bytes member = 3;
   repeated uint64 global_times = 4;
} 
#+END_SRC protocol
