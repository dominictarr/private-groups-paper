# flexible group encryption within a secure broadcast system

//async private groups for secure broadcast medium

## introduction

Most communication software is message oriented, such as email or chat,
messages are transported from sender to recipient, ideally passing as few nodes
as possible. If these messages are encrypted, then the content is private,
but by the fact that messages are routed efficiently from sender to rececipient,
metadata by necessity is not.

Encrypting the metadata is not as easy as the content, to hide who you are
sending a message to, it's necessary to appear to send it everyone, or at least,
for everyone it is sent to, that increases the set of who it might have been for.

The rise of social media in the 2000's has shown that having personal access
to a broadcast medium is quite desireable. However, implementing social media
on a centralized infrastructure also has creates significant unprivate metadata.

SecureScuttlebutt is a secure broadcast system, suitable for implementing
social media applications, yet it is not centralized. As is typical in social
media applications, peers "follow" each other's feeds, and messages from all the followed
feed are displayed merged together in a "timeline" or "newsfeed". In secure
scuttlebutt, these messages are replicated and stored in a local database.
Since the messages are signed, it is not necessary to receive messages directly
from the author. Any peer that also follows a given feed is likely to be able
to provide the messages from that feed.

Given that there is likely to be a large number of peers able to provide
messages, a very resilient broadcast is achived. Messages from a given peer
will eventually reach all their followers.

On top of this platform, we implement a private messaging system.
By broadcasting a private message to all followers and not just the intended recipient,
bandwidth and storage are traded for improved metadata privacy.
Such a message could be intended for any of the peer's follower network
(on even just for themselves)

## aspects 

* base architecture : secure broadcast. public keys, signatures, total order (within a feed)

* message encoding : avoid any kind of replay or manipulation, hide metada

* trade off between performance and metadata

* refer to a group without providing access

## prior art

### pgp

does not hide any metadata.
not forward secure.

```
<receiver.id | zeros>
<box(session_key,sender*receiver>
<box(message, session_key)>
```

### minilock

```
<ephemeral>
<<recipient_nonce><
  box(<sender_id, recipient_id,
      box(<file_key, file_nonce, hash(file_cyphertext)>, nonce, sender*recipient[i]) //**
    >,
    nonce, //** these two boxes use the same nonce, but different keys
    ephemeral*recipient[i]
  )
>,... //1 to many recipients
<file_cyphertext=box(file, file_nonce, file_key)>
```

The number of recipients is revealed in plaintext (via json structure), but their identity is not.
(if sent over email, it's pretty obvious anyway)

recipients can be added or removed, with the same body and still be a valid message.

because the hash is included inside the header, if the same header was used to encrypt
a different file (with the same nonce and key) then the implementation would see that
the message cyphertext hash is different, and abort. Note: this is a property that can only
be verified in the implementation. An implementation might forget this detail,
and it would otherwise seem to work perfectly well. It is preferred to design properties
that can be verified at the protocol level, and if left out of the implementation,
it should not function, and thus be immediately obvious.

### signal group chat

Signal implements group chat on top of 1-to-1 chat model. Each message is simply encrypted
and sent to each member in the group. This works well in the context of signal,

### private-box (secure-scuttlebutt@<=18)

messages format is:

```
<nonce>
<ephemeral_public>
<box(recips.length+boxkey, nonce, recips[i]*ephemeral),...
<box(plaintext, nonce, boxkey)>
```
note, the maximum number of recipients is limited as part of the protocol,
and the length of the recipients is also encrypted. This hides the number of recipients,
but forces the receiver to attempt decrypting the maximum number of times for messages
that are not the recipient of.

The boxed message in then attached to an signed chain of messages.
The sender of a message is public information, but the recipient(s) are hidden.
To know if you are the recipient of a private message, you decrypt all messages.

The same message cyphertext can be replayed on a different feed, and the recipients
will be able to decrypt it, and may be confused that the replayer sent it.
(although the replayer may not have decrypted the message) the replayer
could use the reactions of the recipients to guess who they may be.

If the key is known, the message header can be replayed with a different message body.

Since this uses an ephemeral key, the sender needs to also encrypt the message to themself.
However, assuming they do that by default, then one of the recipients will be
ephemeral*sender so someone compromising the senders key has access anyway.

Theirfore, the ephemeral key adds an additional asymmetric operation, but does not improve
security. If the key used was just sender*recipient, then it would be equally secure,
but those keys would be cachable, meaning many more decryption attempts could be made.
(given that about 60 unboxes of a small value is equivalent to 1 asymmetric operation)

## groupbox
```
external_nonce = hash of previous message
key = random(32)
nonce = random(24)
<nonce>
<box(<key, recipients.length>, hmac(external_nonce, nonce), recipient[i])>,...
<box(msg, hmac(header, hmac(external_nonce, nonce)), key)>
```

the header could be replayed, if the external_nonce is the same. In that ssb is organized
into singly linked lists of messages (called "feeds") with one message in exactly
one feed, this is not possible. A replayed message would not be decrypted by anyone.
This design is possible on a structure like ssb, but could not be used in say, email,
which lacks a suitable value for the external nonce.

If the body was replayed, it would have to be in another message, which would have to have
a different external nonce. This would mean no one is fooled into decrypting a message
not created by the sender.

As noted with private box, if messages are stored on permanent logs, an ephemeral key
does not give us additional security. Theirfore, we use sender*recipient as the key.
this can be cached, and so attempting decryption of a groupbox message only uses fast
symmetric operations.

## groups

Although there are group encryption schemes, similar to group signature schemes,
they require each message to be handled by each participant (like signatures) so
they are impractical in a async messaging system, where multiple parties may be offline.

Group software, such as forums, social networks, chatrooms, are very common in social/group
software in general. But most cryptographic software focuses on 1:1 messaging, or at least,
1:n with specific recipients. (as in private-box and signal groups) however,
this doesn't represent human groups such as a _club_ or _company_.

The simplest possible way to represent a group would be a shared symmetric key.
Any message posted to the group would be encrypted with that key, and members of
the group (who hold that key) would then attempt to decrypt any message using
that key, incase it's a group message. Such a simple method is fully decentralized,
but doesn't provide any way to limit membership or remove members.

Obviously, in the worst case, a peer must attempt decryption of each message with each
group. If they are a member of many groups, they will need to try memberships*group_slots.
Cross posting messages across many groups is annoying, so group slots should probably be a lower
number than recipient_slots.

There is also groups such as _friends_ and _family_. These are groups centered on an individual,
but are not unique, everyone one has their own group of friends, although two groups may overlap.
This style of group may also be represented with a symmetric key, except that key would only
be tested on the feed of it's owner. This would mean a peer could be a member of many centered
groups, but would not need to test every group key on each message - instead, only test it
on the feed that group is centered on.

(idea: multidevice: same key, published from multiple devices, reader just needs to know
which feeds have write access to which keys, but then I realized, this could be done with two way
groups too, they just need a membership list. and then check the members)

---

## adding someone to a group

If a group is just a symmetric key, then adding someone means entrusting the key to them.
this could simply be done by posting a private message containing the key.

reusing a key is the same as adding someone to that group, but: does the recipient realize
that they have been added to a group. For example: if alice has a one-way group with key: k,
and bob creates a multiway group also with key: k, then someone added to the group
would also decrypt alice's messages, possibly without realizing alice isn't in the group.
Bob has surreptitiously added someone to alice's group: it would be better if no one
could add you to a group without you realizing.

### just send someone the secret

is it possible for groups to collide? (or reuse a key with surprising effects?)

### send someone key to message that defines the group

---

## ways to reference a group

### hash of the group key

does not reveal the secret. two groups with the same key would have the same id.

### id of message defining group

each message is gauranteed unique, so no group collisions. however, knowing this would
reveal the identity of the creator of the group. essentially, the hash of the cyphertext
of the encrypted secret of the group.

### hmac(founding_message, secret)

The group id depends on both the plaintext key and cyphertext of that key. since we know
the message is unique, someone that chooses to construct a group with a non-unique key
will still end up with a unique identity.


