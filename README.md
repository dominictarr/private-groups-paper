# flexible group encryption within a secure broadcast system

//async private groups for secure broadcast medium

## introduction

Most communication software is message oriented, such as email or chat,
messages are transported from sender to recipient, ideally passing as few nodes
as possible. If these messages are encrypted, then the content is private,
but given that messages are routed efficiently from sender to recipient,
the metadata is not private - the system needs to know the recipient in order
to route the message.

In the 2000's a new paradigm for communication software became popular: "social media".
In social media applications, the basic mechanism is more like a broadcast
than a 1:1 message. Usually, users "follow" or "friend" each other, and then recieve
all messages from thier friends. Given that social media applications are typically
implemented as centralized services, they also have significant privacy problems.

SecureScuttlebutt is a decentralized, reliable broadcast system, that maps
well to social media applications. Peers replicate append-only logs in an
eventually consistent fashion. (this corresponds to the "feeds" in social media)
Each message in the log is signed by the author, which means it's authenticity
can be verified, even if it was received from another peer. This is a completely
different architecture on which to implement privacy, and very little research
has been done as to how best to privately communicate under such a model.

Also, "social media" revolves around social groups. privacy for 1:1 messaging
has been researched throughly, but for groups larger than 2, the challenges of
cryptographic privacy are combined with the challenges of distributed systems.
This remains an area needing exploration.

In this paper we investigate what relavant prior art we were able to find,
and as well as design a system for private communication, with individuals and
groups, as best we are able. Although this is a serious attempt we do not claim this
is the best possible solution, and encourage further research.

## aspects

* base architecture : secure broadcast. public keys, signatures, total order (within a feed)

* message encoding : avoid any kind of replay or manipulation, hide metada

* trade off between performance and metadata

* refer to a group without providing access

## notation

based on libsodium api

`box : (message, key, nonce) => cypher_text`
authenticated encryption. box includes a mac tag, at the start,
so any bit flipped in the key, nonce, or cypher_text will cause decryption to fail,
instead of returning a corrupted plaintext.

For clarity, we prefer to describe encryption formats without mentioning the nonce.
In a real implementation, this cannot be ignored. The nonce should be generated randomly,
derived from a hash, or included in the message.

`mult(bob.public, alice.private) => shared_key`
this returns the same value as `mult(alice.public, bob.private)`
so for succinctness we write this as `bob * alice`.
If a bit is flipped in a public key, `mult` will return a different result,
and if this is used to attempt to open a box the authentication will fail.
(several formats encode an ephemeral private key as part of the message, but
not all)

`a + b` means concatination of byte arrays `a` and `b`.

`hash(a)` calculate the hash of byte array `a`.

## design principles

* it's better that something fails to decrypt than to include a vulnerability in the design
* any bit flipped changed should invalidate the message (fail to decrypt)
* a replay of any portion of the message should invalidate the message.
* a property that can be verified in the design is better than one that can only
  be verified in the implementation.

## prior art

### pgp

does not hide any metadata.
not forward secure. But presents the most basic design,
generating a symmetric `key`, encrypting that to a `recipient`,
then encrypting the body of the message with the symmetric `key`.
All the other designs studied build upon this basic structure.

```
key = random()

<bob.id | zeros>
<box(key,alice*bob)>
<box(message, key)>
```

where `bob.id` the hash of the public key `hash(bob.public)`.
If the id is zeros, then anyone receiving the message will attempt to use their key.
Since pgp messages are sent over email, the intended recipient is obvious in anycase.

### minilock

```
ephemeral = random_key()
file_key = random()
file_nonce = random()
cyphertext = box(file, file_key)

<ephemeral.public>
map(recipients, (recipient) => {
  <nonce = random(), //note, this nonce is used by both box calls, but with different keys.
    box(<sender.id, recipient.id,
      box(<file_key, file_nonce, hash(cyphertext)>, nonce, sender*recipient)
    >,
    nonce,
    ephemeral*recipient
  )>
})
<cyphertext>
```

This is stored in a json structure. The number of recipients thus revealed,
but their identity is protected (if sent over email, it's revealed anyway)

The minilock format can be modified in several ways, and still be a valid message
(that is, it can still be successfully decrypted by a standard minilock implementation)

recipients can be removed, even without knowing the key, and body can still be decrypted
by the other recipients. Recipients can be added, but if you know `ephemeral.private`
they will be unable to decrypt the message.

If you know the `file_key` then the same cyphertext can be repeated, with a different header,
and the new recipients will be able to decrypt.

because the hash of the cyphertext is included inside the header, if the same header was used to encrypt
a different file (with the same nonce and key) then the implementation would see that
the message cyphertext hash is different, and abort. However, this property can
only be verified by checking the implementation - a minilock implementation could be
modified to skip this check and it would otherwise work as expected. We perfer to
design security properties that can be verified in the design, where the implementation
simply fails to work if it is incorrect.

### signal group chat

Signal implements group chat on top of 1-to-1 chat model. Each message is simply encrypted
and sent to each member in the group. This works well in the context of signal,

### private-box (secure-scuttlebutt@<=18)

messages format is:

```
key = random()
ephemeral = random_key()

<nonce>
<ephemeral.public>
<box([recipients.length]+key, nonce, recipients[i]*ephemeral)>,...
<box(plaintext, nonce, key)>
```

The design is similar to minilock, but the number of recipients is hidden.
The number of recipients is encrypted to each recipient along with the key,
There is a fixed maximum number of recipients. To decrypt, take the nonce
and `ephemeral.public` and attempt to decrypt each slot, this means that you
must try to decrypt every message the maximum number of times, unless
you succeed early. Although this means that a failed decryption tries
the maximum number of times, so it would seem that this is slow, but
most of the operations are symmetric and on small inputs, so they are very fast.

The boxed message in then attached to your append-only scuttlebutt log.
The sender of a message is public information, because of the public key
and signature embedded in the protocol, but the recipient(s) are hidden.
To know if you are the recipient of a private message, you decrypt all messages.

The same message cyphertext can be replayed on a different feed, and the recipients
will be able to decrypt it, and may be confused that the replayer sent it.
(although the replayer may not have decrypted the message) the replayer
could use the reactions of the recipients to guess who they may be.

If the key is known, the message header can be replayed with a different message body.
(because the role of the cyphertext hash in minilock wasn't understood at this time)

Since this uses an ephemeral key, the sender needs to also encrypt the message to themself.
However, assuming they do that by default, then one of the recipients will be
ephemeral*sender so someone compromising the senders key has access anyway.

Theirfore, the ephemeral key adds an additional asymmetric operation, but does not improve
security. If the key used was just sender*recipient, then it would be equally secure,
but those keys would be cachable, meaning many more decryption attempts could be made.
(given that about 60 unboxes of a small value is equivalent to 1 asymmetric operation)

## groupbox

This design seeks to address the problems of minilock and private-box.
like private-box, it encrypts the number of recipients along with the key,
and also introduces the concept of an `external_nonce` this is a additional
input, which is known to be unique. In ssb, it is the hash of the previous message
in the append-only log. This allows us to prevent all replays, without needing
to include the hash of the cyphertext, as minilock does.

```
external_nonce = hash of previous message
key = random(32)
nonce = random(24)
keys = map(recipients, (recipient) => { recipient * sender })
<nonce>
<box(<key, keys.length>, hmac(external_nonce, nonce), keys[i])>,...
<box(msg, hmac(header, hmac(external_nonce, nonce)), key)>
```

Since the header nonce is derived from the external nonce, it means replaying
the message (or just the header) will fail, because a replayer cannot make
a new valid message with the same key. Thus a replayed message would fail
to decrypt and this would be treated like any other message not addressed to you.

This design is possible on a structure like ssb, but on another system like email,
there may not be a reliable substitute for the external nonce.

If the body was replayed, it would have to be in another message, which would have to have
a different external nonce. This would mean no one is fooled into decrypting a message
not created by the sender.

Also, since the body uses a nonce derived from the external nonce and header,
this means that even if you pass someone the message `key` they will not decrypt
a replayed copy of the message, following the protocol they will select a different
nonce.

As noted with private box, if messages are stored on permanent logs, an ephemeral key
does not give us additional security. Theirfore, we just use sender*recipient as the key.
This can be cached, and so attempting decryption of a groupbox message only uses fast
symmetric operations. This significantly improves performance, so for the same cost,
we may attempt many more decryptions, which is necessary for groups.

## entrusting a single message key

All the formats extend the basic structure established in pgp - the body of the message
is encrypted via a symmetric key, which is used for only this message, and that symmetric
key is encrypted to one or more recipients. This creates a possibility that the key
used to encrypt the body could later be shared.

This unavoidable feature could be used for both legitimate and illegitimate purposes.
An example of a legitimate use may be to receive a security disclosure - some one
privately reports a vulnerability in software, and after the fix is deployed,
the report is transparently published. Group governance may also require private
discussions at times, that may important to reveal at a later time.

An illegitimate use would be to reveal a private message to a third party,
without the consent of it's author. However, there are times where such
an action is warranted, for example, if some is sending abuse or threats
via a private message - it may be necessary to reveal or report that.

Even it was some how cryptographically preventable, it would not be possible
to prevent someone taking a screenshot a private message. On the other hand -
such screenshots are easily doctored, but with secure scuttlebutt's authenticated
design, at least this is prevented, if such things are easily verifyable,
surely an unverifyable leak is not credible.

The process of entrusted a such a key is simple: supply a tuple of
the message id, and the body key to the message: `[hash(message), unboxKey(message)]`
The body key can be obtained by decrypting the message header.

## groups

Although there are group encryption schemes, similar to group signature schemes,
they require each message to be handled by each participant (like signatures) so
they are impractical in a async messaging system, where multiple parties may be offline.

Group software, such as forums, social networks, chatrooms, are very common in social/group
software in general. But most cryptographic software focuses on 1:1 messaging, or at least,
1:n with specific recipients. (as in private-box and signal groups) however,
this doesn't represent human groups such as a _club_ or _company_. We need to add
additional members to groups after the fact.

The simplest possible way to represent a group would be a shared symmetric key.
Any message posted to the group would be encrypted with that key, and members of
the group (who hold that key) would attempt to decrypt any message using
that key, in case it's a group message. Such a simple method is fully decentralized,
but doesn't provide any way to limit membership or remove members.

Obviously, in the worst case, a peer must attempt decryption of each message with each
group. If they are a member of many groups, they will need to try memberships*group_slots.
Cross posting messages across many groups is annoying, so group slots should probably be a lower
number than recipient_slots.

There is also groups such as _friends_ and _family_. These are groups centered on an
individual, but are not unique, everyone one has their own group of friends, although
two groups may overlap. This style of group may also be represented with a symmetric
key, except that key would only be tested on the feed of it's owner. This would mean
a peer could be a member of many centered groups, but would not need to test every
group key on each message - instead, only test it on the feed that group is centered on.

(idea: multidevice: same key, published from multiple devices, reader just needs to know
which feeds have write access to which keys, but then I realized, this could be done with two way
groups too, they just need a membership list. and then check the members)

## identifying groups

### group key as identifier

If the group key is also the identity of a group, then anyone who knows the group
exists can also decrypt or encrypt messages to it.
It is likely that various parts of the system, such as the user interface code,
need to handle some reference to the group -
for example, to query the database who is a member of the given group. It would
be risky to pass around the group key through all this code, the more code,
the more likely a bug enables that key to be inadvertantly leaked, especially
considering that an application developer is likely to be less security focused.

### hash(group_key) as identifier

By hashing the key, the group can be referred to, but leaking the group identity
does not mean everyone can now decrypt group messages. However, if users do mistakenly
publish references to the group publically, observers will know they are refering to
the same group.

### hmac(group_key, member_id) as identifier

Another option would be to have a name for the group per member. This would mean
two group id mentions by different members would not be linkable. To check a group id,
you'd have to iterate over the keys for all known groups and hmac them with the
post's author id. If the number of known groups are small, this prehaps wouldn't be
a big problem. The worst problem with this method, is that it seems very inconvienient
for application developers. It would be necessary to transform raw messages in query
results so that they had a static group key, but this would be a lot of complexity,
and would only protect the accidential linking of keys.

## format of group keys

### simple symmetric key

The simplest method is just to have a symmetric key that is used to decrypt messages
in the group.

```
group_key = random()
group_id = hash(group_key)
```

If a group is just a symmetric key, then adding someone means entrusting the key to them.
this could simply be done by posting a private message containing the key.
(see entrusting group keys, below)

This method has a serious flaw: it would be easy to create a second group
with the same key. If alice creates a group, then bob creates another group with the same
key, then adds charles, charles might believe that he has joined bob's group, but
has actually joined alice's and will now be decrypting alice's messages.

## group_key = hmac(key, founding_msg_id)

In this version, the group key is derived from a founding message.
If the key is entrusted by generating the key, 

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

If the group is founded by generating a key, posting it inside an encrypted message,
then deriving the group key from the key and the message id.

To entrust the group key, you do not share it directly, but rather share a link
to the message, along with the message key, the receiver must retrive the message,
decrypt it, and retrive the plaintext, which contains the key to be combined
with the message id.

group_key = hmac(message.id, unboxBody(message, key).key)
