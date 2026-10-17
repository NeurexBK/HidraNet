# The HidraNet node handshake

This is the protocol two HidraNet nodes run before any cell crosses between
them: what each message carries, what goes into each hash, and why each
choice was made. It exists so that someone reviewing the code can check it
against a statement of intent rather than reverse-engineer one. The code is
`hidra-node/src/crypto/handshake.rs`; the tests that hold it to this document
are its unit tests, `tests/hybrid_on_the_wire.rs`,
`tests/pq_identity_on_the_wire.rs` and `tests/post_quantum_claims.rs`.

## Goals

1. **Confidentiality against a recording opened later.** Someone who records
   the traffic today and holds it until a cryptographically relevant quantum
   computer exists must not be able to read it. This is the reason the
   handshake is hybrid.
2. **Authentication of the relay.** A client must be talking to the relay it
   meant to, not to whoever sits between them, today and on the day the
   classical schemes fall.
3. **Anonymity of the client towards the relay.** The relay learns the
   client's X25519 static key for this handshake and nothing that ties it to
   a person; clients present a fresh static key per circuit.
4. **Forward secrecy.** Compromise of either party's long-term keys after the
   fact does not open a recorded session.

## Primitives

| Role | Primitive | Where |
|---|---|---|
| Classical key exchange | X25519 | `x25519-dalek` |
| Post-quantum key encapsulation | ML-KEM-1024 (FIPS 203) | `ml-kem` |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305` |
| Hash and KDF | BLAKE3 (plain, keyed, derive-key) | `blake3` |
| Identity signature, classical half | Ed25519 | `ed25519-dalek` |
| Identity signature, post-quantum half | ML-DSA-87 (FIPS 204) | `ml-dsa` |

The protocol name hashed into the transcript is
`Noise_XXhfs_25519+MLKEM1024_ChaChaPoly_BLAKE3`.

## The pattern

The pattern is Noise XX with one addition: the initiator sends a fresh
ML-KEM-1024 encapsulation key in message A, the responder encapsulates to it
in message B, and the shared secret is mixed into the chaining key *before*
the responder's static key is encrypted.

```
-> e, e1
<- e, ee, ekem1, s, es
-> s, se
```

### Message A (initiator to responder)

```
e      32 bytes   X25519 ephemeral public key, in the clear
e1   1568 bytes   ML-KEM-1024 encapsulation key, in the clear
payload           empty; no key yet, so it is sent as is
```

Both `e` and `e1` are mixed into the transcript hash. A responder that
receives fewer than 1600 bytes is talking to a node from before the hybrid
and refuses; there is no negotiation down to X25519 alone.

### Message B (responder to initiator)

```
e              32 bytes   X25519 ephemeral public key, in the clear
ekem1   1568 + 16 bytes   ML-KEM ciphertext, encrypted under k(ee)
s         32 + 16 bytes   responder static key, encrypted under k(ee, kem)
payload       0 or 4692   identity proof (see below), encrypted under k(ee, kem, es)
```

Order matters. `ee` is mixed first; the KEM ciphertext is encrypted under
that key and hashed; the KEM shared secret is mixed next; only then is the
static key encrypted. An adversary who later breaks every X25519 exchange in
the recording still does not hold the key the static key was encrypted
under, because that key depends on the ML-KEM secret.

ML-KEM decapsulation never fails: a tampered ciphertext yields an unrelated
secret (implicit rejection), the chaining keys diverge, and the next AEAD tag
refuses. There is no oracle that says *which* ciphertext was wrong.

### Message C (initiator to responder)

```
s       32 + 16 bytes   initiator static key, encrypted
payload            16   empty, authenticated
```

### Split

After message C both sides derive two transport keys from the chaining key.
The initiator sends under the first and receives under the second; the
responder the reverse. Transport nonces are the Noise ChaChaPoly form: four
zero bytes followed by a little-endian 64-bit counter, one counter per
direction, never reused and never rolled over.

## Key derivation

Noise specifies HKDF over HMAC-HASH. This implementation uses BLAKE3's keyed
mode as the PRF instead:

```
temp  = BLAKE3_keyed(ck, ikm)
out1  = BLAKE3_keyed(temp, 0x01)
out2  = BLAKE3_keyed(temp, out1 ‖ 0x02)
```

This is a deliberate deviation. BLAKE3 keyed hashing is a PRF by design and
a cleaner primitive than HMAC over BLAKE3 would be; the cost is that a
standard Noise library would not interoperate with this handshake, which no
HidraNet component needs. The protocol name says `BLAKE3`, so the two cannot
agree on a key by accident either.

## Checks on the X25519 half

Every Diffie-Hellman result is checked for contributory behaviour: a
low-order peer point, which would force the shared secret to all zeroes, is
refused. Noise leaves this optional; it is done here because a secret an
attacker chose is not a secret.

## Relay authentication

Noise XX authenticates the responder's X25519 static key: after message B
the initiator knows, from the `es` term, that the far end holds the private
half of the key it sent. Two further checks turn that into "this is the
relay I meant".

### Static key pinning

A relay's X25519 static public key may be listed in the client's
configuration (`noise_pubkey`). When it is, the key learned in message B is
compared against it in constant time and a mismatch ends the handshake
before message C, so an impostor never learns the client's static key.
When no key is listed the client connects and says once, at `warn`, that
the hop is unverified. Relays discovered through the DHT are in that state
until the DHT descriptor carries the key.

### Post-quantum identity proof

The X25519 static key is a key a quantum computer recovers from its public
half. So a relay that holds a hybrid identity proves it: the payload of
message B carries

```
0x01                     version
Ed25519 signature        64 bytes
ML-DSA-87 signature    4627 bytes
```

both over `"HidraNet-noise-identity-proof-v1" ‖ h`, where `h` is the
transcript hash immediately before the payload is mixed in. That hash
already commits to both ephemerals, the KEM key and ciphertext, and the
responder's encrypted static key, so the proof binds this identity to this
handshake and cannot be replayed into another.

The initiator verifies the proof against the relay's hybrid identity
(`identity_pubkey` in its configuration: Ed25519 public key followed by the
ML-DSA-87 public key, 2624 bytes, base64). Both halves must verify. With an
identity pinned, a relay that sends no proof is refused. With none pinned,
a proof is noted at `debug` and the hop is treated as before.

The payload is the slot Noise reserves for exactly this and it used to go
empty. An initiator from before the proof decrypts the payload and ignores
it, as the specification says to, so it keeps working against a relay that
proves itself; a new initiator against an older relay sees an empty payload
and falls back to the static-key check.

## What the transport key is used for

The transport ciphers carry the control messages between a client and one
relay (circuit creation, relayed cells). The onion layers that a cell is
wrapped in between the client and each hop use a *separate* key:

```
layer_key = BLAKE3_derive_key("HidraNet onion layer key v1", transport_key)
```

where `transport_key` is the initiator's sending key. Earlier versions used
the transport key itself for both; the split removes a key shared between
two AEAD uses with different nonce disciplines. A client derives the layer
key when the relay proved its identity (which is when the relay is new
enough to expect it) and keeps the transport key otherwise; a relay tries
the derived key on the first cell of a circuit and the transport key when
that fails, then keeps whichever opened it. Nothing is cut off during the
transition.

## Limits a relay enforces

- A freshly accepted connection has 10 seconds to say which protocol it
  speaks and 20 seconds to finish the handshake; each waits on its own task,
  so one silent peer stalls nobody else.
- A session may create at most 64 circuits, and a relay holds at most 4096
  across all sessions. A session's circuits are removed when it ends.
- Frames are capped at 64 KiB before anything is parsed.

## Out of scope here

- Client authentication. The relay does not and must not learn who the
  client is; the client's static key is per circuit.
- Padding and cover traffic. Cells are not padded to a fixed size; this is
  documented in `SECURITY.md` as a known gap.
- The DHT. How a client learns a relay's keys from the network is the DHT
  descriptor's job and is specified with it.

## Known deviations and open points

- BLAKE3 keyed hashing in place of HMAC-based HKDF (above).
- The hybrid pattern is this project's own arrangement of the Noise `hfs`
  idea rather than the published `hfs` extension; the message layout above
  is the specification.
- The ML-KEM and ML-DSA implementations are pure-Rust crates that follow
  FIPS 203 and 204 and are not certified modules.
- The project has not been audited by anyone outside it. This document is
  input to such an audit, not a substitute for one.
