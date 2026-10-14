# HidraNet — Technical Whitepaper

**Version 1.0 · September 2026 · Lisbon, Portugal**
Authors: João Brandão, Leonardo Mello
Software licence: MIT · Repository: NeurexBK/HidraNet

---

## Abstract

HidraNet is an open-source overlay network combining onion routing with
hybrid post-quantum key encapsulation (X25519 + ML-KEM-1024), a Kademlia DHT for peer
and service discovery, and a suite of end-to-end encrypted applications:
messaging, mail, forum, search and a hidden-site publisher. The reference
implementation consists of a Rust network engine (`hidra-node`) and a desktop
browser that bundles Tor as its exit layer while the HidraNet protocol matures
toward a volunteer-operated relay population. This paper describes the
architecture, the cryptographic constructions actually implemented, the threat
model, and — explicitly — the current limitations and the hardening roadmap.

We state one thing plainly, because a whitepaper that overstates is worse than
no whitepaper: **today, exit anonymity is provided by the Tor network.** The
HidraNet protocol layer is implemented and tested, but its relay population is
not yet large enough to provide anonymity on its own. Section 9 sets out how we
get there.

---

## 1. Motivation

Today's internet has three properties nobody chose: communication is observable
by intermediaries, identity is tied to a network address, and content lives on
third-party infrastructure that can remove it.

Existing tools solve parts of this. Tor solves transport anonymity. Signal solves
message confidentiality. None solves the whole, and none is prepared for the day
elliptic-curve cryptography stops being enough.

HidraNet sets out to do three things:

1. **Transport anonymity** through onion routing.
2. **Quantum-resistant confidentiality**, today, not when it is too late.
3. **Usable applications** on top of that base — because a network with no reason
   to be used has no users, and an anonymity network with no users offers
   anonymity to nobody.

---

## 2. The six pillars

### Pillar 1 — Onion routing

Traffic crosses a multi-hop circuit. Each hop removes one layer of encryption and
knows only the previous and the next hop. No single node knows both the origin
and the destination.

Implementation: `hidra-node`'s `onion/` modules — circuit construction
(`builder`), fixed-size cells (`cell`), layer management (`layer`) and circuit
state (`circuit`).

### Pillar 2 — Post-quantum cryptography

Key encapsulation uses **ML-KEM-1024** (the `ml-kem` crate), the highest
security level of the scheme NIST standardised in FIPS 203.

This was `pqc_kyber`, an implementation of the earlier round-3 Kyber draft,
until an audit of the dependency tree turned up two unfixable advisories
against it. RUSTSEC-2026-0290: the AVX2 backend — the one that runs on
essentially every desktop — skips the Fujisaki-Okamoto implicit rejection
step, which hands a chosen-ciphertext attacker the decapsulation key.
RUSTSEC-2023-0079, KyberSlash: division timings that depend on the secret.
The crate is unmaintained (RUSTSEC-2026-0289) and no fixed release exists,
so the dependency was replaced rather than pinned.

This answers the *harvest now, decrypt later* attack: traffic captured today and
stored does not become readable when a cryptographically relevant quantum
computer exists. It is the difference between confidentiality today and
confidentiality that lasts.

### Pillar 3 — Kademlia DHT

Peer discovery and service resolution with no central server. Implemented in
`p2p/dht/` — k-buckets, iterative routing, bootstrap — with the S/Kademlia
defences against Sybil and eclipse attacks:

- **IDs cost work and are bound to a key.** A node ID is the first 20 bytes of
  `BLAKE3("hidra/node-id/v1" ‖ public key ‖ nonce)`, and the nonce is only
  valid if the last 12 bytes of that same hash start with 24 zero bits. The ID
  is unknown until the work is done, so an operator cannot test closeness to a
  target for free and pay only for the IDs it keeps: landing one identity
  among the K = 20 closest to a key in a network of N nodes costs about
  (N / 20) × 2²⁴ hashes, and the whole closest set twenty times that. Every
  DHT message is signed, and its sender's key must be the signing key and its
  ID the one that key and nonce derive. Every node named in an answer is
  checked the same way before it is even asked.
- **A node is what it says about itself, where it was heard.** An answer
  counts only if it comes from the address that was asked, is signed by the
  node that was asked, and carries that node's own description; that
  description, at that address, is what gets seated, never a third party's
  copy. A node that writes first is seated only after it answers a fresh PING
  from the address it wrote from, so a signed packet replayed from elsewhere
  seats nothing; those checks are budgeted (64 at a time, four per network)
  and an address that fails one waits before it is checked again. Once
  seated, a node's address does not move until it stops answering there, and
  only answers to this node's own requests refresh it.
- **Lookups take three disjoint paths, and service lookups walk wide.** The
  closest known nodes, one network at a time, are dealt to three paths that
  never query the same node, and each path keeps its own closest responders.
  A service is announced to, and asked from, every path's closest set and the
  60 closest of all responders, and each path walks, within a fifteen-second
  budget, until every one of the 60 closest nodes it has seen has answered
  one of the paths or failed to. A cluster closer to a service than every
  honest node therefore has to outnumber that, on every path, before a
  lookup stops reaching honest storers.
- **One network, a few seats.** A bucket holds at most two nodes from one
  IPv4 /24 (or IPv6 /48) and the whole table at most ten. Because a node is
  seated only at an address it answered from, the limit counts addresses the
  nodes were reached at, not addresses they claim.
- **Service records are signed by the service, and expire.** A descriptor
  carries the service's own signature over its address, key, revision and
  introduction points; storing nodes and lookups refuse any other, and a
  lookup keeps the highest revision it can verify. A descriptor expires an
  hour after it was signed (a running service re-signs and republishes every
  fifteen minutes; a deleted site stops, so its record is gone an hour after
  it was last signed), one dated more than ten minutes ahead is refused, and
  a node keeps a pushed descriptor unless 60 networks
  it knows are closer to the service, counted one per /24, so a cluster from
  a few networks cannot make honest storers believe they are far and let the
  record expire. Any one node may introduce at most 32 new services an hour
  to another, and a full store evicts the entries of whoever pushed the most
  first and never its own. A node in the path can withhold a record or
  replay an older one; it cannot swap the introduction points, and filling a
  store takes many earned identities pushing every hour.
- **Relay announcements are not passed on.** A relay announces itself to its
  own neighbourhood, found by a lookup; each node it tells seats it after a
  PING, like any contact.

What this does not do: proof of work raises the price of an eclipse with the
size of the network and the difficulty, and an attacker with hardware and
addresses in many networks can still pay it. More than sixty ground
identities closer to a service than every honest node, from many networks
and seated in honest tables, can still keep lookups from reaching an honest
storer; so can a client whose every path starts at attacker nodes because it
knows nothing else. Enough networks can also keep a node's contact checks
busy, so that it seats no newcomer for a while. A node that relays an honest
node's signed answers from its own address can sit between a client and that
node if it is the first address the client meets the node at; it can delay
or drop what it relays, not change it. §5.2 says so.

### Pillar 4 — Hidden services (`.hidra`)

A `.hidra` service is reachable without revealing the IP address of whoever hosts
it. The address derives from the service's public key, which makes it
**self-certifying**: the name *is* the key, and there is no certificate authority
to trust.

SevenNine is the builder and host for these sites.

### Pillar 5 — End-to-end encryption in the applications

Each application encrypts in the client. The network carries ciphertext and has
no means of reading it, even if it wanted to. Cryptographic detail in section 4.

### Pillar 6 — Isolation and fingerprinting resistance

The browser gives every tab an isolated session and an internally consistent
fingerprint profile. Detail in section 5.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    APPLICATIONS (client)                     │
│  HidraChat · HidraMail · Forum · HidraSearch · HidraReview   │
│  SevenNine (.hidra sites)                                    │
│  — encrypt in the client; the network sees only ciphertext — │
├──────────────────────────────────────────────────────────────┤
│                    HIDRA BROWSER (Electron)                  │
│  Per-tab isolation · anti-fingerprint · Tor manager          │
├──────────────────────────────────────────────────────────────┤
│                    HIDRA-NODE (Rust)                         │
│  ┌────────────┬───────────┬──────────┬────────────────────┐  │
│  │ onion/     │ p2p/dht/  │ relay/   │ proxy/  (SOCKS5)   │  │
│  │ circuits   │ Kademlia  │ router   │ browser gateway    │  │
│  ├────────────┴───────────┴──────────┴────────────────────┤  │
│  │ crypto/ — ML-KEM-1024 · X25519 · Ed25519                 │  │
│  │          ChaCha20-Poly1305 · AES-GCM · BLAKE3 · Argon2 │  │
│  └────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│            EXIT LAYER — today: the Tor network (see §9)      │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 Components

| Component | Language | Function |
|---|---|---|
| `hidra-node` | Rust (2024 edition) | Engine: circuits, DHT, relay, SOCKS5 |
| `hidra-browser` | JavaScript / Electron | Interface, isolation, Tor management |
| Applications | JavaScript (Web Crypto) | Client-side encryption |
| SevenNine | Rust (engine module) | Publishing `.hidra` sites |

---

## 4. Cryptographic constructions

This section describes what is implemented, not what is planned.

### 4.1 Engine primitives

| Function | Algorithm |
|---|---|
| Post-quantum key encapsulation | ML-KEM-1024 |
| Classical key agreement | X25519 |
| Signature | Ed25519 |
| Authenticated symmetric encryption | ChaCha20-Poly1305, AES-256-GCM |
| Hash function | BLAKE3, SHA-256 |
| Password-based derivation | Argon2 |

**Where it runs.** The hybrid is the transport handshake itself, not a layer
beside it: `Noise_XXhfs_25519+MLKEM1024_ChaChaPoly_BLAKE3`. Message A carries
an ephemeral ML-KEM-1024 encapsulation key alongside the X25519 ephemeral;
message B carries the ciphertext, and the shared secret is mixed into the
chaining key immediately after `ee` and before the responder's static key is
encrypted. An adversary holding a recording and a quantum computer therefore
breaks the X25519 halves and still cannot read the static key, let alone the
transport. There is no negotiation and no fallback: the protocol name is
hashed into the transcript, so a peer offering X25519-only Noise cannot
complete a handshake rather than silently downgrading one.

**Hybrid approach.** Key agreement combines X25519 with ML-KEM-1024. The session
is only compromised if *both* are broken. It is the current recommendation for
post-quantum transition: you do not abandon what is well studied, you add quantum
resistance on top of it.

### 4.2 HidraMail — encryption scheme

HidraMail implements an ECIES scheme over Web Crypto:

1. **Identity.** An ECDH P-256 key pair generated on the device. The private key
   never leaves the client.
2. **Self-certifying address.**
   `address = base32(SHA-256(public_key)[0..10]) + "@hidra"`
   The address derives from the key, so it is not possible to claim an address
   without holding the matching key.
3. **Encryption.** For each message an **ephemeral** ECDH pair is generated. A
   shared secret is derived with the recipient's public key, imported as an
   AES-256-GCM key, and used to encrypt with a 96-bit IV.
   Wire format: `ephemeral_public_key ‖ IV ‖ ciphertext`
4. **Anti-substitution check.** Before sending, the client recomputes the address
   from the public key obtained from the directory and compares it with the
   destination address. If they do not match, the send is refused. This defeats
   substitution of the recipient's key by a hostile directory.

**Property obtained:** confidentiality and partial forward secrecy (the sender's
ephemeral key is not stored).

**Declared limitation:** the `from` field is an unsigned claim inside the
ciphertext. The recipient knows the message was encrypted for them, but cannot
prove who sent it. **Sender authentication by signature is on the hardening plan
(§9) and must not be assumed today.**

### 4.3 HidraChat — room scheme

Rooms are encrypted with a key derived from a shared password: PBKDF2-SHA-256 →
AES-256-GCM. The topic identifier derives separately from the same password, so
the transport does not reveal the room name.

**Declared limitation:** the current derivation parameters are below present-day
guidance. Strengthening to Argon2id with a per-room salt is in §9.

### 4.4 Presence beacon — metadata leak, fixed

Declared because it is relevant to the threat model.

For headcount purposes, HidraChat used to publish on a **public** MQTT channel
(`hidra/presence/v1`) an object that included the **approximate location derived
from the IP** (latitude, longitude, city, country) and the **topic identifier of
the room** the person was in.

Because the broker is public, anyone could subscribe to that channel and, without
breaking any encryption:

- enumerate active users;
- locate each one at city level;
- group by room identifier and **infer who was talking to whom**.

The content stayed encrypted. The metadata was in the open — and co-presence
metadata plus location is, in many contexts, more revealing than content.

**Fixed.** Geolocation lookup was removed (no call to an external IP service any
more), and the beacon now carries only an ephemeral identifier and a timestamp.
The monitoring panel no longer requests or shows location and room.

**Limitation that remains:** the channel is still public, so the count is
observable by third parties and can be inflated with false beacons. This is
documented in the panel itself. The count should be treated as indicative, not as
a metric.

### 4.5 `.hidra` sites

A service's address derives from its public key, in base32. As with HidraMail,
the name is the key: there is no certificate authority, and resolution is
verifiable by the client itself.

---

## 5. Threat model

A threat model that does not say what it does **not** protect against is
advertising, not engineering.

### 5.1 We protect against

| Adversary | Protection |
|---|---|
| Local network observer (ISP, public Wi-Fi) | Sees encrypted traffic to an entry node; sees neither destination nor content |
| The site visited | Sees the exit node's IP, not the user's; fingerprint randomised per tab |
| An isolated intermediate node | Knows only the previous and the next hop |
| The message transport operator | Carries ciphertext; does not hold the key |
| Cross-tab tracking | Isolated sessions, separate storage, wiped on close |
| Traffic captured for future decryption | ML-KEM-1024 resists quantum cryptanalysis |

### 5.2 We do **not** protect against

Stated explicitly:

| Threat | Why |
|---|---|
| A global adversary observing the whole network | End-to-end traffic correlation defeats any low-latency network, including Tor |
| Compromise of the user's device | If the endpoint is compromised, encryption is irrelevant |
| User operational error | Signing into a personal account undoes the anonymity |
| Volume and timing metadata analysis | Partially mitigated (fixed-size cells); not eliminated |
| Content the user publishes themselves | The network cannot de-anonymise what the person reveals |
| A well-funded Sybil operator in the DHT | IDs cost proof of work, nodes are seated only where they answer, lookups take disjoint paths and walk wide, and service records are signed by the service and expire (Pillar 3); such an operator can withhold a record, not forge one, and with enough hardware and addresses in many networks it can still hide a service, from some clients or from all |

### 5.3 Disclosure of known limitations

We keep a public record of known limitations and the state of their fix. The
absence of such a record in a security tool means nobody is looking, not that
there is nothing to find.

---

## 6. Fingerprinting resistance

Each tab receives a coherent profile: operating system, user agent, GPU,
resolution, timezone and language are chosen **together**, not independently. A
Windows user agent with an Apple GPU is a stronger signal than not masking
anything at all.

Measures implemented:

- Deterministic canvas noise (stable per pixel: two reads of the same canvas
  return the same bytes, otherwise the randomisation would itself be detectable)
- Masking of `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL`
- Timezone coherent between `Intl.DateTimeFormat` and `Date.getTimezoneOffset`
- AudioContext noise
- Removal of `Sec-CH-UA-*` and `X-Client-Data` headers
- Cross-origin `Referer` stripped, same-origin kept (which is functional: CSRF
  protections depend on it)

---

## 7. Applications

| Application | Description |
|---|---|
| **HidraChat** | End-to-end encrypted rooms, key derived from a shared password |
| **HidraMail** | Mail with self-certifying `@hidra` addresses, ECIES encryption |
| **Forum** | Public discussion on the network |
| **HidraSearch** | Meta-search (DuckDuckGo, SearXNG) routed through the network; no query logging |
| **SevenNine** | Builder and host for `.hidra` sites |
| **HidraReview** | Business reviews with their own `.hidra` address |

---

## 8. Implementation status

**Implemented and tested:**
- Rust engine, ~17,000 lines; `cargo build` and `cargo check --all-targets` with
  no errors
- Onion circuits, Kademlia DHT, relay, SOCKS5 proxy
- Hybrid X25519 + ML-KEM-1024 handshake, Ed25519, ChaCha20-Poly1305, AES-GCM,
  BLAKE3, Argon2id
- **110 tests passing** (92 unit + 18 integration: `onion_routing`,
  `dht_discovery`, `key_agreement`, `hybrid_on_the_wire`, `integration`)
- Browser with bundled Tor, per-tab isolation, anti-fingerprinting
- Six working applications

**Exit layer.** Exit anonymity is today provided by the Tor network, bundled in
the browser. The HidraNet protocol is implemented and tested, but an anonymity
network is made of two things: a protocol and a relay population. We have the
first; the second is being built (§9).

The browser verifies its exit IP against the Tor Project's verifier and, when it
**cannot** confirm it, tells the user it did not confirm — instead of asserting
an unverified anonymity.

---

## 9. Hardening plan

Public, with priorities, because a security project's credibility is measured by
what it promises to fix and then fixes.

| # | Item | Priority |
|---|---|---|
| 1 | ~~Network kill switch~~ | ✅ **Done** |
| 2 | ~~Third-party libraries served locally~~ | ✅ **Done** — mqtt 5.16.0 and qrcode-generator 1.4.4 shipped in the package, exact versions |
| 3 | Encryption at rest for key material on the device | Critical — **open**, requires an interface decision (passphrase) |
| 4 | Sender signatures in HidraMail (§4.2) | High — **open**, changes the wire format |
| 5 | ~~WebRTC blocked at the network level~~ | ✅ **Done** — `setWebRTCIPHandlingPolicy('disable_non_proxied_udp')` per tab |
| 6 | Message transport on our own infrastructure | High — **open** |
| 7 | Profile injection at document start, in every frame | High — **open** |
| 8 | Argon2id with a per-room salt in HidraChat (§4.3) | Medium — **open**, breaks existing rooms |
| 9 | ~~Presence beacon without metadata~~ | ✅ **Done** — see §4.4 |
| 10 | Volunteer relay programme | Medium |
| 11 | **Independent external security audit**, with the report published | High |

Item 11 is a condition for broad public release of the browser. We do not
announce a privacy tool to a wide audience before somebody outside has tried to
break it.

---

## 10. Licensing and governance

Software under the **MIT** licence. The protocol is a common good: anyone may
implement, audit, fork and operate nodes.

HidraNet, Lda develops software and provides services. **The company does not
operate exit nodes.** The network is operated by volunteers, as with Tor. It is a
deliberate separation, described in the Governance Guide.

---

## 11. References

- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- Dingledine, Mathewson, Syverson — *Tor: The Second-Generation Onion Router*
- Maymounkov, Mazières — *Kademlia: A Peer-to-peer Information System*
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8032 — EdDSA (Ed25519)
- RFC 8439 — ChaCha20 and Poly1305
- RFC 9106 — Argon2

---

*A living document. Corrections and contributions: see the Contributing Guide.*
