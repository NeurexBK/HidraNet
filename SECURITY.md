# Security

## What HidraNet is, and what it is not

HidraNet is a young, independently written overlay network. It has not been
audited by anyone outside the project. That sentence is the most important one
on this page, and nothing below it changes it.

Tor has had twenty years of adversarial attention from academics, intelligence
agencies and people whose freedom depended on it. Every serious weakness it has
was found by someone trying to break it, in public, and fixed in the open.
HidraNet has had none of that. The design borrows from Tor because the design
is the part that is well understood; the implementation is new code, and new
code in this field is wrong in ways nobody has looked for yet.

**If being identified would put you in danger, use Tor.** We mean that. The
HidraNet browser ships with Tor built in for exactly this reason, and routing
through it is a supported configuration.

Use HidraNet's own network when you want a second independent overlay, when you
want to run a relay, or when you want to work on it. Not when the cost of being
wrong is high.

## What the current design does defend against

- **An observer on one link.** Traffic between hops is a Noise `XXhfs`
  handshake over X25519 + ML-KEM-1024, then ChaCha20-Poly1305. An observer on
  one hop sees ciphertext and the two endpoints of that hop.
- **A relay in the middle.** Onion layering means a middle relay learns the
  previous and next hop and nothing else — not the origin, not the
  destination, not the content.
- **Someone who records today and decrypts later.** The handshake is hybrid:
  breaking it needs both the X25519 and the ML-KEM-1024 exchange. A recording
  made now is not opened by a quantum computer later unless ML-KEM also falls.
- **A web page attacking the local services.** Everything the node listens on
  is bound to loopback and screens `Host` and `Origin`, so a page cannot reach
  it by DNS rebinding. The circuit view additionally needs a token from a file
  only the user can read.
- **Another account on the same machine.** Secret keys are created `0600` at
  `open(2)` and the keys directory is `0700`. With `HIDRA_KEY_PASSPHRASE` set
  they are also encrypted at rest, which extends this to a stolen disk or a
  copied backup.
- **Another account on the same machine, on the browser side.** The identities
  the browser's apps hold — HidraMail's key pair, the forum token, the chat's
  remembered room passwords, the addresses of published sites — are kept in a
  vault written through the operating system's keychain: the macOS Keychain,
  Windows DPAPI, GNOME Keyring or KWallet on Linux. The key is the OS's, tied
  to the user's login, and never passes through the browser. Each app opens
  only its own compartment, decided from the page's own URL. Where a Linux
  system has no keyring, the data is written as it is and the mail settings
  and the privacy panel say so — Chromium's fixed fallback key is not called
  protection.
- **A log that outlives its usefulness.** Peer addresses, the hostnames asked
  for at an exit, HidraMail addresses, chat nicknames and room ids are scrubbed
  before they reach the log. Content never reaches it at all: an exit relay
  logs how many bytes it relayed and not what they said, which it used to do.
  A Ping body is not logged either — it arrives from a peer, and echoing it
  would let anyone else write an operator's log file.

- **Someone posing as a `.hidra` service.** A service registers with an
  introduction relay only with a fresh signature by the key its address is
  made of, and every session opens with the client challenging the service:
  the service answers with that key's signature over a fresh key exchange,
  checked against the signed descriptor, and the rest of the session is
  sealed end to end. A relay that hands the circuit to anyone else, the relay
  itself included, fails the challenge and can read nothing.
- **An exit pointed inward.** A relay connects for others only to public
  addresses: never to its own loopback, its LAN, link-local space (where a
  cloud host's metadata service sits) or any other reserved range, for an
  exit destination or a circuit's next hop. A name is resolved once and every
  address it gives is checked before the connection is made to that address.
- **Someone replacing another person's content on the public relay.**
  Anyone can publish under any MQTT topic, so what the browser's apps show is
  checked, not trusted: a `.hidra` site is signed by the key its address is
  made of and shown only if the signature holds; forum posts and chat
  messages are signed; a HidraReview listing, its photos and its owner's
  replies are signed by the owner's key, and a browser keeps the first key
  it saw for each listing. Everything a stranger sends is escaped before it
  is shown, and each app runs on an origin of its own, so a script that got
  into one would still have nothing of another's.

## What it does not defend against

- **The first sight of a forum name or a review listing.** A browser that
  has never seen a listing or a forum name believes the first key it is
  shown. Someone who overwrites a listing before your browser first loads it
  is believed by your browser; browsers that saw the real one keep it and say
  that someone tried. The forum has a registrar for names; HidraReview does
  not yet. Sites published before signing (26-character addresses) carry no
  key at all, and the viewer says so.

- **An adversary who can watch both ends.** Someone observing the traffic
  entering the network near you and leaving it near your destination can
  correlate the two by timing and volume. This is true of Tor as well; it is a
  known, unsolved property of low-latency anonymity networks. HidraNet is worse
  off here than Tor simply because it is smaller: fewer users and fewer relays
  mean less to hide in.
- **A small network.** Anonymity is a crowd. On a network of a few hundred
  users, an adversary who can enumerate the relays has a much easier problem
  than on one with millions. No amount of cryptography fixes this.
- **Relays run by one party.** Nothing yet stops someone operating a large
  share of the relays and positioning themselves as both guard and exit.
  Tor has directory authorities, a consensus and bandwidth measurement for
  this. HidraNet does not, and that is the largest architectural gap.
- **A malicious exit.** An exit relay sees traffic as it leaves the network.
  Anything not end-to-end encrypted — plain HTTP, DNS — is readable there.
  Use HTTPS.
- **Code running as you.** The keychain unlocks for your login, so anything
  running under your account — malware, a browser exploit that escapes the
  sandbox — can read what the vault protects, the same as it could read the
  keychain itself. The vault defends the files, not the session.
- **Traffic analysis by shape.** Packets are not padded to a fixed size and
  there is no cover traffic, so the size and timing pattern of a page load
  crosses the network largely intact.
- **A Sybil operator in the DHT.** Node IDs cost proof of work (24 bits,
  bound to the node's key); a node is seated only at an address it answered
  from, as it describes itself; lookups walk three disjoint paths, and
  service lookups the sixty closest nodes they can reach; a bucket seats at
  most two nodes from one /24; and a `.hidra` descriptor must be signed by
  the service's own key, expires an hour after it was signed, and is kept by
  a storer unless sixty networks are closer to the service. Together they
  mean an operator with many identities can withhold a service's record, not
  forge it. With enough hardware and addresses in many networks it can still
  hide a service, from some clients or from all, and a node that relays an
  honest node's signed answers can sit between a client and that node.
- **A DHT peer you talk to.** `.hidra` names are resolved over a Kademlia
  DHT that the client speaks to directly, so a peer it queries learns its IP.
  The client no longer *listens* on a predictable port — it binds an ephemeral
  one, so nobody can sweep the internet for port 7000 and get a list of this
  network's users — but the queries themselves still go out from the user's
  own address. Routing lookups through a circuit is the fix, and it is not
  done.
- **A compromised endpoint.** If your machine is compromised, nothing here
  helps. The keys are on it.
- **The browser's own attack surface.** It is Chromium. Chromium has
  vulnerabilities, and ours is pinned to a version rather than updated by
  Google's release channel.

## Reporting something

Open an issue at https://github.com/NeurexBK/HidraNet/issues for anything that
is not itself dangerous to disclose.

For a vulnerability that puts users at risk, use GitHub's private reporting
("Report a vulnerability" under Security) so there is a fix before there is a
public description. There is no bounty programme; there is a project that
would rather know.

Please include what you did, what happened, and what you expected. A proof of
concept is welcome and never required.

## Dependencies

`cargo audit` runs in CI on every push and pull request, and on a schedule so
that an advisory published against a dependency that has not changed still
surfaces. This is not a formality — it is how the project found that
`pqc_kyber`, the crate the post-quantum handshake was built on, was
unmaintained and carried two unfixable highs: an AVX2 backend that skipped
Fujisaki-Okamoto implicit rejection, handing a chosen-ciphertext attacker the
decapsulation key, and KyberSlash, whose division timings depend on the
secret. It was replaced with `ml-kem` (FIPS 203).

One advisory is currently accepted rather than fixed:

- **RUSTSEC-2025-0141 — `bincode` 1.3.3 is unmaintained.** It parses relay
  commands, which arrive from the network, so it is worth being precise about.
  Frames are capped at 64 KiB before anything is deserialized, deserialization
  is always from a slice and never from a stream, and a crafted length prefix
  was tested against it: a `Vec<u8>` claiming 2^48 elements is refused at
  end-of-input rather than allocated. Unmaintained is still a reason to move,
  and it is tracked — but it is not an exposure today.

## Anonymity-relevant properties worth verifying yourself

Rather than taking the above on trust:

- `cargo test -p hidra-node --test no_addresses_in_logs` fails if any log line
  would write a peer address, a destination hostname, a mail address, a
  nickname or a relayed payload in the clear.
- `node hidra-browser/test/anonymity-claims.js` fails if a badge in the
  browser's anonymity panel claims something the code does not do.
- `node hidra-browser/test/preload-boundary.js` fails if the privileged
  renderer API reaches a page that is not one of ours.
- `ss -lntup` with the node running shows everything it listens on. Expected:
  the relay listener on the configured port in server mode, an ephemeral UDP
  port for the DHT, and loopback-only sockets for the proxy, the status API
  and the apps. A client listening on a fixed, predictable port is a bug.
