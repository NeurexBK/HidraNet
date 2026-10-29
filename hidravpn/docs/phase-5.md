# HidraVPN — Phase 5: passes

What exists after this phase: a **pass issuer** that signs passes blind for
accounts under a daily quota; nodes that **admit with a pass** instead of
openly; a client that keeps a wallet of passes, joins such a node by
redeeming one, and **redeems a fresh pass, with a fresh key, every
connection**. The signed node list names the issuer and the keys passes are
signed under.

Phase 4 let a stranger connect: open admission hands an invite to anyone
who asks, three per address every ten minutes. That makes the network usable
and leaves it unaccountable — nobody decides who uses a node, and a script
with many addresses can fill one — and it shows a node the same key every
time the same machine comes back. A pass answers both without telling anyone
who used which node.

## What a pass is

One connection's worth of admission on one node, signed blind by the
issuer: RFC 9474 RSA blind signatures, `RSABSSA-SHA384-PSS-Randomized`,
2048-bit keys (`hidravpn-core/src/pass.rs`).

1. The client picks a node, makes a **fresh WireGuard key** and a random
   nonce for it, and builds the message

   ```text
   "HidraVPN pass v1\0" || issuer key id (8) || node public key (32)
                        || client public key (32) || nonce (32)
   ```

2. It blinds the message and sends only the blinded form to the issuer with
   its account token (`POST /issue`, up to 16 at a time).
3. The issuer checks the account is on and under today's quota, signs what it
   cannot read, and counts the passes — all of a request or none.
4. The client unblinds each signature and checks it. It now holds passes
   that verify under the issuer's key and that the issuer cannot link to the
   request that made them.
5. To connect, the client sends one pass to the node (`POST /redeem` on the
   admission port). The node checks the issuer key is one it trusts and is
   current, that the pass names **this** node, that the signature holds, and
   that the nonce was never spent here. It writes the pass down as spent —
   before admitting, so a crash cannot let it be spent twice — and admits the
   key the pass names, with a lease that lapses soon after it is unused.

What the message binds, and why: the issuer key id, so a pass is checked
under the key it was made for; the node, so a pass spent on one node is not
spent again on another, and a spent list per node is enough; the client key,
so a pass copied off the wire admits only the key its owner holds the secret
of; the nonce, so each pass is spent once.

## What is new

- **`hidravpn-issuer`**, a new program (`crates/hidravpn-issuer`):
  `keygen --out issuer-key.json --days 35` makes a key and prints its record;
  `account add --name N --quota Q` prints the account's token once and keeps
  only its SHA-256; `account list|disable|enable`; `run --key ...` serves
  `POST /issue` (and `GET /keys`). It listens on 127.0.0.1 by default and is
  meant to sit behind a TLS proxy; it refuses any other address without
  `--plain-http-public`. It checks the token and the quota, and charges the
  account, **before** it signs anything — so nobody without an account makes
  it use its secret key — and gives the count back if signing then fails;
  signing runs off the threads that serve connections. Every change to the
  accounts file, by the running issuer or an `account` command, is made under
  a lock on the file system, so neither undoes the other's. It logs counts,
  never an account, a token or an address. Several keys can be served at
  once, for a rotation.
- **Nodes that admit with a pass.** `hidravpn-node init --pass-admission`;
  `hidravpn-node pass-key add record.json | list | remove ID` (the node
  fetches nothing: the operator copies the key from the signed list, and
  restarts the node). Such a node answers `/admit` with `403` and says to get
  a pass; `/redeem` checks the pass and admits. Spent passes live in
  `/var/lib/hidravpn/spent.json`, as hashes (no nonce in the clear), each
  kept until its issuer key expires, then pruned. A pass taken is one line
  appended to `spent.log` beside it and flushed, so taking a pass costs the
  same with a hundred on record or a million; the list is folded back into
  `spent.json` every few thousand passes and when old ones are pruned. A lease won with a pass is
  dropped after `pass_idle_hours` (6) without a handshake, or fifteen minutes
  if it never had one; `max_clients` still applies.
- **The signed list names the issuer**: `pass_issuer` with its `url` and its
  `keys` (id, key, `not_after`); `make-node-list.sh --issuer-url URL
  --pass-key record.json`. A node record can say `"admission": "pass"`. The
  issuer's keys come from the list, never from the issuer: an issuer that
  answered under another key would make passes nobody takes, and is refused.
- **The client and the service.** A wallet of passes,
  `/etc/hidravpn/passes.json` (root only; it holds the secret halves of the
  keys its passes admit). `hidravpn passes token FILE|-` keeps the account
  token (root only); `hidravpn passes get [--count N] [--node NAME]` asks the
  issuer for N passes per pass node, interleaved so the issuer cannot tell
  from a batch which pass is for which node; `hidravpn passes list` counts
  them. A node that admits with a pass needs no joining first: **every
  `connect`, and every new identity, redeems the next pass** as the circuit
  is built (`circuit::prepare`, the same step that asks open nodes for a
  session key), so the node is shown a key it has never seen. The first hop
  redeems its pass directly: it sees this machine's address in any case.
  **The exit of two hops redeems its pass through the entry**, so neither
  the redemption nor the tunnel reaches it from this machine's address; with
  no pass left for it the connection is refused, never built with a key it
  saw before (`anonymity.md`, finding 16). A first hop with no pass left
  reuses its last pass's key, and a note says so. On a new identity the old
  circuit comes down and the kill switch holds the machine to the next
  first hop's own ports while it is asked. A pass the node refused is
  thrown away (and so is one the node took and then answered badly: it is
  spent there); one that never reached it goes back in the wallet. A pass
  redeemed and not yet used is not replaced by another on the next connect:
  it already shows the node a key it has not seen in use. Each invite won
  with a pass remembers when it was redeemed and last used, so a pick or a
  rotation does not land on a node whose lease has likely lapsed when no
  pass is left for it, while another will do; for the exit of two hops,
  only a node with a pass in the wallet will do. The service takes the
  pocket, the wallet and the circuit in that order on every path, and the
  command line and the service take one lock on the pocket's folder to
  change the pocket or the wallet.
- **A fetch that stops midway keeps what it paid for.** Passes are asked
  for sixteen at a time; if a later request fails, the passes from the
  earlier ones — already counted against the account — are kept, and the
  line says where it stopped.
- **The browser gets passes.** The service has `set_pass_token` (root or an
  administrator only, as `up` with an invite; the token goes over the
  control channel once, is written root-only, and is never sent back; the
  token it replaces is kept beside it as `pass.token.previous`, then
  `.previous.1` and on, root-only too: none is ever written over) and `get_passes` (it asks the issuer with the token it keeps, and not
  while two hops are up: `anonymity.md`, finding 20); `nodes` reports each
  pass node's count. The VPN page has a *Passes* card: *Get 10 passes per
  node*, and how an administrator keeps the token (`sudo hidravpn passes
  token FILE`): the browser runs as the person, never as root, so it has no
  token field.
- **An HTTPS client of its own** (`hidravpn-core/src/http.rs`): rustls with
  the Mozilla roots built in, one request, strict limits, chunked answers
  read (a TLS proxy may send them). The token goes over `https://`, or plain
  HTTP to this machine itself, and nowhere else: a private address is not
  enough, since the network a laptop sits on is whoever runs its router.
  `HIDRAVPN_PLAIN_HTTP_ISSUER=1` lifts that for a test network.

## Command lines

```
# the issuer (a machine of the maintainers', behind a TLS proxy)
hidravpn-issuer keygen --out issuer-key.json --days 35 > pass-key.json
hidravpn-issuer account add --name someone --quota 50        # prints the token once
hidravpn-issuer run --key issuer-key.json                    # 127.0.0.1:8730

# the list
bash hidravpn/scripts/make-node-list.sh --key list.key --out nodes.json --sequence N \
     --issuer-url https://passes.example.org --pass-key pass-key.json record-*.json

# a node
sudo bash hidravpn/scripts/install-node-linux.sh ... --pass-admission
sudo hidravpn-node pass-key add pass-key.json && sudo systemctl restart hidravpn-node

# a client
sudo hidravpn nodes import nodes.json
sudo hidravpn passes token token.txt
sudo hidravpn passes get --count 20
sudo hidravpn up --rapido            # joins with a pass the first time, a new pass every time after
```

## How to check it

```
hidravpn/scripts/test-passes-netns.sh      # an issuer, two pass nodes, a client: 42 checks
hidravpn/scripts/test-unit-sandbox-netns.sh  # the service in the unit's sandbox, NetworkManager's resolv.conf
hidravpn/scripts/test-fuzz-netns.sh        # broken requests at /admit, /redeem, /issue
hidravpn/scripts/test-load-netns.sh        # a crowd, a full node, many passes at once
cargo test --manifest-path hidravpn/Cargo.toml --workspace
```

`test-passes-netns.sh` proves, in three namespaces: the issuer makes a key
(a root-only file) and an account whose token it never stores; it refuses
plain HTTP off loopback unless told the network is private; the node takes
the issuer's key and admits with passes only, and shuts the open door; the
signed list carries the issuer; the client keeps the token root-only, gets
three passes, and the issuer refuses a fourth request past the quota, all or
nothing; `connect` redeems a pass with no join first, connects, and the
internet sees the node; a second connection redeems the next pass — a fresh
key, a second lease under an unrelated key; a new identity through the same
node redeems another, a fresh key again, three passes written down as spent;
the browser's own module hands the service the token, which never comes
back, and gets passes through it; a second pass node joins with a pass, a
rotation to it uses that unused key, and a later one redeems its next pass,
after which the internet sees it; two hops with an open entry and a pass
exit: the exit's pass is redeemed through the entry, the exit never
exchanges a packet with the client's address, and with no pass left for it
`connect` is refused and the exit hears nothing; the same
pass redeemed again from a copy of the wallet is refused as already spent; a switched-off account and a token nobody issued get nothing;
and no log names the client's address, an account, a token or a pass's key.

Unit tests cover the rest: a pass verifies only on the node it names, only
under a current trusted key, and not once any of its fields is changed (a
stolen pass with the thief's key, a new nonce, another randomizer, another
signature); a signature under another issuer key is refused when the client
unblinds it; the quota resets each UTC day and a disabled account gets
nothing; spent tags are kept until their key ends; pass leases lapse on their
own clock.

Every earlier suite still passes, twice in a row (see the report of this
round).

## Three harder tests, and what they found

Run after the phase was built, each its own script:

- **`test-unit-sandbox-netns.sh`** (33 checks): the service inside the
  systemd unit's sandbox (everything read-only but `/etc`, `/proc/sys/net`
  and the runtime directory), on a machine without systemd-resolved, with
  `/etc/resolv.conf` as NetworkManager's link into `/run` and as a plain
  file. *Found:* with the link, connecting failed (`writing
  /etc/resolv.conf: Read-only file system`): the write followed the link into
  `/run`, which the unit makes read-only. *Now* the link itself is replaced,
  NetworkManager's file is never touched, and `down` puts the link back. Also
  found: after a power cut while connected, the tunnel's `resolv.conf` stayed
  behind for good (the plan that undoes it lives in `/run`, gone at boot).
  *Now* a copy of the original is kept in `/etc/hidravpn/resolv.conf.saved`
  for as long as a connection is up, and the next start of the service (or
  `hidravpn down`, or the next connection) puts it back.
- **`test-fuzz-netns.sh`** (12 checks, `scripts/test/fuzz-http.py`): tens of
  thousands of broken and mutated requests at a node's `/admit` and
  `/redeem` and the issuer's `/issue` — broken HTTP, broken JSON, oversized,
  half-sent, a real pass rewritten (case, spaces, padding, a lax base64
  letter). Every answer is a well-formed HTTP answer with an expected status;
  nothing is signed or charged for a broken request; a pass written
  differently is still one pass, taken once; nothing panicked or grew. It
  found nothing to fix.
- **`test-load-netns.sh`** (23 checks, `scripts/test/load-http.py`): 300
  admissions at once from 150 addresses fill a node exactly to its limit,
  each client with its own address, while a connected client's tunnel keeps
  answering; 100 passes sent twice each at the same moment fill a pass node
  exactly, none taken twice, and one refused for "full" is not spent.
  *Found:* 150 idle connections held the admission door shut for 19.5 s
  (there were 32 places, each kept for the 5-second timeout). *Now* there are
  256, and one address holds 8 at most: 300 idle connections from one address,
  or 149 from 149, leave the next request answered at once. A determined
  attacker with hundreds of addresses can still hold the door for a while;
  the tunnel is untouched either way. *Found:* the node rewrote its whole
  spent list for every pass, close to a second each at a million passes, so
  15 of 20 redemptions at once were answered "did not answer in time". *Now*
  a pass is one appended line (see above): 20 at once, with a million on
  record, all taken in 0.66 s.

## A review of all the code, and what it fixed

Each fix with a check that fails without it where one could be written.

- **The service under systemd** needs `CAP_CHOWN` to hand the control socket
  and token to the hidravpn group; without it the unit would not start
  (`test-unit-sandbox-netns.sh` now runs the service with exactly the unit's
  capabilities, read from the unit).
- **A tunnel survives its node restarting**: the ICMP error a datagram draws
  while the node is away no longer ends the tunnel (`test-netns.sh`); a stop
  asked before the tunnel listens is no longer lost.
- **A connection that fails partway is undone at once** (routes, plan),
  not at the next connection (the read-only `/etc` case of the sandbox test).
- **Leases are read and written under one lock**, by the node and by
  `admit`/`revoke` alike: a client admitted by hand while the node runs keeps
  its address, a revoked one stays revoked (`test-load-netns.sh`); the file is
  flushed to disk and root only.
- **Passes are not lost**: a full node or a disk error answers 503 (the
  client keeps the pass), never 400; a redemption the admission side stopped
  waiting for is not admitted; the issuer's charge and signing are not cut
  by a connection's timeout; a token nobody issued makes the issuer write
  nothing.
- **The service**: a connect still waiting when it stops is refused, so
  nothing stays routed; two accounts connecting at once cannot take each
  other's circuit; an accept error no longer ends the control channel; the
  token is checked before a command is read; the CLI writes the pocket
  atomically, as the service does; a member of the hidravpn group connects
  with `hidravpn up --rapido` / `--privado` through the service; `uninstall
  --purge` takes the passes and the token too.
- **The browser** waits up to two minutes for a command that goes to the
  network (connect, join, passes), eight seconds for the rest.
- **Windows**: the kill switch replaces its filters in one transaction, with
  no moment without any (built, not run on Windows).
- **Smaller**: answers cut short or not text are refused; dates are parsed
  strictly; a node's own claim of its country is not kept; the token never
  shows in a debug print; interface names are checked before they go into
  the firewall rules; `hidravpn-sign verify` with no file fails.
- **Scripts**: the network suites refuse to run on a machine with HidraVPN
  installed (`scripts/test/guard.sh`); three checks that could pass on a
  failure now cannot; the installer builds as the person who ran sudo, not
  as root; the node's unit runs the binary and settings the installer used;
  `--help` prints the whole text; the release manifest is never written half;
  the prober does not take its own address for the node's; CI also checks
  that every script parses and runs the node installer's dry run.

Left as it is, on purpose: the inner MTU of two hops never goes below 1280
(IPv6 needs it; with a small entry MTU a packet is split, not lost); a
node-full answer still counts against an address's three tries (the limit
protects a full node from being hammered).

## What is honest about this phase

- **A redemption travels in plain HTTP to the node.** It carries nothing
  secret, and a pass names the key it admits, so one copied off the wire is
  of no use to whoever copied it. But someone on the path can send it to the
  node first: the node spends it, and the real client is told it was already
  spent and loses that pass (it takes the next). A nuisance, not a breach.

- **It is not payment.** An account is whatever the maintainers hand out —
  an invitation, a subscription, a donation receipt. How accounts are sold
  is phase 7 (`phase-7-payments.md`): a pack of passes paid in HNET, on an
  account made for the token, prepaid instead of under a daily quota.
- **The issuer is online and holds its secret key**: it signs on demand. It
  is a third key, apart from the release key and the list key, and it is
  meant to rotate: `--days` (35 by default) bounds every pass made under it.
  Whoever holds it can mint passes for every node that trusts it; a leaked
  issuer key means a new key, a new list, and every node's operator removing
  the old one.
- **A node trusts what its operator copied in.** Nodes do not fetch the list;
  a key added or removed takes a restart. A node that never removes an old
  key keeps taking passes under it until it expires — which is why every key
  expires.
- **Unlinkable is not untraceable.** The issuer cannot link a pass to an
  account, and a node cannot link a pass to an account; but someone who
  watches both the issuer and a node can compare times. Fetch passes in
  batches, ahead of time, which is what `passes get --count` is for.
- **The issuer sees an account's address** when it asks for passes, unless
  the request goes through the VPN. That is the price of an account; the
  passes it gets still say nothing about where they are spent.
- **A node in the running circuit keeps its key on a new identity.** With
  one exit only, a new identity reconnects to it with the same key, and says
  so. In the test network the first node sits on the client's own link, so
  even a rotation to it leaves by the physical link and the kill switch stops
  the request; the service then keeps its last key. On the open network nodes
  are not on one's link.
- **Any account on this computer can spend the account's passes** through
  the service. It cannot read the token, and it cannot replace it: since
  phase 7 the token can hold passes bought with HNET, it exists only on this
  machine (the issuer keeps its hash), and the next purchase goes on
  whatever token is kept, so replacing it would wipe a paid balance and send
  the next purchase to someone else's account. Only root (an administrator
  on Windows) replaces it, and the token replaced is kept beside it as
  `pass.token.previous` (then `.previous.1` and on; none is written over).
  `uninstall --purge` removes them all.
- **Nothing of this phase has run on Windows.** It compiles for the Windows
  target; the client side there is the same code, untested at run time.
- **The blind-signature crate sits on a release candidate of `rsa` (0.10).**
  It is the release with constant-time arithmetic, which matters here: the
  issuer signs messages its clients chose, which is exactly the setting in
  which the older `rsa` crate's timing leak (RUSTSEC-2023-0071) could be
  exploited. The crate pins the release candidate; move to `rsa` 0.10 final
  when it ships.
