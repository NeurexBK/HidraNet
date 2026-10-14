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
  kept until its issuer key expires, then pruned. A lease won with a pass is
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
  them. `nodes join` and `connect` redeem a pass on a node that admits with
  one; **every later `connect`, and every new identity, redeems the next
  pass**, so the node is shown a key it has never seen. On a new identity the
  pass is redeemed while the old circuit still carries traffic, before the
  kill switch is held, so the request goes through the tunnel and the node
  sees the old exit, not this machine. A node the running circuit goes
  through cannot be asked then (the kill switch lets only the tunnel's
  packets reach it, and a node answers nothing from inside its tunnel): it
  keeps its key that time, at once and saying so. A pass the node refused is
  thrown away (and so is one the node took and then answered badly: it is
  spent there); one that never reached it goes back in the wallet. A pass
  redeemed and not yet used is not replaced by another on the next connect:
  it already shows the node a key it has not seen in use. Each invite won
  with a pass remembers when it was redeemed and last used, so a pick or a
  rotation does not land on a node whose lease has likely lapsed when no
  pass is left for it, while another will do. The redemption on a new
  identity happens without holding the circuit's lock, so `down` is never
  kept waiting on the network. The command line and the service take one
  lock on the pocket's folder to change the pocket or the wallet.
- **A fetch that stops midway keeps what it paid for.** Passes are asked
  for sixteen at a time; if a later request fails, the passes from the
  earlier ones — already counted against the account — are kept, and the
  line says where it stopped.
- **The browser gets passes.** The service has `set_pass_token` (the token
  goes over the control channel once, is written root-only, and is never sent
  back) and `get_passes` (it asks the issuer with the token it keeps); `nodes`
  reports each pass node's count. The VPN page has a *Passes* card: a token
  field emptied the moment it is handed over, and *Get 10 passes per node*.
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
cargo test --manifest-path hidravpn/Cargo.toml --workspace
```

`test-passes-netns.sh` proves, in three namespaces: the issuer makes a key
(a root-only file) and an account whose token it never stores; it refuses
plain HTTP off loopback unless told the network is private; the node takes
the issuer's key and admits with passes only, and shuts the open door; the
signed list carries the issuer; the client keeps the token root-only, gets
three passes, and the issuer refuses a fourth request past the quota, all or
nothing; `connect` joins the node by redeeming a pass, connects, and the
internet sees the node; a second connection redeems the next pass — a fresh
key, a second lease under an unrelated key, two passes written down as
spent; a new identity through the same node keeps its key, says why and does
not wait; the browser's own module hands the service the token, which never
comes back, and gets passes through it; a second pass node joins with a pass,
and a new identity from the first to it redeems its next pass through the
tunnel, a fresh key there too, after which the internet sees it; the same
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

## What is honest about this phase

- **A redemption travels in plain HTTP to the node.** It carries nothing
  secret, and a pass names the key it admits, so one copied off the wire is
  of no use to whoever copied it. But someone on the path can send it to the
  node first: the node spends it, and the real client is told it was already
  spent and loses that pass (it takes the next). A nuisance, not a breach.

- **It is not payment.** An account is whatever the maintainers hand out —
  an invitation, a subscription, a donation receipt. How accounts are sold,
  if ever, is outside this phase, and nothing here promises it.
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
- **Any account on this computer can spend the account's passes**, and can
  replace the token, through the service. It cannot read the token.
- **Nothing of this phase has run on Windows.** It compiles for the Windows
  target; the client side there is the same code, untested at run time.
- **The blind-signature crate sits on a release candidate of `rsa` (0.10).**
  It is the release with constant-time arithmetic, which matters here: the
  issuer signs messages its clients chose, which is exactly the setting in
  which the older `rsa` crate's timing leak (RUSTSEC-2023-0071) could be
  exploited. The crate pins the release candidate; move to `rsa` 0.10 final
  when it ships.
