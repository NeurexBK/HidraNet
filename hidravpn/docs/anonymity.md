# HidraVPN — who can see what

This document records an audit of HidraVPN for anonymity, not only for
encryption. For every party that could observe a HidraVPN user, it says what
that party learns today and points to the code (file:line, as of this
change) and to the test that proves it. A claim with no test is marked as
not verified.

The words stay what they were in every phase: **strong privacy, not
anonymity**. Two hops remove the single place that knows both who you are and
where you go. They do not stop two parties who watch both hops at once from
matching times and volumes. No VPN can make that promise, and this one does
not.

The audit started from one question. A community reviewer had found that
HidraNet's onion circuits showed the client's address to every relay. Did
HidraVPN have gaps of the same kind? It did. They are listed below with what
was done about each one.

## What changed, in short

Every node that admits openly — all the nodes on the maintainers' list — is
shown a key made for one connection. It sees that key once and forgets it
about ten minutes after the connection ends. So no node can tell, by key,
that two connections are the same person. This holds for:

- the exit of two hops, which is asked for that key *through the entry*,
  so it never hears from your address;
- the entry;
- the node of one hop.

Before this change, the exit of two hops could tie your address to your
traffic in two ways:

- a node that admits openly was asked for admission straight from your
  address, and later saw the same key carrying your two-hop traffic;
- a node used for one hop saw the same key it later saw as your exit.

Without an address, the stable key of every node let it follow you across
days, networks and places.

The other gaps are closed too:

- An entry cannot read anything a program pushes into the outer tunnel.
- Two hops under one operator are refused unless you say yes.
- Logs at DEBUG no longer record the names clients look up.
- A dead exit no longer leaves the tunnel broken for good.
- The browser's leak test can no longer be the leak itself.
- Admission is paid for with a second of computing, not counted per
  address.
- A node whose software is older than all this is passed over, and the
  person is told why.
- Nodes that admit with a pass (phase 5) follow the same rule: each
  connection shows them the next pass's key, and the exit of two hops
  redeems it through the entry, never from your address (finding 16).

## Who learns what

"Today" means after this change; the findings below say what was different.

| Party | Learns | Does not learn |
|---|---|---|
| **Your local network / ISP** | That you use WireGuard, to which entry address and port; when, and how much; DHCP as before. | Destinations, DNS names, anything inside the tunnel. IPv6: nothing (blocked). |
| **Entry node (two hops)** | Your address. A key made for this connection (`circuit.rs:663`), so across connections it has only your address to go by — and if you move between networks, not even that. Which exit you use (it forwards to it). When you connect, for how long, how much. One admission request to the exit per connection: plain HTTP inside your tunnel, so the entry can read it, and it carries only a fresh public key and the word "client". | Destinations, DNS names: its resolver is never asked and nothing but WireGuard to the exit leaves the outer tunnel (`killswitch/linux.rs:103-121`, test A). |
| **Exit node (two hops)** | Destinations, DNS names, and traffic content that is not encrypted end to end. The entry's address. A key made for this one connection (`circuit.rs:848`), and an inner address leased to it. If it admits with a pass: one pass, redeemed through the entry. | Your address (test A, and the passes test: zero packets from it). Any key it has seen from your address (test B). Whether two connections, or the connections before and after a new identity, are the same person, *by key* (tests B, C). Which account a pass came from (blind signatures, phase 5). |
| **Node used for one hop (Rápido)** | Your address and your traffic. That is what one hop is, and the page says so. A key made for this connection. | Your two-hop sessions through it, and your other one-hop sessions, by key (test B). |
| **One operator running entry and exit** | Everything: who and where. | — That is why such a pair is refused unless you say yes (`pocket.rs:410`, `daemon.rs:1259`, test C). |
| **Two operators who compare notes** | No key in common (`keys.rs`). They can still match the entry's records ("this address sent this much at 10:02") against the exit's ("this key received this much at 10:02"). This includes the admission request the entry forwarded a moment before the exit admitted a fresh key. That is the timing residue of any two-hop design; see "Open". | Anything a key can link. |
| **A site you visit** | The exit's address. | Your address, unless you tell it (cookies, logins: that is the browser's job, and the browser's own tabs go through Tor regardless). |
| **hidranet.org (list and release server)** | That a Tor exit fetched the node list or a release file, when you press the button. The request carries no cookies and a generic user agent, and is refused while Tor is not ready (`main.js:51-105`). | Your address (Tor). Not verified at run time: whether Electron's `net.fetch` honours the overridden user agent (a lint test checks the code, not the wire). |
| **api.ipify.org (the leak test)** | The exit's address, and that someone asked at that moment, when you press the button. | Your address: the test refuses to run unless the kill switch is armed and the exit shook hands in the last three minutes (`vpn-leaktest.js`). The browser's name and version are not sent either. |
| **Websites, inside the browser** | Nothing about the VPN: no header, global or bridge reaches a website (`test/preload-boundary.js`). | — |

## Findings

Severity is about what an attacker learns, not how hard it is to exploit.

### 1. Critical — open admission showed the exit your address *and* the key it would see

`connect privado` with a pocket that only knew the nodes joined every open
node, exits included, straight from the client's address (before: the
daemon's `join(None)`). The exit got `POST /admit` with the key it would then
see on every two-hop session. An exit operator could therefore read your
address next to your traffic. The admission test did exactly this
(`test-admission-netns.sh`: node-a, the exit, was joined from the client).

**Fixed.** An exit of two hops is asked for admission through the entry,
with a fresh key: `circuit::admit_behind` (`hidravpn-core/src/circuit.rs:848`).
While it runs, the kill switch allows only the encrypted packets to the entry
and, inside the outer tunnel, one TCP connection to the exit's admission port
(`killswitch/linux.rs`, `bridge_ruleset`). It sends no DNS and adds no
default route into the entry. An entry forwards TCP 51821 for this, and still
nothing else (`hidravpn-node/src/nat.rs:60`). For two hops the client asks
only entries from its own address (`circuit.rs:663`, `prepare`, used by the service and `hidravpn/src/main.rs`).

**Test:** `test-anonymity-netns.sh` A: 0 packets from the client to any exit,
0 packets at the exit from the client's address, and the exit's own peer
table shows the session coming from the entry. Before the fix: 10, 5 and the
client's address.

### 2. Critical — the same key for one hop and as an exit

The key a node is shown was derived from the master key and the node's key
only. A node used once for one hop (it sees your address) and later as your
exit saw the same key, and could tie the two-hop traffic to your address.

**Fixed.** An exit of two hops is never shown the one-hop key. If it admits
openly, it gets a fresh random key per connection. If it was admitted by
hand, it gets a key derived with another salt, `for_node_behind`
(`keys.rs:102`), which the operator admits with
`hidravpn pubkey --node K --behind`. A pocket lease for that key is used for
two hops only (`Invite.behind`, `pocket.rs`).

**Test:** B: one hop through exit-b, then two hops through it; the keys
differ, and no key the exit ever saw from the client's address appeared from
anywhere else. Before the fix: the same key.

### 3. High — the exit saw the same key on every session, for thirty days

Even without an address, a stable key lets an exit build a profile: "this key
visits these sites, every evening, for months". Openly admitted leases lived
for 30 idle days.

**Fixed, for exits that admit openly** (all listed nodes do):

- A fresh key on every connection and every new identity, even to the same
  exit (`circuit.rs:663`).
- The exit keeps such a "session" lease only until ten minutes after the
  last packet it received under that key (`hidravpn-node/src/leases.rs:61`,
  `:241`).

**Not fixed for exits admitted by hand:** they see one stable key behind
the entry. The operator who admitted it knows who asked for it. Use such
nodes as entries.

**Tests:** B and C (a new key on each connection and each new identity), E
(the exit no longer holds any key a two-hop session showed it).

### 4. High — DEBUG logging on a node recorded every name clients looked up

`RUST_LOG=debug` turned on the DNS library's own logging, which writes each
query name, so an operator chasing a problem recorded what every client
looked up. The service and the client had the same exposure through their
libraries.

**Fixed.** Whatever `RUST_LOG` asks for applies only to HidraVPN's own
crates. Every other crate is silenced (`hidravpn-core/src/logging.rs:14`,
used by all three binaries).

**Test:** F. Every node and the service run at DEBUG through every test
above, failures included: an invalid admission request, an exit killed
mid-session, a connection to a dead exit. No log contains any of:

- the client's address
- its tunnel addresses
- the master key
- any key it presented, in base64 or hex
- the canary name looked up or sent

Before the fix the canary name appeared in the exit's log.

### 5. Medium — the entry could see what a program pushed into the outer tunnel

The kill switch allowed everything on the outer interface. A program that
bound to it (deliberately or by accident) sent its packets to the entry. The
entry could read their destinations, and its resolver would answer names.

**Fixed.** With two hops the outer interface carries only UDP to the
exit's endpoint: on Linux in `killswitch/linux.rs:103-118`, on Windows with
a WFP filter for that one peer (`killswitch/windows.rs:401`, finding 15).
The Windows rules have not run with two hops yet (see Open, 4).

**Test:** A: a socket bound to the outer interface reaches neither the
entry's resolver nor, through it, the internet; the entry's counters stay 0.
Before: the entry counted the HTTP packets.

### 6. Medium — two hops could silently be one operator's

Privado preferred two operators but fell back to one without asking. A new
identity rotated at random with no regard for operators. An operator the list
did not name counted as "different".

**Fixed.** A pair whose operator is the same, or not named, is refused unless
the person says yes:

- `allow_same_operator` on the control channel;
- `--allow-same-operator` on the command line;
- a box on the VPN page, off by default.

A new identity never moves to such a pair. It says which exits it passed
over and why (`daemon.rs:1259`). `status` still reports `same_operator`.

**Test:** C.

### 7. Medium — a dead exit left the tunnel dead

When the exit stopped, its ICMP error made the client's tunnel task end. The
service then panicked ("JoinHandle polled after completion",
`tunnel.rs:136`), and the tunnel never recovered. The kill switch held, so
nothing leaked, but the person stayed offline until they reconnected.

**Fixed.** Transient socket errors are waited out (`tunnel.rs:279`), and a
finished task is not awaited twice.

**Test:** D: the exit is killed for six seconds; the kill switch stays armed;
when the exit comes back, the session resumes. Throughout, 0 IPv4 packets and
0 DNS packets leave the client outside the tunnel. The one exception is
the kernel's ICMP "port unreachable" sent to the entry about the entry's own
packet; the test allows it by name.

### 8. Medium — the leak test could itself be the leak

The test asked api.ipify.org directly, bypassing Tor, whenever the service
said "connected", even with the kill switch off or a tunnel that was not
carrying traffic. With the kill switch off, that request could leave from
the person's own address. It also sent the browser's name, version and
system.

**Fixed.** The test runs only with the kill switch armed and an exit
handshake in the last three minutes. With the kill switch off it asks no
website anything and says why. The probe sends a generic user agent and no
cookies (`vpn-leaktest.js`, `main.js:109-132`).

**Tests:** `hidra-browser/test/vpn-leaktest.js` (9), `test/vpn-page.js` (54).

### 9. Low — the list and release fetches named the browser

`net.fetch` sent Electron's default user agent and could carry cookies. The
code itself says that whether it honours the Tor lock depends on the Electron
version.

**Fixed:** a generic user agent, `credentials: 'omit'`, and an explicit
refusal while the Tor lock is engaged (`main.js:51-105`).

**Not verified on the wire:** a lint test checks the code; no test captures
the request.

### 10. Checked, nothing to fix

- **Inner addresses** are leased by each node, in order, per key. They are
  derived from nothing about the user. With fresh keys, an exit's inner
  address for you changes with every connection.
- **Lease names** sent on admission are the constant "client"
  (`circuit.rs`, `prepare`).
- **DNS** goes to the exit's resolver through both hops. Any other resolver is
  dropped by the kill switch (`killswitch/linux.rs`, "DNS only to the
  node"). Tests A and D: the resolver sees the canary name from the exit, and
  no DNS packet appears on the client's link.
- **Rotation and reconnect** hold the kill switch from the moment the old
  circuit starts to come down. Test D also covers the new admission through
  the entry.
- **Node probing order** is uniform at random from the operating system
  (`random.rs`). The node list is fetched only when the person presses the
  button, never on a timer.
- **The browser** sends the service nine commands (status, connect, down,
  new identity, the node list, importing it, passes, the pass token and
  automatic passes), never joins a node, and
  holds no key or invite. The VPN bridge exists only on our own pages (`preload-boundary`
  test). No VPN state reaches a website.

### 11. High — entries and one-hop nodes kept a stable key per person (second round)

The first round gave the exit a fresh key, but the entry and the node of one
hop still saw one stable key per person. They see the address anyway. Still,
a stable key let a node follow a person across networks: home in the
morning, a café at noon, the same key both times. Their leases also kept
every key's activity on disk for 30 days.

**Fixed.** Every node that admits openly is asked for a key for each
connection, the first hop directly (`circuit::prepare`, `circuit.rs:663`).
Connecting no longer "joins" anything: the browser has no Join button and no
`join` bridge any more. Rápido and the prober take open nodes from the list
as they are. A node admitted by hand keeps its lease: its operator knows who
asked for it.

**Tests:** B (two one-hop connections, two keys), and B again (the entry was
shown a different key on each two-hop connection).

### 12. Medium — admission was counted per address, which fresh keys break (second round)

One admission per connection, counted at three per address per ten minutes,
would stop anyone reconnecting a fourth time. For an exit, every client of an
entry shares the entry's address, so they would all be stopped together.

**Fixed.** A session admission carries a proof of work instead
(`hidravpn-core/src/admission.rs:75`). It is a SHA-256 search bound to:

- the node's key;
- the key asked for;
- the current minute.

It costs about a second of one core at the default of 20 bits (a node's
`admission_work_bits`). Session admissions are not counted per address. They
have a node-wide ceiling of 600 per ten minutes
(`hidravpn-node/src/admission.rs:61`), and each key counts once against it
(finding 17). A key whose session never shakes hands is forgotten after two
minutes (`leases.rs:65`). A node that wants more work answers 428 with how
much, and the client works the proof out again for that, up to 26 bits; a
node asks for more as its ceiling fills (finding 17). Lasting leases (Join
on the command line, for root's `up` with an invite) keep the old count.

This makes filling a node cost computing for every lease, and the most for
the last places. It does not stop someone with many machines; the passes of
phase 5 do.

**Tests:**

- H: a session request with no proof is refused with the work wanted, and a
  false proof is refused;
- H: six connections in a row from one address all go through;
- unit tests for the proof and the ceiling.

### 13. Medium — a node not yet updated would have broken connections (second round)

An entry from before this change drops the admission request. An exit from
before it ignores `session`.

**Fixed.** A node's record lists what its software can do (`features`:
`sessions`, and for entries `admission-relay`; `directory.rs:90`,
`hidravpn-node/src/config.rs:264`). The client uses an open node only if its
record lists `sessions`. It asks an exit through an entry only if the entry
lists `admission-relay`. Otherwise it passes the node over and says which
and why (`pocket.rs:334`, `:500`). The maintainers publish the list again
from the updated nodes' `hidravpn-node record`.

**Test:** H: a list whose entry record lacks `sessions` makes the client
refuse with that reason, and 0 TCP packets leave for that node.

### 14. Medium — an active session's lease was judged by its handshakes (second round)

The node counted a lease as alive only from its last WireGuard handshake,
which happens every two minutes. With a short window, an active session was
forgotten while in use.

**Fixed:** any packet received under the key counts (`leases.rs:241`).

**Test:** D, where the entry and exit keep the session across a dead exit,
with windows shorter than the rekey interval. Unit test
`traffic_between_handshakes_keeps_a_session_alive`.

### 15. Windows (second round)

The admission requests during a hold, the outer tunnel restricted to the
exit, and the route to the exit's admission port through the entry are now
written for Windows too:

- WFP filters for one destination through one interface, and for an
  admission port off-tunnel (`killswitch/windows.rs:401`, `:424`);
- `route_host_via` (`netcfg/windows.rs:78`).

They compile, and `clippy -D warnings` passes for the Windows target.

**Run by hand on one Windows PC**, against one updated exit node, one hop
only:
- connect through the service;
- the internet saw the node's address;
- the node held a different session key for each connection (read from
  its own lease file);
- a new identity, `down` and `status` all go through the service.

The person running it reported these three as passing, without sending
the output:
- DNS through the tunnel, IPv6 blocked;
- nothing out while the node was stopped;
- the machine's own address back after `down`.

That run found a bug, now fixed. The service reused each control-pipe
instance after a client. On Windows a reused instance no longer showed its
clients that the service (session 0) held it. So every client after the
first eight refused the service, and the command line then acted on the
network by itself, undoing the service's kill switch. Each instance is now
made afresh after a client, and a client that finds something other than
the service on the pipe stops with an error instead of going around it.

**Not run on Windows:** two hops (Privado), passes, the browser page. A CI
job runs the unit tests on Windows. It cannot arm a firewall on a hosted
runner: that would cut the runner off from GitHub.

### 16. Critical — passes would have shown the exit your address and its key again (merge with phases 5 and 6)

Phase 5 added nodes that admit with a pass, and phase 6 tops passes up
by themselves. They were written beside this audit, and merging them
brought finding 1 back for a pass node used as the exit of two hops: the
pass was redeemed straight from the client's address, and the exit then saw
the key it had just handed out carrying the two-hop traffic. It also kept a
node's key across a new identity when the node was part of the circuit in
use.

Fixed in the merge:

- Passes are spent in one place, `circuit::prepare`
  (`circuit.rs:663`), the same one that asks open nodes for a session key.
  The first hop redeems its pass directly: it sees the address anyway
  (`circuit.rs:772`). The exit of two hops redeems its pass *through the
  entry* (`admit_behind`, `circuit.rs:848`), so its redemption and its
  tunnel come from the entry's address.
- The exit of two hops never falls back to a key it saw before: with no pass
  left for it, the connection is refused and says so (`circuit.rs:822`). A
  first hop with no pass left may reuse its last key, with a note, since it
  sees the address anyway.
- A pick or a rotation prefers nodes it can build with: no pass exit without
  a pass (`passes.rs:69`, `daemon.rs:1259`).
- A new identity redeems the next pass even for the node it leaves and
  comes back to: the kill switch holds the machine to that node's own ports
  while it asks (`daemon.rs:845`).
- The service takes the pocket, the wallet and the circuit in one order
  everywhere (`daemon.rs:363`), so a top-up and a connection never wait on
  each other in a circle or spend one pass twice.
- Phase 6's stricter invite check (the resolver inside the tunnel) is kept;
  a node not yet admitted is checked for shape only until `prepare` has won
  its invite, which is then checked in full (`circuit.rs:174`).

Proved by `scripts/test-passes-netns.sh`, which now also builds two hops
with an open entry and a pass exit:

- the exit never exchanges a packet with the client's address, and the
  redemption reaches it from the entry's address;
- with no pass left for the exit, `connect` is refused and the exit hears
  nothing;
- a new identity through the same pass node shows it a fresh key.

The same checks fail on the code of phase 6 alone (see the report).

### 17. High — four faults a review of findings 11 to 16 found (third round)

A review of this branch, line by line, found four faults. Each is fixed and
has a test that fails on the code before the fix.

1. **One proof of work could shut a node to new sessions.** The node
   checked the proof, then counted the request against its ceiling of 600,
   without asking whether that key had been counted already. A proof holds
   for a few minutes, so one proof sent 600 times filled the window, and
   every person then got 429 for ten minutes. Now a key counts once: a
   repeat gets the lease it already has and takes no room
   (`hidravpn-node/src/admission.rs`, `allow_session`). And filling the
   window with new keys costs more as it fills: two more bits of work (four
   times the work) at half full, at three quarters and at seven eighths, up
   to the 26 bits a client agrees to (`session_bits`). Filling the last
   eighth then costs about a minute of one core per place.
   Test H sends one proof 650 times: every answer is the same lease, and six
   connections in a row still go through. Unit tests count the window.
2. **Disconnect waited for a connection being made.** Asking a node for
   admission (the proof of work, the request, the request through the
   entry) ran under the service's state lock, so `status`, `down` and the
   browser's polling waited for it, up to the HTTP timeouts, and a person
   could not stop a connection to a node that did not answer. Now a
   connection being built can be stopped: `down` sets a switch the waiting
   watches (`circuit::Cancel`), what was set up is taken down as on any
   failure, and the machine is open again. `status` answers at once while a
   circuit is built: the hops it will have, not connected
   (`daemon.rs`, `status`). Only the account building it, or root, can stop
   it. Test I stops an exit's process mid-admission: `status` answers in
   milliseconds, `down` in well under a second, nothing is left behind, and
   the next connection works.
3. **Passes were lost when a two-hop circuit failed.** With an entry that
   takes passes, the entry's pass was redeemed first; if the exit then
   failed, the invite the pass won was dropped, so every retry spent another
   pass. And a failure while opening the tunnel to the entry dropped the
   exit's pass. Now what the exit needs (a pass left for it, software that
   takes sessions, an entry that can ask it) is checked before anything is
   asked of the entry; an invite a pass won is kept in the pocket as soon as
   it is won, whatever happens next, and the next try uses it; and the
   exit's pass goes back into the wallet on any failure before it was sent
   (`circuit.rs`, `prepare`, `admit_behind`). `test-passes-netns.sh` adds an
   entry that takes passes: with no pass for the exit, nothing is spent;
   with the exit not answering, one entry pass is spent once, retries spend
   none, and the exit's pass stays.
4. **An exit on another admission port could not be reached behind an
   entry.** An entry relays admission requests only to TCP 51821 (relaying
   any port would make it carry anything, not only WireGuard and this
   request), but a client would still pick an exit whose operator chose
   another port, do the proof of work, and time out. Now a client never
   picks such an exit behind an entry and says why; it is still used as the
   only hop (`pocket::entry_can_reach`), and its node warns its operator at
   start. Test H: such an exit is refused for two hops with the reason, and
   no packet leaves the client.

## Open

None of these is claimed as solved.

1. **Timing.** Two colluding operators can match times and volumes,
   including the moment the entry forwards an admission request and the exit
   admits a fresh key. Padding and delays are not attempted.
2. **Admission is paid in work, not identity**, on nodes that admit openly.
   Someone with many machines can still fill such a node for a while.
   Nodes that admit with a pass (phase 5) are the answer; an operator
   chooses which a node is.
3. **IPv6 has not run on this machine.** Its kernel boots with IPv6
   disabled (`ipv6.disable=1`), so the three IPv6 checks print SKIP here.
   The CI job `netns` (`.github/workflows/hidravpn-build.yml`) runs every
   suite twice on a runner with IPv6, with `HIDRAVPN_REQUIRE_IPV6=1`, so
   the IPv6 checks must pass there, not be skipped. It runs on the first
   push.
4. **Windows at run time**: only one hop, by hand, as said in 15.
5. **Nodes admitted by hand** keep a stable key. Their operator knows who
   asked; use them as entries.
6. **The exit's resolver sees every name.** That is inherent: the exit sees
   the traffic.
7. **The new tab page polls the local service every five seconds**, even
   when hidden. This stays on the machine.

## Verify it yourself

On Linux, as root, with the release binaries built and `tcpdump` installed:

```
sudo bash hidravpn/scripts/test-anonymity-netns.sh
```

Seven namespaces: a client, its own network (a router with no NAT, so any
direct contact shows the client's real address), an entry, two exits
(one run by the entry's operator) and the internet. Captures run on the
client's link and on the exit. The exit's own peer table is read every half
second, as its operator could read it.

It proves, in 46 checks (plus 3 IPv6 checks, which SKIP on a kernel without
IPv6 unless `HIDRAVPN_REQUIRE_IPV6=1` makes them required):

- **A.** Two hops from a pocket that only knew the nodes:
  - the client sends 0 packets to an exit, and the exit receives 0 from the
    client's address;
  - everything the client sends goes to the entry;
  - the exit's peer table shows the session from the entry;
  - DNS goes through both hops;
  - the entry forwards only WireGuard and the admission request, and its
    resolver is never asked;
  - a socket bound to the outer tunnel reaches nothing.
- **B.** One hop twice, then two hops, through the same exit:
  - a different key every time;
  - no key the exit saw from the client's address ever appears from
    elsewhere;
  - the entry is shown a different key on each two-hop connection.
- **C.** A new identity never moves to the exit the entry's operator runs,
  and says why. A new identity shows even the same exit a new key. Two hops
  under one operator are refused without the person's yes and allowed with
  it.
- **D.** A new identity, a reconnect and an exit killed for six seconds:
  - 0 IPv4 packets and 0 DNS packets leave the client outside the tunnel;
  - the kill switch stays armed;
  - the session resumes when the exit returns.
- **E.** After the session, the exit holds none of the keys two hops showed
  it.
- **G.** The command line without the service does the same: it asks the
  exit through the entry, the exit sees a new key from the entry, it sends 0
  packets to an exit, and SIGTERM restores everything.
- **H.** A session admission without a proof of work, or with a false one,
  is refused with the work wanted. One proof sent 650 times gets the same
  lease every time and takes no room. Six connections in a row from one
  address all go through. An entry whose record predates per-connection keys
  is not used, the person is told why, and nothing is sent to it; nor is an
  exit on an admission port entries do not relay.
- **I.** While an exit does not answer, `status` answers at once and `down`
  stops the connection being made; nothing is left behind.
- **F.** At DEBUG, failures included, no log names the client's address, its
  tunnel addresses, a key it presented or the canary.

The passes, two hops with a pass exit included (finding 16):

```
sudo bash hidravpn/scripts/test-passes-netns.sh
```

The design note for the passes of phase 5 is in `phase-5-anonymity.md`.
