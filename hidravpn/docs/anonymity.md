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

## Who learns what

"Today" means after this change; the findings below say what was different.

| Party | Learns | Does not learn |
|---|---|---|
| **Your local network / ISP** | That you use WireGuard, to which entry address and port; when, and how much; DHCP as before. | Destinations, DNS names, anything inside the tunnel. IPv6: nothing (blocked). |
| **Entry node (two hops)** | Your address. A key made for this connection (`circuit.rs:570`), so across connections it has only your address to go by — and if you move between networks, not even that. Which exit you use (it forwards to it). When you connect, for how long, how much. One admission request to the exit per connection: plain HTTP inside your tunnel, so the entry can read it, and it carries only a fresh public key and the word "client". | Destinations, DNS names: its resolver is never asked and nothing but WireGuard to the exit leaves the outer tunnel (`killswitch/linux.rs:107-123`, test A). |
| **Exit node (two hops)** | Destinations, DNS names, and traffic content that is not encrypted end to end. The entry's address. A key made for this one connection (`circuit.rs:648`), and an inner address leased to it. | Your address (test A: zero packets from it). Any key it has seen from your address (test B). Whether two connections, or the connections before and after a new identity, are the same person, *by key* (tests B, C). |
| **Node used for one hop (Rápido)** | Your address and your traffic. That is what one hop is, and the page says so. A key made for this connection. | Your two-hop sessions through it, and your other one-hop sessions, by key (test B). |
| **One operator running entry and exit** | Everything: who and where. | — That is why such a pair is refused unless you say yes (`pocket.rs:376`, `daemon.rs:782`, test C). |
| **Two operators who compare notes** | No key in common (`keys.rs`). They can still match the entry's records ("this address sent this much at 10:02") against the exit's ("this key received this much at 10:02"). This includes the admission request the entry forwarded a moment before the exit admitted a fresh key. That is the timing residue of any two-hop design; see "Open". | Anything a key can link. |
| **A site you visit** | The exit's address. | Your address, unless you tell it (cookies, logins: that is the browser's job, and the browser's own tabs go through Tor regardless). |
| **hidranet.org (list and release server)** | That a Tor exit fetched the node list or a release file, when you press the button. The request carries no cookies and a generic user agent, and is refused while Tor is not ready (`main.js:52-92`). | Your address (Tor). Not verified at run time: whether Electron's `net.fetch` honours the overridden user agent (a lint test checks the code, not the wire). |
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
with a fresh key: `circuit::admit_behind` (`hidravpn-core/src/circuit.rs:550`).
While it runs, the kill switch allows only the encrypted packets to the entry
and, inside the outer tunnel, one TCP connection to the exit's admission port
(`killswitch/linux.rs`, `bridge_ruleset`). It sends no DNS and adds no
default route into the entry. An entry forwards TCP 51821 for this, and still
nothing else (`hidravpn-node/src/nat.rs:42`). For two hops the client asks
only entries from its own address (`daemon.rs:307`, `hidravpn/src/main.rs`).

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
  exit (`circuit.rs:570`).
- The exit keeps such a "session" lease only until ten minutes after the
  last packet it received under that key (`hidravpn-node/src/leases.rs:54`,
  `:166`).

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

**Fixed (Linux).** With two hops the outer interface carries only UDP to the
exit's endpoint (`killswitch/linux.rs:107-123`). **Not on Windows yet:** the
Windows rules still allow the whole outer interface
(`killswitch/windows.rs`, `apply`).

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
over and why (`daemon.rs:829`). `status` still reports `same_operator`.

**Test:** C.

### 7. Medium — a dead exit left the tunnel dead

When the exit stopped, its ICMP error made the client's tunnel task end. The
service then panicked ("JoinHandle polled after completion",
`tunnel.rs:130`), and the tunnel never recovered. The kill switch held, so
nothing leaked, but the person stayed offline until they reconnected.

**Fixed.** Transient socket errors are waited out (`tunnel.rs:219`), and a
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
cookies (`vpn-leaktest.js`, `main.js:109-135`).

**Tests:** `hidra-browser/test/vpn-leaktest.js` (9), `test/vpn-page.js` (54).

### 9. Low — the list and release fetches named the browser

`net.fetch` sent Electron's default user agent and could carry cookies. The
code itself says that whether it honours the Tor lock depends on the Electron
version.

**Fixed:** a generic user agent, `credentials: 'omit'`, and an explicit
refusal while the Tor lock is engaged (`main.js:52-92`).

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
- **The browser** sends the service six commands, never joins a node, and
  holds no key or invite. The VPN bridge exists only on our own pages (`preload-boundary`
  test). No VPN state reaches a website.

### 11. High — entries and one-hop nodes kept a stable key per person (second round)

The first round gave the exit a fresh key, but the entry and the node of one
hop still saw one stable key per person. They see the address anyway. Still,
a stable key let a node follow a person across networks: home in the
morning, a café at noon, the same key both times. Their leases also kept
every key's activity on disk for 30 days.

**Fixed.** Every node that admits openly is asked for a key for each
connection, the first hop directly (`circuit::prepare`, `circuit.rs:570`).
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
(`hidravpn-core/src/admission.rs:73`). It is a SHA-256 search bound to:

- the node's key;
- the key asked for;
- the current minute.

It costs about a second of one core at the default of 20 bits (a node's
`admission_work_bits`). Session admissions are not counted per address. They
have a node-wide ceiling of 600 per ten minutes
(`hidravpn-node/src/admission.rs:55`). A key whose session never shakes hands is forgotten after
two minutes (`leases.rs:58`). A node that wants more work answers 428 with
how much, and the client does it once, up to 26 bits. Lasting leases (Join
on the command line, for root's `up` with an invite) keep the old count.

This makes filling a node cost computing for every lease. It does not stop
someone with many machines; the passes of phase 5 do.

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
`hidravpn-node/src/config.rs:214`). The client uses an open node only if its
record lists `sessions`. It asks an exit through an entry only if the entry
lists `admission-relay`. Otherwise it passes the node over and says which
and why (`pocket.rs:302`, `:461`). The maintainers publish the list again
from the updated nodes' `hidravpn-node record`.

**Test:** H: a list whose entry record lacks `sessions` makes the client
refuse with that reason, and 0 TCP packets leave for that node.

### 14. Medium — an active session's lease was judged by its handshakes (second round)

The node counted a lease as alive only from its last WireGuard handshake,
which happens every two minutes. With a short window, an active session was
forgotten while in use.

**Fixed:** any packet received under the key counts (`leases.rs:166`).

**Test:** D, where the entry and exit keep the session across a dead exit,
with windows shorter than the rekey interval. Unit test
`traffic_between_handshakes_keeps_a_session_alive`.

### 15. Windows (second round)

The admission requests during a hold, the outer tunnel restricted to the
exit, and the route to the exit's admission port through the entry are now
written for Windows too:

- WFP filters for one destination through one interface, and for an
  admission port off-tunnel (`killswitch/windows.rs:399`, `:422`);
- `route_host_via` (`netcfg/windows.rs:79`).

They compile, and `clippy -D warnings` passes for the Windows target.

**Not run on Windows:** nothing of HidraVPN has run on Windows hardware yet.
A CI job runs the unit tests on Windows. It cannot arm a firewall on a hosted
runner: that would cut the runner off from GitHub. The run-time check is
`scripts/windows/phase4-test.ps1` on a real PC, still to do.

## Open

None of these is claimed as solved.

1. **Timing.** Two colluding operators can match times and volumes,
   including the moment the entry forwards an admission request and the exit
   admits a fresh key. Padding and delays are not attempted.
2. **Admission is paid in work, not identity.** Someone with many machines
   can still fill a node for a while. Phase 5's passes are the answer.
3. **IPv6 has not run on this machine.** Its kernel boots with IPv6
   disabled (`ipv6.disable=1`), so the three IPv6 checks print SKIP here.
   The CI job `netns` (`.github/workflows/hidravpn-build.yml`) runs every
   suite twice on a runner with IPv6, with `HIDRAVPN_REQUIRE_IPV6=1`, so
   the IPv6 checks must pass there, not be skipped. It runs on the first
   push.
4. **Windows at run time**, as said in 15.
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
  is refused with the work wanted. Six connections in a row from one
  address all go through. An entry whose record predates per-connection keys
  is not used, the person is told why, and nothing is sent to it.
- **F.** At DEBUG, failures included, no log names the client's address, its
  tunnel addresses, a key it presented or the canary.

The design note for the passes of phase 5 is in `phase-5-anonymity.md`.
