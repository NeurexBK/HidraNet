# HidraVPN — Phase 3: two hops, two modes, a new identity

Phases 1 and 2 made a one-hop VPN held by a background service, with a kill
switch. Phase 3 adds a second hop. In **Privado** the client talks to an
*entry* node and, through that tunnel, to an *exit* node, which is the one
that reaches the internet. The entry sees the client's real address but not
where the traffic goes; the exit sees the traffic but gets it from the entry's
address. Neither alone can tie *who* to *what*. **Rápido** is the one hop of
before, for when speed matters more. And **new identity** rebuilds the circuit
through another exit node, so the address the internet sees changes.

Everything is still in `hidravpn/`, and nothing outside the VPN is touched.

## What is new

```
crates/hidravpn-core/src/circuit.rs   one hop or two: the spec, the bring-up order, the teardown
crates/hidravpn-core/src/keys.rs      one master key; a different key derived for each node
crates/hidravpn-core/src/pocket.rs    the pocket: entries and exits to pick from, at random
crates/hidravpn-service/src/daemon.rs  holds a circuit and the pools of entries and exits; new_identity
crates/hidravpn-service/src/ipc.rs     Up gains via + alternates; NewIdentity; status gains mode, hops, each hop's handshake
scripts/test-multihop-netns.sh         five namespaces, three nodes, the whole thing end to end
```

The nodes gain one command, `hidravpn-node pubkey`, and nothing else. Any
phase-1 node is an entry or an exit; which one it is depends only on how the
client uses it.

## A different key for every node

The client keeps one secret, `client.key`, exactly as before: 32 bytes, base64,
same file. But no node is ever shown its public half. For each node the client
derives a key of its own:

```
node_key = HKDF-SHA256(ikm  = the 32 bytes of the master key,
                       salt = "HidraVPN per-node key v1",
                       info = the 32 raw bytes of the node's WireGuard public key)
```

The 32 bytes out are an X25519 secret (clamped as the library does for any
key). The derivation is deterministic, so there is nothing new to store, and
the same node always gets the same key, so it is admitted once. Two nodes get
keys with nothing in common: an entry and an exit whose operators compared
their peer lists would find no key shared between them. The entry and the
exit of a circuit, and the one node of Rápido, are each shown their own key;
so is a node reached with `--direct`.

What the administrator admits is therefore the key *for that node*:

```
hidravpn-node pubkey                       # on the node: its public key, to share
hidravpn pubkey --node <that key>          # on the client: the key this node is shown
hidravpn pubkey --node-from-invite x.json  # the same, read from an invite of that node
hidravpn-node admit --name laptop --pubkey <what the client printed>
```

`hidravpn keygen` makes the master key if there is none and says this. A
client admitted before this change was admitted with its master key, which it
no longer presents: it needs admitting **once more**, with the per-node key,
on every node it uses. The key file itself does not change.

## The pocket

Instead of being handed one invite at a time, the client can keep the nodes
it holds invites for in a pocket, `/etc/hidravpn/circuit.json` on Linux and
`%ProgramData%\HidraVPN\circuit.json` on Windows:

```
hidravpn nodes add --entry entry.json      # an entry node
hidravpn nodes add --exit exit.json        # an exit node
hidravpn nodes list                        # names and endpoints, never keys
hidravpn nodes remove <name>
hidravpn up --privado                      # an entry and an exit from the pocket, at random
hidravpn up --rapido                       # an exit from the pocket, at random
```

The choice is uniform, from the operating system's randomness, among pairs
of two different nodes; a node that is in the pocket as both an entry and an
exit is never paired with itself. `up` hands the service the nodes it did not
pick, so that `new-identity` can rotate to them. `nodes` and `up` need
administrator rights.

## Two tunnels, one inside the other

Two ordinary WireGuard tunnels, nested by **routing**, not by a new protocol:

- the outer tunnel on `hvpn0` goes to the entry node over the physical link;
- the inner tunnel on `hvpn1` goes to the exit node, and its UDP packets are
  routed into `hvpn0`, so the outer tunnel encrypts them a second time;
- the default route goes into `hvpn1`; DNS is the exit node's resolver;
- the kill switch allows both interfaces and keeps the **entry's** endpoint
  as the only address reachable off-tunnel.

The entry node sees one more UDP flow it forwards through its NAT. The exit
sees one more client, arriving from the entry's address. The inner MTU is the
smaller of the exit's MTU and the entry's MTU minus 80 (WireGuard's 32 bytes
plus the outer UDP/IP headers, with margin), never below 1280.

The bring-up order is the part that must be exact, and `Circuit::up` is that
order and nothing else: the outer interface and tunnel; the inner interface;
the network plan, once (entry endpoint over the physical gateway, exit
endpoint through `hvpn0`, `0.0.0.0/1` and `128.0.0.0/1` into `hvpn1`, DNS at
the exit's resolver); **only then** the inner tunnel's socket, so its first
packet already goes into `hvpn0`; then the kill switch. On any failure it
undoes in reverse and refuses the connection. With no entry it is the single
tunnel of phases 1 and 2, step for step; the one-hop suites prove that.

One detail worth knowing: the outer interface carries a `/32`, not the prefix
in the entry's invite. The client needs nothing on the entry's subnet, and
with the wider prefix the entry's subnet would shadow the exit's resolver when
both nodes hand out the same default `10.77.0.0/16` — which, with two phase-1
nodes, they do.

## New identity

`hidravpn new-identity` takes the circuit down completely — the exit's
session, the routes, the kill switch — and builds it again through a
**different** exit, chosen at random among the others the service holds, and
through a different entry too when it holds more than one. The address the
internet sees changes because the exit did. With only one exit it reconnects
to the same one and **says so**; with only one entry it says the entry stays.
The reply carries the note, and the command prints it. It never claims a new
address it did not get.

## What `status` says

One line per connection, as before, then one honest line for the mode and one
per hop with the age of its last handshake:

```
connected: privado, 2 hops: entry entry-node then exit exit-node (10.202.0.1:51820); kill switch on; ...
  privado: no node sees both who you are and where you go; the entry sees your address, the exit sees your traffic
  entry entry-node (10.200.0.1:51820): last handshake 3s ago
  exit exit-node (10.202.0.1:51820): last handshake 2s ago
```

For one hop the line is: *rapido: the node sees your address and your
traffic; it hides them from your network, not from the node*. The word is
"strong privacy"; the word "anonymous" appears nowhere, and the test checks
that.

## Command lines

```
hidravpn up exit.json                                   # Rápido: one hop
hidravpn up exit.json --via entry.json                  # Privado: two hops
hidravpn up exit.json --via entry.json --alternate other-exit.json --alternate-entry other-entry.json
hidravpn up --privado | --rapido                        # the same, picked from the pocket
hidravpn new-identity                                   # another exit (and entry); needs the service
hidravpn status                                         # mode and what it hides, hops and handshakes, kill switch
hidravpn down
```

`hidravpn-service up|new-identity|status|down` take the same arguments
(except `--privado`/`--rapido`: the pocket is the client's). `--direct` holds
a two-hop circuit in the current process as it held one hop before; the
alternates are for the service's `new-identity` and do nothing there.
`hidravpn-service firewall on --extra-interface hvpn1` arms the kill switch
for two interfaces by hand, for diagnosis.

Requests from the phase-2 client still work: `via`, `alternates` and
`alternate_entries` are optional on the wire, and a status report without
the new fields still reads.

## How to check it

On Linux, as root, with the release binaries built:

```
hidravpn/scripts/test-multihop-netns.sh
```

Five namespaces: the client, the entry, two exits behind a bridge in the
entry's namespace, and an "internet" host that both exits reach but the entry
cannot. The internet host has no route back to a private address, so it is
reachable only through an exit's NAT, and it answers with the address it saw.
The daemon runs in the client namespace; the three nodes run on the one host
(`HIDRAVPN_RUN_DIR` and a different interface name each) and, on purpose, all
three hand the client the same tunnel subnet.

It proves, in 73 checks:

- the three nodes are shown three different keys, none of them the master
  key: the entry's and the exit's `peers.json` hold different client keys
  and neither holds the master key's public half;
- the internet host sees the **exit's** address, never the entry's;
- the entry **never forwarded plaintext**: an observation table in its
  namespace (counters only) sees 0 TCP packets, 0 HTTP and 0 DNS leave its
  tunnel, and hundreds of WireGuard packets to the exit;
- DNS resolves, and the resolver saw the query come from the exit;
- 2 MB arrive intact through both hops, so the inner MTU is right;
- the kill switch is armed, the entry's endpoint is the only address it
  allows off-tunnel, both interfaces are allowed, and a plain request to a
  host on the physical link is blocked;
- `status` says privado, 2 hops, and names both nodes;
- `status` explains the mode honestly and shows each hop's handshake age,
  and nowhere says "anonymous";
- `new-identity` with a second exit changes the address the internet sees,
  moves the via route, and keeps the kill switch armed throughout; with no
  alternate it reconnects and the note says so;
- the pocket: `nodes add` one entry and two exits, `nodes list` names them
  without a key, a duplicate is refused, `up --privado` picks from it, a
  `new-identity` moves to the other exit and the address the internet sees
  changes, `nodes remove` takes one out, `up --rapido` picks the one left;
- `down` removes both interfaces, every route, restores `resolv.conf`, leaves
  no plan behind, and the physical link works again;
- the same circuit held directly, without the service, connects and restores;
- no node or service log names a client address or a name looked up.

Then the existing suites still pass: unit tests, `test-netns.sh` (one hop,
24: it now also checks the per-node key), `test-killswitch.sh` (12) and
`test-service-netns.sh` (19).

## What is honest about this phase

- Two hops cost latency and throughput: every packet is encrypted twice and
  travels two legs. Rápido exists for that reason, and is the same one hop
  as before.
- Strong privacy, not anonymity. The entry still knows the client's address;
  the exit still sees the traffic. What two hops take away is the single
  place that knew both. Any party who watches both nodes at once is outside
  what this phase defends against.
- A new identity changes the exit only if another exit is available, and the
  command says which it got. It is a full rebuild, so the connection drops
  for a second while it happens.
- Each node is shown a different key, derived from the one secret the client
  keeps; the entry and the exit have no key in common to compare. What two
  nodes that conspired could still do is correlate times and volumes — the
  residue of any two-hop system, which this phase does not remove. Phase 5's
  passes give every connection a fresh key on top.
- A client admitted before per-node keys was admitted with its master key,
  which it no longer presents. It needs admitting once more, with
  `hidravpn pubkey --node ...`, on every node it uses.
- The pocket holds only nodes the person added, invite by invite; a
  directory of nodes to pick from is later work. `nodes list` prints names
  and endpoints, never keys.
- Nothing logs an address, a name looked up or a byte of traffic — on either
  hop.
