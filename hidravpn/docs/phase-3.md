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
crates/hidravpn-service/src/daemon.rs  holds a circuit and the pool of exits; new_identity
crates/hidravpn-service/src/ipc.rs     Up gains via + alternates; NewIdentity; status gains mode, hops, entry
scripts/test-multihop-netns.sh         five namespaces, three nodes, the whole thing end to end
```

The nodes do not change. Any phase-1 node is an entry or an exit; which one it
is depends only on how the client uses it.

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
session, the routes, the kill switch — and builds it again through the next
exit the service holds an invite for, through the same entry. The address the
internet sees changes because the exit did. With only one exit configured it
reconnects to the same one and **says so**: the reply carries a note, and the
command prints it. It never claims a new address it did not get.

## Command lines

```
hidravpn up exit.json                                   # Rápido: one hop
hidravpn up exit.json --via entry.json                  # Privado: two hops
hidravpn up exit.json --via entry.json --alternate other-exit.json   # ... with an exit to rotate to
hidravpn new-identity                                   # next exit; needs the service
hidravpn status                                         # mode, hops, nodes, kill switch
hidravpn down
```

`hidravpn-service up|new-identity|status|down` take the same arguments.
`--direct` holds a two-hop circuit in the current process as it held one hop
before; `--alternate` is for the service's `new-identity` and does nothing
there. `hidravpn-service firewall on --extra-interface hvpn1` arms the kill
switch for two interfaces by hand, for diagnosis.

Requests from the phase-2 client still work: `via` and `alternates` are
optional on the wire, and a status report without the new fields still reads.

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

It proves, in 50 checks:

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
- `new-identity` with a second exit changes the address the internet sees,
  moves the via route, and keeps the kill switch armed throughout; with no
  alternate it reconnects and the note says so;
- `down` removes both interfaces, every route, restores `resolv.conf`, leaves
  no plan behind, and the physical link works again;
- the same circuit held directly, without the service, connects and restores;
- no node or service log names a client address or a name looked up.

Then the existing suites still pass unchanged: unit tests, `test-netns.sh`
(one hop, 23), `test-killswitch.sh` (12) and `test-service-netns.sh` (19).

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
- Both hops use the client's one key, admitted on each node; the entry and
  the exit can see it is the same key. Phase 5's passes give every
  connection a fresh key.
- The second exit is still chosen by the person, invite by invite; a
  directory of nodes to pick from is later work.
- Nothing logs an address, a name looked up or a byte of traffic — on either
  hop.
