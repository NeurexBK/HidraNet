# HidraVPN — Phase 3 plan: two hops, two modes, a new identity

**Done.** Everything below is implemented and proved by
`scripts/test-multihop-netns.sh`; `phase-3.md` is the page to read now. This
plan stays as the record of why things are built the way they are.

**Status when written.** The groundwork was in (`bf198e9`): the client's network plan can
route a host through a tunnel interface, the kill switch can allow a second
tunnel interface, and a node's run directory is configurable so two nodes can
share one test machine. The circuit itself, the service wiring, the end-to-end
test and the user docs are the remaining work. This page is the plan to finish
them, written so it can be picked up cold.

## What phase 3 adds

- **Privado** — two hops. The client talks to an *entry* node and, through
  that tunnel, to an *exit* node, which is the one that reaches the internet.
- **Rápido** — one hop, exactly as phases 1 and 2 (fastest).
- **New identity** — tear the circuit down and rebuild it with a different
  exit node from the ones the client holds invites for, so the address the
  internet sees changes. With only one exit available it reconnects and says
  so honestly; it never claims a new address it did not get.

What each node can and cannot see, in two hops:

| node  | sees                                        | does not see                              |
|-------|---------------------------------------------|-------------------------------------------|
| entry | the client's real address                   | where the traffic goes (encrypted inside) |
| exit  | the traffic and where it goes               | who sent it (it arrives from the entry)   |

Neither alone can tie *who* to *what*. Say "strong privacy", never
"anonymous".

## Design: nest, do not invent

Two ordinary WireGuard tunnels, one inside the other, joined by **routing**,
not by any new protocol:

- outer tunnel on `hvpn0` to the entry node, over the physical link;
- inner tunnel on `hvpn1` to the exit node — its UDP packets are routed into
  `hvpn0`, so the outer tunnel encrypts them a second time;
- the default route goes into `hvpn1`; DNS is the exit node's resolver;
- the kill switch allows both interfaces and keeps the **entry** endpoint as
  the only address reachable off-tunnel.

Consequences worth keeping in mind:

- **The nodes do not change.** The entry sees one more UDP flow it forwards
  through its NAT; the exit sees one more client, arriving from the entry's
  address. Any phase-1 node is an entry or an exit. To run two on one test
  machine: `HIDRAVPN_RUN_DIR` for the leases, and a different `interface` in
  the second node's `node.toml` so the two userspace control sockets differ.
- **Both hops use the client's one key** (it is admitted on both nodes). In
  phase 5 passes give every connection a fresh key.
- **Inner MTU** = min(exit's MTU, entry's MTU − 80), never below 1280. The 80
  covers WireGuard's 32 bytes plus the outer UDP/IP headers, with margin.
- Core pieces already there: `netcfg::Wanted::via_tunnel`,
  `RevertPlan::via_routes` (both OSes), `KillConfig::extra_interface` (nftables
  and WFP, fixed filter key), node `HIDRAVPN_RUN_DIR`.

## Bring-up order — the part that must be exact

1. Open `hvpn0` with the entry invite's address and MTU; start the outer
   tunnel to the entry (it needs no special route).
2. Open `hvpn1` with the exit invite's address and the inner MTU.
3. Apply the network plan **once**: entry endpoint via the physical gateway;
   exit endpoint via `hvpn0` (`via_tunnel`); `0.0.0.0/1` + `128.0.0.0/1` via
   `hvpn1`; DNS = the exit's resolver.
4. **Only now** open the inner tunnel's UDP socket to the exit, so its very
   first packet is routed into `hvpn0` (a connected UDP socket caches its
   route when it connects).
5. Arm the kill switch: interface `hvpn0`, extra interface `hvpn1`, node
   endpoint = the **entry**, DNS = the exit's resolver.

One hop is the same list with no outer tunnel: open `hvpn0` for the exit,
plan, socket, kill switch. On any failure undo in reverse and refuse the
connection, as the daemon does today. Teardown: kill switch off, routes
back, stop the inner tunnel, then the outer, then drop the interfaces.

## Remaining work, in order

1. **`hidravpn-core/src/circuit.rs`** — `CircuitSpec { exit, entry: Option }`
   with `hops()`, `mode()`, `inner_mtu()`, `validate()` (entry and exit must
   be different nodes); `CircuitOptions { route_ipv6, allow_lan, kill_switch,
   interface_base }`; `Circuit::up(spec, key, opts)`, `status()` (per-hop
   handshake and bytes, `connected` only when every hop has a session),
   `down()`. `ClientKey` needs `Clone`. With `entry: None` it must behave
   exactly like today's single `Tunnel`, so the existing one-hop tests prove
   no regression.
2. **Service** — `Command::Up` gains `via: Option<Invite>` and
   `alternates: Vec<Invite>` (both `serde(default)`, so old requests still
   work); new `Command::NewIdentity`; `StatusReport` gains `hops`, `mode`,
   `entry_name`; `Response` gains an optional `note` for honest messages
   ("only one exit node is configured; reconnected to the same one"). The
   daemon keeps the spec and the pool to rebuild from.
3. **Command lines** — `hidravpn up exit.json [--via entry.json]
   [--alternate other.json]…`, `hidravpn new-identity`, a status line that
   shows the mode and the hops; the same on `hidravpn-service`; direct mode
   (`--direct`) uses the circuit too; `firewall on --extra-interface`.
4. **`scripts/test-multihop-netns.sh`** — see below.
5. **`docs/phase-3.md`** in the style of phases 1 and 2, and the README.

## How to check it — what the test must prove

Namespaces `hv-client`, `hv-entry`, `hv-exit`, `hv-exit2`, `hv-inet`; the
entry's "internet" is the exit link; the inet host has no route back to a
private address (so it is reachable only through the exit's NAT). The daemon
runs in the client namespace, as `test-service-netns.sh` does.

- The internet host sees the **exit's** address, not the entry's.
- The entry **never carried plaintext**: an observation table in the entry
  namespace (`nft`) counts `tcp dport 80` on its forward chain → must be 0,
  while `udp dport 51820` to the exit endpoint is > 0.
- DNS resolves, and the resolver saw the query come from the **exit**.
- 2 MB transferred intact over both hops (inner MTU is right).
- The kill switch is armed; a leak path is blocked; only the entry endpoint
  is reachable off-tunnel.
- `status` shows mode `privado`, hops `2`, the entry's and the exit's names.
- `new-identity` with `hv-exit2` as an alternate: the address the internet
  sees **changes**; with no alternate it reconnects and the note says so.
- `down`: both interfaces gone, routes and `resolv.conf` restored, no plan
  left behind, the client back on its own network.
- Then every existing suite still passes: unit tests, `test-netns.sh`
  (one hop), `test-killswitch.sh`, `test-service-netns.sh`.

## What stays honest

- Two hops cost latency and throughput; Rápido exists for that reason.
- A new identity changes the exit only if another exit is available; the
  client says which it got.
- Nothing logs an address, a name looked up or a byte of traffic — on
  either hop.
