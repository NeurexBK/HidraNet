# HidraVPN — Phase 6: passes that top themselves up

Phase 5 made every connection to a pass node spend a pass, and left fetching
them to the person: `hidravpn passes get`, or the browser's *Get 10 passes*.
A wallet that ran out stopped the next connection to that node. Now the
service keeps it filled.

## What is new

- **Automatic passes.** Every ten minutes, and up to five more at random so
  the issuer cannot set a clock by it, the service looks at the wallet. A
  pass node with fewer than `low` passes left (3) is topped up back to
  `count` (10), in one request for all such nodes, interleaved as
  `passes get` does. Only when automatic passes are on (the default once a
  token is kept), a token is kept, and **a one-hop circuit is up**: the
  request then goes through the tunnel. Disconnected, nothing is fetched,
  even when low — it would leave from this machine's own address. With two
  hops up nothing is fetched either, and passes asked for by hand are
  refused: the request would leave through the exit, and the exit and the
  issuer together could tie the two-hop session to the account
  (`anonymity.md`, finding 20).
- **`hidravpn passes auto [on|off] [--low N] [--count N]`** sets it, root
  only, in `/etc/hidravpn/refill.json`; with no argument it says how it is
  set, and so does `hidravpn passes list`. `low` must be below `count`, and
  `count` at most 100.
- The service logs that it topped up, never how many for which node, an
  address or the token. A top-up that fails (the issuer cannot be asked,
  the wallet cannot be written) rests automatic passes for an hour, so a
  quota is not spent again and again on passes that cannot be kept;
  switching them on again ends the rest. Whether the circuit is up is asked
  twice: before, and once more right before the request, after the locks
  are held, so a `down` meanwhile cannot send it out of this machine's own
  address. Passes under an expired issuer key are thrown away before
  counting what is left.
- A `refill.json` that is there but cannot be read is taken as **off**,
  never as the default: whoever wrote it may have switched spending off.
- `HIDRAVPN_REFILL_SECS` changes the ten minutes (the test uses 2).
- **The browser shows and switches it.** The VPN page's *Passes* card has a
  box, *Top passes up by themselves*, that shows what the service has and
  switches it; the service command is `refill` (`enabled`, `low`, `count`,
  each optional; with none, it only reads). Any account that may drive the
  service may switch it: as with getting passes, only the account's quota is
  at stake.

## Command lines

```
sudo hidravpn passes auto                    # how it is set
sudo hidravpn passes auto on --low 3 --count 10
sudo hidravpn passes auto off                # back to `passes get` by hand
```

## How to check it

```
hidravpn/scripts/test-refill-netns.sh        # 17 checks
hidravpn/scripts/test-browser-netns.sh       # the page's box, against the real service
cargo test --manifest-path hidravpn/Cargo.toml --workspace
```

`test-refill-netns.sh` puts the issuer on the "internet" side, behind the
node, and gives the client a side door to it used once, for its first two
passes, then shut. It proves: automatic passes are on by default and `passes
list` says so; `passes auto` keeps its settings root-only and refuses a low
that is not below the count; connected, a node left with one pass is topped
up to the count, by a request that could only have gone through the tunnel;
off, nothing is fetched; disconnected, nothing is fetched though the node is
low; connected again, it is topped up; and no log holds the token or the
client's address. Unit tests cover which nodes are topped up and by how many,
and that settings that do not make sense are the defaults.

## The first run on real hardware

On 15 October 2026 the network ran for the first time outside the test
namespaces: a node rented from Hetzner in Helsinki (Ubuntu 24.04, kernel
WireGuard, installed with `install-node-linux.sh`, open admission, role exit)
and a client on a Windows PC, the unsigned build of this branch with
`wintun.dll` 0.14.1 beside it, run by hand in an administrator PowerShell:

- `hidravpn nodes discover <node> --trust` read the node's record over its
  admission port, and `nodes join --all` was admitted openly;
- `hidravpn up --rapido --direct` brought the tunnel, the routes, the DNS and
  the kill switch up and reported `connected`;
- an address-echo site showed the node's address, not the PC's; a DNS leak
  test showed only the node's resolvers (Quad9, Cloudflare) in Finland; an
  IPv6 test showed no IPv6;
- after Ctrl+C the network was the PC's own again.

Then the service, the way a user runs it: `hidravpn-service install --client
hidravpn.exe` installed it and started it, and `hidravpn up --rapido` connected
through it (the command returns; the service holds the circuit), with the
node's address seen from outside again. Smart App Control, on, let the client
run and stopped the unsigned service; the test went on with it switched off,
which a user of the signed build will never be asked to do.

That round found a bug no test here could: on a machine where the data
folder (`C:\ProgramData\HidraVPN`) already had files — from an earlier
`--direct` run, and so on every update — the installer left those files with
no rights at all (`icacls` with inheritable grants and `/T` strips a file's
inherited rights and grants it nothing), and the service could not read the
pocket: "Access is denied". The installer now protects the folder alone and
resets what is inside to inherit from it; after the fix, on the same PC, the
pocket showed SYSTEM and Administrators (inherited) and the service connected.

The browser's VPN page on Windows, two hops, a new identity, passes and the
phase-4 Windows script had still not run on a real PC; that was the next
round. Two hops and a new identity have run on one PC since (`anonymity.md`,
finding 15). The VPN page and passes have been used there by hand, with no
recorded run, and the phase-4 Windows script has still not run.

## What is honest about this phase

- **Through the tunnel, the issuer sees the node instead of you.** It no
  longer sees this machine's address, but it sees the address of the
  one-hop node the circuit uses at that moment, so it learns which node an
  account was using then. The passes it signs still say nothing about where
  they are spent. Who would rather the issuer saw neither can turn automatic
  passes off and fetch by hand, at a moment of their own choosing.
- **Never through two hops.** There the request would leave through the
  exit that carries the session. The exit sees the flow to the issuer leave
  from the session's address, and the issuer gets the account's request from
  the exit's address at the same moment: not a timing guess but an exact
  join of the session to the account, for an exit whose operator runs the
  issuer or shares its logs with it. The maintainers run both, and the list
  does not name the issuer's operator, so automatic passes wait for one hop,
  and passes are fetched by hand before connecting in privado.
- **The timing still says something.** A top-up follows the use of passes,
  within ten to fifteen minutes; someone who watches both the issuer and a
  node can compare. Fetching more at a time (`--count`) makes it rarer.
- **A top-up names the nodes that ran low.** It asks only for those, so the
  issuer learns how many nodes ran low at once, and how many passes each
  needed; `passes get` asks for every pass node alike and says less.
- **It spends the account's quota by itself.** Up to `count` passes a node,
  for every pass node in the pocket, whenever one runs low.
- **The page switches it on or off only**; `low` and `count` are set from
  the command line.
