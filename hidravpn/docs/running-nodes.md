# Getting nodes: what to rent, what to run, what it costs

The short answer to "who hosts this, and why": at the start, you do. You rent
servers; you do not pay people. A node is a small Linux server with a public
address, installed in one command. Ten of them cost about what one streaming
subscription costs, and they are what lets a stranger connect at all.

## What a node needs

- A Linux server (Debian 12 or Ubuntu 24.04) with a **public IPv4 address**,
  1 vCPU, 1 GB of RAM, and a few GB of disk. Nothing more: the node carries
  packets, it does not store them.
- Two ports reachable from the internet: **UDP 51820** (the tunnel) and
  **TCP 51821** (admission and the node's record). The installer opens them in
  ufw or firewalld; a provider firewall (Hetzner Cloud, DigitalOcean) has to
  be opened by hand in its panel.
- `nft`, `systemd` and `/dev/net/tun`, which every normal VPS has and which the
  installer checks before touching anything.
- A kernel with WireGuard (every current one); the node falls back to its own
  userspace WireGuard otherwise.

IPv6 is optional. A node used as an exit whose server has an IPv6 address
and an IPv6 default route (Hetzner and most providers give one) carries its
clients' IPv6 too: each client gets an address of a private subnet
(`tunnel_cidr6`, `fd68:6964:7261:7670::/64` by default), and its IPv6 leaves
with the server's own IPv6 address, as its IPv4 leaves with the server's
IPv4 one. The node's log says `IPv6 for clients: yes` or `no`. Without IPv6
on the server, or with `ipv6 = "off"` in `node.toml`, clients get IPv4 only
and their IPv6 is blocked on their side while connected, which leaks
nothing. An entry never carries IPv6, and neither does a node on userspace
WireGuard. Clients reach every node over IPv4 in any case.

A home connection is not a node: no port forwarding, no carrier-grade NAT,
no changing address. That is by design (`docs/business/16`, §1).

## Where to rent, and what it costs

Any provider works; these are known to, and the prices are what they charged
in 2026 for the smallest instance with a public IPv4:

| Provider | Smallest instance | About | Regions worth using |
|---|---|---|---|
| Hetzner Cloud | CX22 | €4–5/month | Germany, Finland |
| netcup | VPS 200 | €3–4/month | Germany, Austria |
| OVHcloud | VPS Starter | €4/month | France, Germany, Canada |
| Contabo | VPS S | €5/month | Germany, UK, US |
| DigitalOcean | Basic 1 GB | $6/month | Netherlands, Germany, US, Singapore |
| Vultr | Cloud Compute 1 GB | $6/month | many |

Ten nodes in three or four countries: **€40–60 per month**. Pay with the
company card or your own; document 16 says the founders pay this personally
in Phase 0 so the company does not operate the network.

Pick exits with care: an exit's owner receives abuse complaints for what
clients do through it. Hosting Tor exits is established practice in the
Netherlands, Germany, Sweden and Finland; the providers above in those
countries are used to it. Entries are harmless anywhere.

## Setting one up (five minutes)

On the server, as root, with the repository cloned (or the `hidravpn-node`
binary copied in):

```
# an exit, admitting any client that asks
sudo bash hidravpn/scripts/install-node-linux.sh \
    --endpoint <this server's public ip>:51820 \
    --name hel-1 --role exit --operator "HidraNet maintainers" \
    --contact nodes@hidranet.org --open-admission

# an entry (forwards only WireGuard, and clients' admission requests, to other
# nodes; sees addresses, not traffic)
sudo bash hidravpn/scripts/install-node-linux.sh \
    --endpoint <ip>:51820 --name ams-1 --role entry \
    --operator "HidraNet maintainers" --open-admission
```

The installer checks the machine, builds or installs the binary, makes the
node's key, installs the hardened systemd unit, opens the two ports, waits for
the node to report ready, and prints the node's record. `--country NL` puts the
node's country in its record, and `--tunnel 10.80.0.0/16` gives it a tunnel
subnet of its own; give every node a different one, so a client never gets the
same address from its entry and its exit. **Back up
`/etc/hidravpn/node.toml`**: it is the node's identity.

Then, on the server: `hidravpn-node record > hel-1.json`, and send that file to
whoever makes the list. The record lists what the node's software can do
(`features`); clients rely on it.

## Open admission: what it means

With `--open-admission`, any client that knows the node (from the list) is
admitted when it asks. Clients ask for a **session**: a key made for one
connection, which the node forgets about ten minutes after the last packet
it received under it. A session request must carry a proof of work bound to
this node, that key and the current minute: about a second of one core at
the default of 20 bits (`admission_work_bits` in `/etc/hidravpn/node.toml`;
raise it if scripts fill the node). The node asks for more as it fills, four
times the work from half full, sixteen times from three quarters and
sixty-four times from seven eighths, counting both the sessions of the last
ten minutes and the leases it holds now, so the last places cost the most
however slowly they were taken. Sessions are not counted per address,
because an exit sees every client of an entry under the entry's address;
the node takes at most 600 every ten minutes. A lasting lease (`hidravpn
nodes join`) costs no work: it is counted the old way, at most three times
per address every ten minutes and 120 per node, and lasting leases hold at
most a quarter of `--max-clients` together, so the other places stay for
sessions. **An entry gives no lasting lease at all** (it answers `join` with
403): a client asks an entry only for a key for each connection, and a
lasting lease there would hold a place for weeks after one handshake.
Everything together stays under `--max-clients` (4000). A client that never
completes a handshake loses its lease within about fifteen minutes; one that
stops coming loses it after `--idle-days` (30; the node writes each client's
last handshake down, so a restart is not idleness), or, on an entry, ten
minutes after its last packet, as a session does. A manually admitted client
(`hidravpn-node admit`) is never expired. Both numbers are installer flags
too (`--max-clients`, `--idle-days`) and settings in
`/etc/hidravpn/node.toml`.

What that does not stop, said plainly: one handshake every few minutes
keeps a session, or a lasting lease, alive. Someone with enough processor
time can still fill an open node with sessions and hold it while they keep
them alive, and someone with hundreds of addresses can keep its admission
port busy. Nodes that admit with a pass are the answer to that.

The admission port accepts every connection and closes at once one it has
no room for: past 4096 open at once, or past 8 from one address. A
connection that sends nothing for two seconds, or not a whole request in
three, is closed. An exit sees every two-hop client of an entry under that
entry's address, so on an exit list the outside addresses of the entries in
the signed list in `node.toml`, and each gets a share of 1024 connections
instead of 8, then restart the node:

```
admission_relays = ["<entry 1's public ip>", "<entry 2's public ip>"]
```

Put that line above any `[[pass_keys]]` section of the file: below one, it
would belong to that section and be ignored. The node's log then says
`2 entry address(es) relay admission requests here`.

The entry in turn lets each of its clients hold at most 4 admission
requests open through it at once, so one client of an entry cannot use up
that share.

An entry forwards only to UDP 51820, the default tunnel port, and to TCP
51821, the default admission port, so a client can ask an exit for admission
through the entry: keep exits on those ports, or an entry cannot reach them.
It forwards those ports to any public address, not only to listed nodes:
the node has no list.

## What a client can reach through a node

Whatever the role, traffic from the tunnel reaches the node's outside
interface and nothing else of the host — not a private network interface,
not a service on the node itself other than its DNS forwarder — and no
client reaches another. Through the outside interface it reaches the open
internet only: the node drops what clients send to private, loopback,
link-local (`169.254.169.254`, where clouds serve instance metadata, among
them), shared (`100.64.0.0/10`), multicast, reserved and documentation
addresses, and to their IPv6 equivalents (unique local `fc00::/7`,
link-local `fe80::/10`, multicast `ff00::/8`, loopback, IPv4-mapped and the
NAT64 prefixes). So a client cannot reach the provider's network or the
metadata service behind the node's outside interface, even where they are
routed through it. And nothing from outside reaches a client unless the
client started it: the node forwards to the tunnel only the replies to
clients' own connections. The node's log says `private destinations:
blocked`.

`forward_private_destinations = true` in `node.toml` lifts the destination
filter. It is for a test network, or a private deployment whose "internet"
is a private range (the namespace suites in `scripts/` use it); never set it
on a public node. Even with the filter, keep secrets out of a server's
cloud-init user data, and where the provider offers it, let its metadata
service answer only requests that carry a token.

## Updating a node

Clients pass over an open node whose record does not list `sessions`, and
use an entry for an open exit only if its record lists `admission-relay`.
A node updated to this release says so in `hidravpn-node record`. After
updating the nodes, make and sign the list again from the new records:
until then, clients cannot use them. On an exit, list the entries in
`admission_relays` (above) when you update it.

Without it, the node still describes itself on TCP 51821 (`GET /`), but
admits only by the operator's hand: the way a friend runs a node for friends.

An exit with open admission is a public VPN exit. Complaints will come;
`docs/operators/abuse-response.md` is what to answer.

## Admission with a pass (phase 5)

Open admission lets anyone in. `--pass-admission` lets in a client that
redeems a **pass**: one connection's worth of admission on this node, signed
blind by the issuer the list names, which counts passes against an account
and its daily quota. The issuer never learns which node a pass is for; the
node never learns which account paid for it; every connection shows the node
a fresh key. A script with many addresses no longer fills a node: it needs
many accounts.

```
sudo bash hidravpn/scripts/install-node-linux.sh --endpoint <ip>:51820 --name ams-2 \
    --role exit --operator "HidraNet maintainers" --pass-admission
sudo hidravpn-node pass-key add pass-key.json     # the issuer's key, as the list carries it
sudo systemctl restart hidravpn-node
```

Add the next issuer key before the current one expires, and remove an old
one with `hidravpn-node pass-key remove ID`. `hidravpn/docs/phase-5.md` says
how the issuer is run and what a pass binds; `phase-7-payments.md` how the
issuer sells passes for HNET (`--pay-wallet`, `--pay-pack`), which changes
nothing on a node.

## Publishing the list

Once, offline, make the two keys and embed their public halves (the secret
halves never touch a server or the repository):

```
hidravpn-sign keygen --out release.key        # signs releases
hidravpn-sign keygen --out list.key           # signs node lists
hidravpn/scripts/embed-release-key.sh --release <public 1> --list <public 2>
```

Every time the set of nodes changes:

```
hidravpn/scripts/make-node-list.sh --key list.key --out nodes.json \
    --sequence 1 --expires 2027-01-15T00:00:00Z \
    --note "the maintainers' nodes" hel-1.json ams-1.json ...
```

`--sequence` goes up every time (clients refuse an older list); `--expires`
is when clients stop trusting it (90 days by default); `--removed <key>`
withdraws a node from every client that imports the list. Publish
`nodes.json` and `nodes.json.sig` where the browser looks (`VPN_LIST_URL` in
`hidra-browser/src/main/main.js`, `https://hidranet.org/vpn/nodes.json`), and
anywhere else you like.

## What a client does with it

In the browser: open HidraVPN, press **Get the maintainers' list**, press
**Connect**. The service checks the list's signature, writes the nodes down,
and connects, asking each open node it uses to admit a key made for that
connection. On the command line:

```
sudo hidravpn nodes import nodes.json     # checked against the list key built in
sudo hidravpn up --privado                # two hops, two nodes, a fresh key for each
```

A node that admits by hand shows up as known with its contact; the client
asks, gets an invite, adds it with `hidravpn nodes add`.

## Knowing it works

Every hour, a GitHub Actions run checks that every node in the published list
answers with its key, that the list and the release manifest on hidranet.org
are signed, that the pass issuer answers and sells passes, and that the list
and the pass keys are good for two more weeks. A problem opens an issue, and
the next passing check closes it: [`node-monitor.md`](node-monitor.md).

That check does not go through the tunnel. For that, on a small machine of
yours that is admitted on every node, hourly:

```
sudo hidravpn/scripts/probe-nodes.sh --out /var/www/status
```

It connects through each exit in turn, checks the address the internet sees,
and writes `status.json` and `status.md`. Publish the folder. That is the
uptime measurement document 16's Phase 0 asks for, and the first thing to
look at when someone says a node is down.

## What volunteers get, and when

An operator who is not one of us and wants to run an entry has a guide of
their own: [`operators/running-an-entry.md`](operators/running-an-entry.md).

Nothing financial, and the documents say so (`docs/business/16`, §6). What
they get: their name on their node and in the list, the same installer, the
same abuse template, and an honest statement of what running an exit means.
During the preview, independent operators are taken for **entries only**,
after the check in that guide and at most two nodes per operator; every exit is
still one you rented (`docs/business/16`, §4). Other volunteers come after the
maintainers' nodes have stayed up for months and the list has a name.
