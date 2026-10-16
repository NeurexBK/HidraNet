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
the node to report ready, and prints the node's record. **Back up
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
raise it if scripts fill the node). Sessions are not counted per address,
because an exit sees every client of an entry under the entry's address;
the node takes at most 600 every ten minutes. A lasting lease (`hidravpn
nodes join`) is still counted the old way, at most three times per address
every ten minutes and 120 per node. Everything together stays under
`--max-clients` (4000). A client that never completes a
handshake loses its lease within about fifteen minutes, so a script that
only asks cannot keep a node full; one that stops coming loses it after
`--idle-days` (30; the node writes each client's last handshake down, so a
restart is not idleness). A manually admitted client (`hidravpn-node admit`) is never
expired. Both numbers are installer flags too (`--max-clients`,
`--idle-days`) and settings in `/etc/hidravpn/node.toml`.

An entry forwards only to UDP 51820, the default tunnel port, and to TCP
51821, the default admission port, so a client can ask an exit for admission
through the entry: keep exits on those ports, or an entry cannot reach them.
It forwards those ports to any address, not only to listed nodes: the node
has no list.

## Updating a node

Clients pass over an open node whose record does not list `sessions`, and
use an entry for an open exit only if its record lists `admission-relay`.
A node updated to this release says so in `hidravpn-node record`. After
updating the nodes, make and sign the list again from the new records:
until then, clients cannot use them. Whatever the role,
traffic from the tunnel reaches the node's outside interface and nothing
else of the host — not a private network interface, not a service on the
node itself other than its DNS forwarder.

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
how the issuer is run and what a pass binds.

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

On a small machine of yours that is admitted on every node, hourly:

```
sudo hidravpn/scripts/probe-nodes.sh --out /var/www/status
```

It connects through each exit in turn, checks the address the internet sees,
and writes `status.json` and `status.md`. Publish the folder. That is the
uptime measurement document 16's Phase 0 asks for, and the first thing to
look at when someone says a node is down.

## What volunteers get, and when

Nothing financial, and the documents say so (`docs/business/16`, §6). What
they get: their name on their node and in the list, the same installer, the
same abuse template, and an honest statement of what running an exit means.
Volunteers come after the maintainers' nodes have stayed up for months and
the list has a name. Until then, every node is one you rented.
