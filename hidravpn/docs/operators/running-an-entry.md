# Running a HidraVPN entry: a guide for operators who are not us

This page is for someone who is not a HidraNet maintainer and is willing to
run an **entry** node: the first hop of HidraVPN's two-hop mode. It says what
an entry sees, what it costs you, what we ask, what you get, and how to set
one up in about half an hour. The maintainers' own guide to renting and
installing nodes is [`../running-nodes.md`](../running-nodes.md); this page
leans on it and adds what an independent operator needs to know.

**Where HidraVPN stands:** a preview. The client, the nodes, the signed
release and the signed node list work end to end and are tested on Linux and
Windows, but HidraVPN has not been launched for the public. Your entry would
carry the maintainers' and early testers' traffic first. Taking entries from
operators who are not us during the preview is a decision the founders made on
purpose ([`docs/business/16-network-bootstrap.md`](../../../docs/business/16-network-bootstrap.md) §4);
exits stay the maintainers' own.

## Why an entry run by someone else matters

In two-hop mode (`privado`) a client goes through an **entry** and then an
**exit**:

- the **entry** sees the client's address, which exit it uses, and when, for
  how long and how much it connects. It sees nothing of where the traffic goes
  or what it says: that is a second WireGuard tunnel, encrypted to the exit;
- the **exit** sees the traffic, and not who sent it: it is reached from the
  entry's address.

No single node sees both ends. But if one operator runs both nodes, that
operator could put the two halves together. Today every node in the official
list is run by the maintainers, so a client has to tick "Allow two hops run by
one operator" to use two hops at all. An entry run by you, with the exit run by
us, is what makes "no one sees both" true of the **people**, not only of the
machines.

Without that box ticked, the client only builds two hops from an entry and an
exit run by two different operators, and says so when no such pair exists.
With it ticked, it picks among all pairs at random. So while there are only a
few independent entries, **every two-hop connection made without the box goes
through one of them**: your entry may carry most of the two-hop traffic, and
see most two-hop clients' addresses, for a while.

## What an entry does, and does not

- **From the tunnel it forwards only two ports:** UDP 51820 (WireGuard) and
  TCP 51821 (the one admission request a client makes to an exit, so that the
  exit is asked from the entry's address and never from the client's). The node
  has no list of nodes, so it forwards those two ports to **any** address, not
  only to nodes. It also answers its clients' DNS, resolving through Quad9 and
  Cloudflare over HTTPS. Everything else from the tunnel is dropped by the
  node's own firewall rules: web, mail and every other port never leave from an
  entry.
- **It admits clients openly**, with limits. A client normally asks for a key
  valid for one connection, and each such request carries about a second of
  proof of work; the node forgets that key ten minutes after the last packet.
  The node admits at most 600 new one-connection keys every ten minutes, and
  holds at most 4000 clients in all (`--max-clients`). A client may also ask for
  a lasting key (`hidravpn nodes join`): that takes no proof of work, is limited
  to three per address and 120 per node every ten minutes, and is forgotten
  after 30 days without use (`--idle-days`), or after about fifteen minutes if
  it is never used.
- **It keeps no traffic and writes down no address.** The node's log holds
  counts and states. The only client data on disk is
  `/var/lib/hidravpn/peers.json`: for each key admitted, its public key, its
  tunnel address, a label the client chose (the official client sends
  `client`), and when it was admitted and was last active. Nothing the node
  writes down says who a client is. While a client is connected, though, its
  address can be seen on the server by anyone with root, in the WireGuard
  device's peer list and in the kernel's connection table, as on any server. In
  two hops the entry is the one node that sees it.
- **It never carries IPv6** and does not need an IPv6 address.

**An entry draws far fewer complaints than an exit**: web, mail and every other
port leave from the exit's address. Only traffic to UDP 51820 or TCP 51821 of
another host can leave from yours. If you are asked to run an exit instead,
that is a different and heavier decision; read
[`abuse-response.md`](abuse-response.md) first and talk to us.

## What it costs you

- **A rented server:** Debian 12 or Ubuntu 24.04, a public IPv4 address, 1 vCPU
  and 1 GB of RAM. That is about €4 to €6 a month at Hetzner, netcup, OVHcloud,
  DigitalOcean or Vultr. The table in [`../running-nodes.md`](../running-nodes.md)
  has the providers and prices. A home connection does not work: there is no
  NAT traversal, and a home address that changes cannot be in a signed list.
- **Traffic:** an entry carries its clients' traffic once in and once out. The
  1 to 2 TB a month most small plans include is plenty while HidraVPN is in
  preview.
- **Your time:** about half an hour to set up, most of it waiting for the
  build, and a few minutes for each update.
- **Your provider's terms:** a few providers forbid running relays or VPN
  servers. Check yours before you start.

## What you get, said plainly

**No payment, in money or in HNET.** Operators are volunteers, and no page,
post or person from the project may tell you otherwise
([`docs/business/16-network-bootstrap.md`](../../../docs/business/16-network-bootstrap.md) §6
says why). What you get instead:

- **Your name in the network.** Your operator name is on your node and in the
  official signed list, which every client shows. The first independent
  operators are listed as **Founding Operators** on an operators page on
  hidranet.org, which goes up with them, and are thanked by name in the
  project's dev reports and posts.
- **HidraVPN for yourself.** While your node is in the official list, your own
  HidraVPN account gets **100 passes a month** from us: one pass is one
  connection through a node that takes passes, so about three a day.
- **Your node watched.** We check every node in the list every hour. When
  yours stops answering, we write to you at the address you gave us.
- **Stickers and a T-shirt**, once we have them, for operators whose node has
  stayed in the list for three months.
- **For a company:** your company named as a network partner on hidranet.org,
  beside its node.

That is all. Nothing else is promised, and nothing financial.

## What we ask of you

1. **Keep it up.** Short outages happen; tell us before a planned long one.
   While your entry is one of only a few, two-hop clients who have not ticked
   the box cannot connect while it is down.
2. **Update within a week** when we tell you a new node version is out. An old
   node can drop out of clients' choices.
3. **Do not change what the node keeps or forwards.** No packet capture, no
   logging of addresses, no extra firewall rules on the tunnel.
4. **Keep the node's key private.** `/etc/hidravpn/node.toml` holds it. If it
   leaks, tell us, and we will withdraw the node from the list.
5. **Tell us before you stop**, and follow "Stopping" below.
6. **Give us one way to reach you.** The address you write to us from is
   enough, and it stays between us.

What becomes **public**: the operator name you choose and your server's address
are in the record your node serves to anyone on TCP 51821, in the signed list,
and on every client's screen. Choose a name, handle or organisation you are
happy to publish.

## Who can run one

Anyone can offer. The maintainers decide who goes into the official list, for
one reason. Someone who runs many nodes under different names could, now and
then, be both the entry and the exit of the same connection, and see who a
client is and where they go: the very thing two hops are there to prevent.
This is called a Sybil attack, and every network of this kind has to guard
against it. So:

- **Every candidate is checked before their node goes into the list.** We talk
  to you by e-mail and ask who you are (a name or a known pseudonym, with
  something public we can look at: a website, a GitHub account, relays you
  already run elsewhere), where your server is and with which provider. We do
  not ask for an identity document.
- **At most two nodes per operator**, counting every name a person, company
  or group uses. If we find one operator behind nodes listed under different
  names, all of them leave the list.
- **We may say "not now"**, for instance when the list already has enough
  nodes with your provider or in your country; we spread the nodes out on
  purpose. We say why whenever we can.

Write to us **before you rent a server** (see "Talking to us" below), so that
you do not pay for one we cannot list yet.

## Setting it up

### 1. Prepare the server

Create the server with **SSH key login only** (most providers ask for your
public key when you create it). Then, as root on the server:

```
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
apt-get install -y git curl build-essential nftables
[ -f /var/run/reboot-required ] && reboot
```

If your provider puts a firewall in front of the server (Hetzner Cloud,
DigitalOcean and others have one in their panels), open **UDP 51820** and
**TCP 51821** there.

**Leave ufw and firewalld inactive on the server** (most cloud images ship
with them off), and use the provider's firewall if you want one: the node installs its
own rules for what may leave the tunnel. The installer opens the two ports in
ufw or firewalld when one of them is active, but an entry also needs traffic to
be **forwarded** from its tunnel, which those firewalls drop by default. If you
keep ufw, allow it as well:

```
ufw route allow in on hvpn0 out on <the server's outside interface, often eth0>
```

Make sure SSH refuses passwords:

```
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
    > /etc/ssh/sshd_config.d/00-keys-only.conf
sshd -t && (systemctl reload ssh || systemctl restart ssh)
```

Keep your SSH session open and check from another terminal that you can still
log in with your key before you close it.

### 2. Ask us for your node's settings

Once we have said yes and your server is ready, send us its public IPv4
address and the country it is in. We answer with:

- a **name** for the node, such as `porto-1`: up to 32 letters, digits, `-`,
  `_` or `.`, which clients show;
- a **tunnel subnet** of its own, such as `10.80.0.0/16`. Every node gets a
  different one, so a client never gets the same address from its entry and
  its exit. The default works, but costs Windows clients a second request.

### 3. Build and install

The node is built from source on the server, so you run exactly the code that
is public. The build takes about six minutes on one core and needs close to
1 GB of memory by itself, more than a 1 GB server has free. On such a server,
add swap **first**, and keep it across reboots for later updates (the node
itself, once built, needs far less):

```
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

Then get Rust and build:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
git clone --depth 1 https://github.com/NeurexBK/HidraNet.git
cd HidraNet
cargo build --release --locked --manifest-path hidravpn/Cargo.toml -p hidravpn-node
```

Then install it as an entry, with the values we gave you:

```
bash hidravpn/scripts/install-node-linux.sh \
    --endpoint <your server's public IPv4>:51820 \
    --name <the name we gave you> --role entry --open-admission \
    --operator "<a name, handle or organisation you are happy to publish, up to 64 characters>" \
    --country <two letters, e.g. PT> --tunnel <the subnet we gave you>
```

A public contact in the record is optional for an entry, which admits clients
openly. If you want one, add `--contact "<an address made for this, up to 128
characters>"`: clients show it to everyone, so never use a personal address.

The installer checks the machine before it changes anything, installs the
binary, creates the node's key, installs a hardened systemd unit, opens the two
ports, and waits for the node to say it is serving. At the end it prints the
node's public key and the command that prints its record, which you run in
steps 4 and 6. Run it with `--dry-run` first to see every step without changing
anything.

If `/etc/hidravpn/node.toml` is already there, the installer does not touch
it: every setting in the file stays as it is (name, endpoint, role, admission,
operator, contact, country and subnet), whatever options you pass. The summary
it prints at the end shows the options you passed, not what is in the file, and
`--dry-run` shows the init step even though a real run skips it. Check what the
node really uses with `hidravpn-node --config /etc/hidravpn/node.toml record`.
To change a setting, first move the old file somewhere safe (it holds the
node's key, and a new file means a new identity, which we have to put in the
list again), then run the installer again.

### 4. Check it

On the server:

```
systemctl is-active hidravpn-node
hidravpn-node --config /etc/hidravpn/node.toml record
```

From any other computer, the node's record must answer on its admission port:

```
curl -s http://<your server's public IPv4>:51821/
```

It prints the same record: your node's name, key, endpoint, operator, your
contact if you gave one, `"role":"entry"`, `"admission":"open"`, your country,
and `"features":["sessions","admission-relay"]`. If it times out, a firewall is
in the way, most often the provider's.

Reboot once (`reboot`) and check `systemctl is-active hidravpn-node` again: the
node must come back by itself.

### 5. Back up the key

Copy `/etc/hidravpn/node.toml` to your own computer and keep it private. It is
the node's identity: lose it and the node needs a new entry in the list; leak
it and someone can pretend to be your node.

```
scp root@<your server's public IPv4>:/etc/hidravpn/node.toml ./<node name>-node.toml
```

### 6. Send us the record

Send us the output of `hidravpn-node --config /etc/hidravpn/node.toml record`.
It holds nothing secret. We check that the node answers, add it to the next
official list, sign the list offline with the list key, and publish it at
`https://hidranet.org/vpn/nodes.json`. From then on, every client that presses
"Get the maintainers' list" knows your node, and two-hop connections made
without the same-operator box start using it as their entry.

## Running it

- **Updating:** when we announce a new node version, paste this as one block.
  It stops at the first step that fails, and the running node is only stopped
  once the new one has built:

  ```
  (set -e
   cd ~/HidraNet && git pull && . "$HOME/.cargo/env"
   cargo build --release --locked --manifest-path hidravpn/Cargo.toml -p hidravpn-node
   systemctl stop hidravpn-node
   install -m 0755 hidravpn/target/release/hidravpn-node /usr/local/bin/hidravpn-node
   systemctl start hidravpn-node
   systemctl is-active hidravpn-node) || echo "update stopped; the error is above"
  ```

  The node keeps its key and its admitted clients across updates and reboots,
  and clients connected through it reconnect by themselves after the restart.
- **Looking at it:** `systemctl status hidravpn-node` and
  `journalctl -u hidravpn-node -f`. The log holds counts and states, never an
  address or a name, by design.
- **Keeping the server safe:** let the system install its security updates
  by itself (`apt-get install -y unattended-upgrades`; Ubuntu has it on
  already), keep SSH on keys only, and run nothing else on the server.

## Stopping

Tell us first, and **leave the node running on the same address** until we
tell you that a list withdrawing it is out. Clients forget a node only when
they next fetch the list, and until then they keep sending admission requests,
from their own addresses, to its address; if the provider gives that address to
someone else, those requests reach the new holder. If you can, keep the server
and its address until the `expires` date of the last list your node was in.
Then, on the server:

```
systemctl disable --now hidravpn-node
rm /etc/systemd/system/hidravpn-node.service /usr/local/bin/hidravpn-node
rm -r /etc/hidravpn /var/lib/hidravpn
```

## Talking to us

Write to **contact@hidranet.pro** with the subject "New entry: <the country
you would run it in>". In the first message, say who you are (with something
public we can look at), the provider and country you have in mind, and the
operator name you would like clients to see. Never send the node's key, a
password, or anything from `node.toml`: later, the record and the server's
address are all we need, and both end up in the public list anyway. Questions
about the code itself are welcome as issues at
<https://github.com/NeurexBK/HidraNet/issues>.

## Questions operators ask

**Can I see who uses my node?** You can see which addresses connect, as any
server sees who connects to it. The node does not write them down, and we ask
you not to either. You cannot see where they go or what they do: that is
encrypted to the exit.

**Can I be asked who used my node?** Yes, rarely. In two hops the entry is the
hop that sees clients' addresses, so a lawful request may come to you. The
node keeps no addresses, only per-key admission and last-active times; do not
say you cannot see addresses at all. Reply as the law-enforcement row of
[`abuse-response.md`](abuse-response.md) says, and read
[`docs/business/10-legal-and-regulatory-risk.md`](../../../docs/business/10-legal-and-regulatory-risk.md)
and talk to a lawyer before anything else.

**Can someone use my entry to attack a site?** Only narrowly. An admitted
client can send UDP to port 51820, or TCP to port 51821, of any host from your
address, because the node does not check that the destination is a node.
Nothing else leaves: the node's own firewall rules drop the rest.

**Will this get me in trouble with my provider?** An entry looks like a small
WireGuard server, which providers see every day. Check your provider's terms
for "VPN", "proxy" or "relay" all the same; a few forbid them.

**Can I run it at home?** Not yet. It needs a public address and an open UDP
port. Entries that need no open port are a roadmap item
([`docs/business/16-network-bootstrap.md`](../../../docs/business/16-network-bootstrap.md) §7).

**Can I run an exit?** Perhaps, later. An exit receives the abuse complaints
for its clients' traffic. Read [`abuse-response.md`](abuse-response.md) and talk
to us first. We do not list an exit whose operator has not read it.
