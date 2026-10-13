# HidraVPN

The decentralised VPN of the HidraNet network: nodes a client is admitted to,
run by whoever runs them (today, the maintainers), no accounts, protecting the
whole machine. Who runs the first nodes, and what
operators are promised, is written down in the
[network bootstrap plan](../docs/business/16-network-bootstrap.md); nothing is
promised there that does not exist yet.

Developed in phases; each phase is a working, testable step. See
`docs/phase-1.md` (the tunnel), `docs/phase-2.md` (the service and the kill
switch), `docs/phase-3.md` (two hops, two modes, a new identity) and
`docs/phase-4.md` (the VPN in the browser, a signed node list, a node in one
command) for what exists now and how to run it.

Everything in this folder is new and separate from the HidraNet browser,
mail, chat, forum and relay engine, which it does not change.

## What makes it different

Only what the code proves, and the test scripts check:

- **Nodes run by different people.** An entry and an exit are two ordinary
  nodes; you choose which, invite by invite, or from your own pocket of nodes.
- **A different identity for every node.** Each node is shown a key derived
  for it from your one master key; no two nodes see the same key, and none
  sees the master key. Two operators comparing their peer lists find nothing
  in common. What remains to two nodes that conspire is the timing and volume
  of your traffic — the residue of any two-hop design.
- **Two hops where no node sees both.** In Privado the entry sees your
  address but not where your traffic goes; the exit sees the traffic but gets
  it from the entry. The test watches the entry and counts zero plaintext
  packets leaving it.
- **Kill switch by default, and a leak test.** Nothing leaves outside the
  tunnel; if the circuit cannot be protected, it is refused. A test proves a
  request to the open network is blocked while connected.
- **Nothing recorded.** No node or service log names an address, a name
  looked up or a byte of traffic; the tests grep the logs for them.
- **The browser asks, the service decides.** The HidraNet Browser's VPN page
  drives the service without ever holding an invite or a key: the service
  picks the nodes from the pocket, and the page shows only what the service
  reports. Nothing on it is a fixed badge.
- **Nodes from a signed list.** A new client learns which nodes exist, and
  who runs them, from a list the maintainers sign; the signature is checked
  against a key built into the client before a byte of the list is read. A
  list nobody signed goes nowhere. A node that admits openly then admits
  this machine when it asks (the client asks by itself); one that admits by
  hand needs its operator, and the client says whom to ask.
- **Open code, reproducible builds.** Everything is in this folder, built and
  checked by CI from the committed source; Windows binaries come from that
  build and are signed before any release.

Strong privacy, not anonymity: `docs/phase-3.md` says exactly what each node
can and cannot see.

## Linux: install and use

```
sudo bash hidravpn/scripts/install-linux.sh
```

It builds the binaries if needed, installs them to `/usr/local/bin`, installs
and starts the background service and makes this machine's master key. Each
node is shown a different key derived from it: `hidravpn pubkey --node <the
node's public key>` prints the one to give that node's administrator. Then:

```
sudo hidravpn up exit.json                      # Rápido: one hop, fastest
sudo hidravpn up exit.json --via entry.json     # Privado: two hops — the entry sees who,
                                                #   the exit sees where, neither sees both
sudo hidravpn nodes add --entry entry.json      # the pocket: nodes to pick from
sudo hidravpn nodes add --exit exit.json        #   (nodes list / nodes remove NAME)
sudo hidravpn nodes import nodes.json           # the maintainers' signed list, checked before it is read
sudo hidravpn nodes join --all                  # ask every listed node that admits openly; now they are usable
sudo hidravpn up --privado                      # two hops, picked at random from the pocket (joins first if needed)
sudo hidravpn up --rapido --node <name>         # one hop through a named node
sudo hidravpn nodes discover <ip> --trust       # a node you know by other means, such as your own
sudo hidravpn new-identity                      # rebuild through another exit: a new address
hidravpn status                                 # mode and what it hides, hops, handshakes, kill switch
sudo hidravpn down                              # disconnect and restore the network
sudo hidravpn-service uninstall                 # remove everything
```

Each `.json` is the invite a node printed when it admitted this machine's
key for that node; an entry and an exit are just two nodes. The installer
puts the person who ran it in the `hidravpn` group, which is what lets the
browser (running as that person) drive the service; log out and in once.
To run a **node** on a server: `sudo bash hidravpn/scripts/install-node-linux.sh
--endpoint <public-ip>:51820 --name <name> --role exit --operator <who> --contact <how>
--open-admission` (`docs/running-nodes.md` says where to rent one and what it
costs; `docs/phase-4.md` says what open admission means). `hidravpn up`/`down`/`status`
use the service when it is installed; with `--direct` they make the change in
the current process instead (no service). Two hops give strong privacy, not
anonymity: `docs/phase-3.md` says exactly what each node can and cannot see.
