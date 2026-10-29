# HidraVPN

The decentralised VPN of the HidraNet network: nodes a client is admitted to,
run by whoever runs them (today, the maintainers), no accounts, protecting the
whole machine. Who runs the first nodes, and what
operators are promised, is written down in the
[network bootstrap plan](../docs/business/16-network-bootstrap.md); nothing is
promised there that does not exist yet.

Developed in phases; each phase is a working, testable step. See
`docs/phase-1.md` (the tunnel), `docs/phase-2.md` (the service and the kill
switch), `docs/phase-3.md` (two hops, two modes, a new identity),
`docs/phase-4.md` (the VPN in the browser — installed, updated and removed
from it, a leak test, the route by country — a signed node list, a node in one
command), `docs/phase-5.md` (passes: accountable admission that no one can
link to its use, a fresh key every connection), `docs/phase-6.md` (passes
that top themselves up) and `docs/phase-7-payments.md` (passes bought with
HNET) for what exists now and how to run it.

Everything in this folder is new and separate from the HidraNet browser,
mail, chat, forum and relay engine, which it does not change.

## What makes it different

Only what the code proves, and the test scripts check:

- **Nodes run by different people.** An entry and an exit are two ordinary
  nodes; you choose which, invite by invite, or from your own pocket of nodes.
- **A different identity for every node, and for every connection at the
  exit.** A node reached from your address is shown a key derived for it
  from your one master key; no two nodes see the same key, and none sees the
  master key. Every node that admits openly — entry, exit, or the node of one
  hop — is shown a fresh key on every connection, and forgets it minutes
  after you leave; the exit of two hops is asked for it through the entry,
  so it never hears from your address and never sees a key it could tie to
  it.
  What remains to two nodes that conspire is the timing and volume of your
  traffic — the residue of any two-hop design. `docs/anonymity.md` says who
  can see what, and the test that proves each line.
- **Two hops where no node sees both.** In Privado the entry sees your
  address but not where your traffic goes; the exit sees the traffic but gets
  it from the entry. The test watches the entry and counts zero plaintext
  packets leaving it.
- **Kill switch by default, and a leak test.** Nothing leaves outside the
  tunnel; if the circuit cannot be protected, it is refused. It holds across
  a new identity or a reconnect too: the machine is never on the open network
  between two circuits. A test proves a request to the open network is
  blocked while connected, another that a connection opened before the VPN
  is cut off, and another that nothing gets out while a circuit is rebuilt.
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
- **Admission nobody can link to its use.** A node can admit with a pass
  instead: signed blind by an issuer that counts passes against an account,
  so who may use the network is decided, while the issuer never learns which
  node a pass is for and the node never learns whose it was. Every
  connection redeems a new pass with a new key while one is left (a node of
  one hop with none left gets the last pass's key again, with a note). The
  test redeems one pass twice and sees it refused.
- **Open code, built in CI.** Everything is in this folder, built and tested
  by CI from the committed source. No release has come from that build yet:
  the one release, the 0.1.0 preview, was built and published by hand,
  without Authenticode (`docs/code-signing.md`). Its files are listed with
  their SHA-256 in the release manifest (`landing/vpn/release/manifest.json`
  in this repository), signed with the release key. Releases cut by the workflow (`hidravpn-build.yml`) start once
  signing is on. The builds are not reproducible yet: rebuilding a release
  from its source does not promise the same bytes.

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
sudo hidravpn nodes join --all                  # ask every listed node that admits openly or takes passes for a lasting lease,
                                                #   but the entries that admit openly: they give none, and are named as skipped
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
