# HidraVPN

The decentralised VPN of the HidraNet network: nodes run by the community,
no accounts, paid in $HNET, protecting the whole machine.

Developed in phases; each phase is a working, testable step. See
`docs/phase-1.md` (the tunnel), `docs/phase-2.md` (the service and the kill
switch) and `docs/phase-3.md` (two hops, two modes, a new identity) for what
exists now and how to run it.

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
sudo hidravpn up --privado                      # two hops, picked at random from the pocket
sudo hidravpn new-identity                      # rebuild through another exit: a new address
hidravpn status                                 # mode and what it hides, hops, handshakes, kill switch
sudo hidravpn down                              # disconnect and restore the network
sudo hidravpn-service uninstall                 # remove everything
```

Each `.json` is the invite a node printed when it admitted this machine's
key for that node; an entry and an exit are just two nodes. `hidravpn up`/`down`/`status`
use the service when it is installed; with `--direct` they make the change in
the current process instead (no service). Two hops give strong privacy, not
anonymity: `docs/phase-3.md` says exactly what each node can and cannot see.
