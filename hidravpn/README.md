# HidraVPN

The decentralised VPN of the HidraNet network: nodes run by the community,
no accounts, paid in $HNET, protecting the whole machine.

Developed in phases; each phase is a working, testable step. See
`docs/phase-1.md` (the tunnel), `docs/phase-2.md` (the service and the kill
switch) and `docs/phase-3.md` (two hops, two modes, a new identity) for what
exists now and how to run it.

Everything in this folder is new and separate from the HidraNet browser,
mail, chat, forum and relay engine, which it does not change.

## Linux: install and use

```
sudo bash hidravpn/scripts/install-linux.sh
```

It builds the binaries if needed, installs them to `/usr/local/bin`, installs
and starts the background service, makes this machine's key, and prints the
public key to give the node's administrator. Then:

```
sudo hidravpn up exit.json                      # Rápido: one hop, fastest
sudo hidravpn up exit.json --via entry.json     # Privado: two hops — the entry sees who,
                                                #   the exit sees where, neither sees both
sudo hidravpn up exit.json --via entry.json --alternate other-exit.json
sudo hidravpn new-identity                      # rebuild through the next exit: a new address
hidravpn status                                 # mode, hops, nodes, kill switch
sudo hidravpn down                              # disconnect and restore the network
sudo hidravpn-service uninstall                 # remove everything
```

Each `.json` is the invite a node printed when it admitted this machine's
key; an entry and an exit are just two nodes. `hidravpn up`/`down`/`status`
use the service when it is installed; with `--direct` they make the change in
the current process instead (no service). Two hops give strong privacy, not
anonymity: `docs/phase-3.md` says exactly what each node can and cannot see.
