# HidraVPN

The decentralised VPN of the HidraNet network: nodes run by the community,
no accounts, paid in $HNET, protecting the whole machine.

Developed in phases; each phase is a working, testable step. See `docs/phase-1.md` and `docs/phase-2.md` for what exists now and how to run it.

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
sudo hidravpn up invite.json      # connect: routes everything, arms the kill switch
hidravpn status                   # connected? kill switch on?
sudo hidravpn down                # disconnect and restore the network
sudo hidravpn-service uninstall   # remove everything
```

`hidravpn up`/`down`/`status` use the service when it is installed; with
`--direct` they make the change in the current process instead (no service).
