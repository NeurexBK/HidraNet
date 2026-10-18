# HidraVPN — Phase 1: a working single-hop tunnel

What exists after this phase: a node (`hidravpn-node`, Linux) and a client
(`hidravpn`, Linux and Windows). An admitted client routes its whole machine
through the node over WireGuard; DNS is answered by the node and leaves it
over DNS-over-HTTPS; disconnecting restores the machine's network.

Not in this phase (by design, see the plan): kill switch, the service and its
IPC, multi-hop, the browser tab, payments and passes. Admission is done by the
node's administrator with a command; passes replace that in phase 5.

## Layout

```
hidravpn/
  crates/hidravpn-tun     the TUN interface per OS (Linux tun, Windows wintun, macOS utun)
  crates/hidravpn-core    WireGuard data plane (boringtun), keys, invites, client routes and DNS
  crates/hidravpn-node    the node: WireGuard (kernel, or userspace when there is none),
                          NAT, DoH forwarder, admission, status
  crates/hidravpn         the client command line
  crates/hidravpn-sign    Ed25519 signing of release files (key stays offline)
  scripts/test-netns.sh   the whole path on one Linux machine, in three network namespaces
  scripts/windows/phase1-test.ps1   the whole path from a real Windows client to a real node
  scripts/build-windows-client.sh   cross-builds hidravpn.exe on the node, for scp
  scripts/hidravpn-node.service   systemd unit
```

The crates are prefixed `hidravpn-` because the repository already has a
`hidra-node` (the HidraNet relay engine), which the VPN must not collide with.

## Build

Rust stable (1.85 or later).

```
cd hidravpn
cargo build --release                                   # Linux: everything
cargo build --release --target x86_64-pc-windows-gnu \
  -p hidravpn -p hidravpn-sign                          # Windows client, from Linux (needs mingw-w64)
cargo test --workspace                                  # unit tests
sudo scripts/test-netns.sh                              # end-to-end on one machine (needs /dev/net/tun, nft, python3, curl)
```

## The node

On the server, as root:

```
hidravpn-node init --endpoint 203.0.113.10:51820 --name node-1
hidravpn-node run                     # or install the systemd unit below
hidravpn-node admit --name laptop --pubkey <the client's public key>   # prints the invite
hidravpn-node status
hidravpn-node revoke --pubkey <key>
```

`init` writes `/etc/hidravpn/node.toml` (the node's key, root-only). The node
uses the kernel's WireGuard when the kernel has it (Ubuntu does) and its own
userspace implementation otherwise. DNS inside the tunnel is the node's tunnel
address (`10.77.0.1`); it forwards over DNS-over-HTTPS to Quad9, then
Cloudflare, by default (`--dns` changes that). Clients cannot reach each
other through the node. Leases live in `/var/lib/hidravpn` and survive a
reboot (they were in RAM until phase 4, when a rebooted node throwing every
client out proved to be the wrong intent).

The firewall needs UDP 51820 open inbound; nothing else.

Install as a service:

```
install -m 0755 hidravpn-node /usr/local/bin/
install -m 0644 scripts/hidravpn-node.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now hidravpn-node
journalctl -u hidravpn-node -f
```

## The client

```
hidravpn keygen            # once; the master key
hidravpn pubkey --node <the node's public key>   # the key to give that node's administrator (phase 3)
sudo hidravpn up invite.json      # Linux
hidravpn up invite.json           # Windows: in a PowerShell opened "as Administrator"
```

Ctrl+C disconnects and restores routes and DNS. If the process was killed,
`hidravpn down` (as administrator) restores them from the plan it saved.

Windows needs `wintun.dll` beside `hidravpn.exe`. It is Microsoft-signed and
comes from https://www.wintun.net (the `amd64` file inside the zip); check its
Authenticode signature before using it (`Get-AuthenticodeSignature`: Valid,
signed by WireGuard LLC). Without a code signature of our own yet, SmartScreen
may warn when the exe is first run.

The whole Windows check runs from one script, in a PowerShell opened "as
Administrator" on the client machine:

    scripts/windows/phase1-test.ps1 -Server NODE [-Name NAME] [-Manual]

It puts the exe in `C:\HidraVPN` (a downloaded copy, found by its SHA-256,
or one built on the node by `scripts/build-windows-client.sh` over ssh and
fetched with scp), fetches and verifies `wintun.dll`, makes the key, admits
it on the node over ssh, connects, runs the checks below plus a 2 MB transfer
and an IPv6 leak check, disconnects with Ctrl+C (or waits for yours, with
`-Manual`), checks that the network is back as it was, and prints a report
that masks the machine's own address.

What the client changes while connected: a route to the node through the
original gateway; `0.0.0.0/1` and `128.0.0.0/1` into the tunnel (more specific
than the default route, which stays); `::/1` and `8000::/1` into the tunnel,
where IPv6 is dropped in this phase (no IPv6 beside the tunnel is better than
IPv6 around it; `--keep-ipv6` disables this for diagnosis only); and DNS.

## How to check it is working

On the client, connected:

```
curl ifconfig.me            # the node's public address
nslookup example.com        # answered by 10.77.0.1
```

On https://ipleak.net the address and the DNS servers shown must be the
node's. (Windows: until phase 2, a second adapter's DNS can still be asked by
the system; that is what the kill switch and WFP rules fix.)

## Release files

`hidravpn-sign` signs release files with Ed25519. The signing key is made on
an offline machine (`hidravpn-sign keygen`) and never enters the repository
or a build machine; `hidravpn-sign verify --pubkey ... FILE` checks a
download against `FILE.sig`. The public key goes into the browser in phase 4.

## What is honest about this phase

- The data plane is boringtun's WireGuard implementation; the protocol is not ours.
- Phase 1 admission is a static key per client. With passes, every connection will use a fresh key.
- The client's Windows network setup goes through the NetTCPIP and DnsClient PowerShell cmdlets, in the active store only (nothing survives a reboot); phase 2 moves to the IP Helper and WFP APIs with the kill switch.
- Nothing logs an address, a name looked up or a packet.
