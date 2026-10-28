# HidraVPN — Phase 2: the service, the kill switch and leak protection

Phase 1 made a working tunnel you ran from a terminal window. Phase 2 turns it
into a background service you install once, and adds the kill switch: while the
tunnel is up, nothing leaves the machine except the encrypted packets to the
node and the traffic inside the tunnel, so a dropped tunnel never falls back to
the open internet. IPv6 is blocked and DNS is pinned to the node's resolver.

Everything is still in `hidravpn/`, and nothing outside the VPN is touched. The
browser does not know about any of this yet; that is phase 4.

## What is new

```
crates/hidravpn-core/src/killswitch/   the kill switch, one file per OS
  linux.rs     an nftables table of our own (inet hidravpn_ks)
  windows.rs   the Windows Filtering Platform, as the WireGuard client uses it
  (macOS)      not built yet; connecting refuses rather than go unprotected
crates/hidravpn-service/   the background service
  daemon.rs    holds the tunnel, arms the kill switch, puts the network back
  ipc.rs       the local control channel: a request and a reply, one line each
  install/     the OS service (systemd unit / Windows service)
scripts/test-killswitch.sh       the leak test, in two network namespaces
scripts/test-service-netns.sh    the whole service, end to end, with a real node
scripts/windows/phase2-test.ps1  the same checks from a real Windows machine
```

## The kill switch

While it is on, the only packets allowed out are: loopback; everything on the
tunnel interface; the WireGuard packets to the node's endpoint; and DHCP, so the
physical link keeps its address. Everything else is dropped. Because the block
is a firewall rule, not a route, it holds even if the tunnel interface or its
routes disappear — which is exactly when a leak would otherwise happen.

- **Linux**: one nftables table, `inet hidravpn_ks`, with a default-drop policy
  on output, input and forward. The `inet` family covers IPv4 and IPv6 together,
  so IPv6 is blocked the moment the table exists. DNS to any address but the
  node's resolver is dropped.
- **Windows**: the Windows Filtering Platform, the same mechanism the official
  WireGuard client uses, so it does not disturb the user's own Windows Firewall
  rules. One provider, one top-weight sublayer and a fixed set of filters, all
  with fixed identifiers so turning it off is deterministic.

If the kill switch cannot be armed, the service (and the direct command line)
**refuses to connect** and undoes the routing: an unprotected tunnel is worse
than no tunnel.

## The service and its control channel

`hidravpn-service run` is the daemon. It holds the tunnel so no window needs to
stay open, and it exposes a local control channel for a client to drive it:

```
hidravpn-service install      # register and start the service (root / admin)
hidravpn-service status       # connected? kill switch on?
hidravpn-service up invite.json
hidravpn-service down
hidravpn-service uninstall
hidravpn-service firewall on --node IP:PORT --dns 10.77.0.1   # the kill switch alone
hidravpn-service firewall off
```

The command line now prefers the service when it is running, so `hidravpn up`,
`hidravpn down` and `hidravpn status` do the right thing whether or not the
service is installed. `--direct` makes the change in the current process instead
(phase-1 behaviour), and `hidravpn up --no-kill-switch` connects without the
kill switch, for diagnosis only.

The channel is a Unix socket in `/run` that only root may open (Linux) or a
named pipe (Windows). Every request must carry a control token the service
writes where only the owner can read it, so a web page that guesses the address
still cannot drive the tunnel. This is the channel the browser will use in
phase 4, through the same token.

## How to check it

On Linux, as root, with the release binaries built:

```
hidravpn/scripts/test-killswitch.sh       # the kill switch blocks a real leak path
hidravpn/scripts/test-service-netns.sh    # the whole service, connect to disconnect
```

The first proves that a path which worked before the kill switch is blocked
once it is armed, that the node endpoint still gets through, that loopback still
works, and that turning it off restores everything. The second runs a real
tunnel through the daemon and checks the interface, the routes and the kill
switch are all gone after `down`.

On Windows, `scripts/windows/phase2-test.ps1` runs the same checks from a real
machine. The kill switch there is the Windows Filtering Platform code, which is
validated on that machine; `hidravpn-service firewall off` always removes it,
even if everything else is blocked, because it needs no network to do so.

## What is honest about this phase

- The kill switch is a real default-drop firewall, not a route trick: it holds
  when the tunnel is gone.
- macOS has no kill switch yet, so the service refuses to connect there rather
  than leave the machine unprotected. pf comes next.
- On Windows the service is registered with the Service Control Manager and
  runs as LocalSystem (SYSTEM) at boot. (The first builds ran it from a
  scheduled task; the SCM's stop and shutdown controls let the daemon put the
  network back when the machine stops, which a hard-ended task did not.)
- Nothing is logged but counts and states: no address, no name, no traffic.
