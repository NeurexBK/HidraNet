# Abuse complaints: what arrives, what to answer

If you run an **exit**, complaints about what clients did through it arrive at
you: your provider's abuse desk, or the address in the WHOIS record of your
server's IP. This page is what to do. It is written for an operator, not a
lawyer; the legal picture is `docs/business/10-legal-and-regulatory-risk.md`.

## Before the first complaint

1. **Put your abuse contact in the WHOIS record** of the address (your
   provider's panel: "abuse contact", `abuse-c`, or a reverse DNS name that
   says what the server is, such as `vpn-exit-1.example.org`). Complaints that
   reach you directly are complaints that do not reach your provider first.
2. **Know what the node blocks.** From the tunnel, an exit never forwards
   mail (TCP 25) nor the usual abuse ports (135–139, 445, 1433, 3389); an
   entry forwards nothing but WireGuard. `hidravpn-node run` installs these
   rules in nftables (`nat.rs`).
3. **Know what the node keeps.** Nothing about traffic: no destination, no
   packet, no name looked up. The leases file holds clients' public keys and
   tunnel addresses, not who they are. You cannot identify the client behind a
   complaint, and you should say so plainly.
4. **Answer within one working day.** Most providers suspend a server for
   silence, not for a complaint.

## The reply

Send this, filled in, from the address in WHOIS:

> Hello,
>
> Thank you for the notice. The address you reported, <ip>, is the exit of a
> HidraVPN node, part of the open-source HidraNet network
> (<https://github.com/NeurexBK/HidraNet>). It carries encrypted traffic for
> clients I do not operate and cannot identify: the node keeps no logs of
> destinations, content or client identities, by design, and I therefore have
> no information about the activity you describe.
>
> The node does not forward mail (port 25) or the ports commonly used for
> abuse. If the activity concerned a specific destination or port, tell me and
> I will check whether the node's policy can block it without affecting other
> users.
>
> I take abuse seriously and answer every notice. Please direct legal requests
> to <your contact>; I will respond to any lawful order within the applicable
> time.
>
> Regards,
> <name>, operator of <node name>

Keep it factual. Do not promise to identify a user: you cannot. Do not promise
to log: do not.

## Common cases

| Complaint | What it usually is | What to do |
|---|---|---|
| Port scanning, SSH brute force | A client's automated tool | Reply as above; if it repeats from the node daily, consider blocking the destination port range in the node's policy and say so |
| Copyright notice (DMCA and the like) | A client's download | Reply as above; you hold no information to forward; keep the notice |
| Spam | Should not happen: port 25 is blocked | Say that outbound mail is blocked at the node and ask for the evidence |
| Law-enforcement request | Rare | Reply that you will comply with a lawful order and have no logs; consult document 10 and a lawyer before anything else |
| Provider threatens suspension | They want an answer | Answer the same day; point at this page's facts |

## What the node can do for you

- `hidravpn-node status` shows the admitted clients by name, handshake age and
  bytes: counts, not identities.
- `hidravpn-node revoke --pubkey <key>` removes a client you admitted by hand.
  Openly admitted clients expire on their own after `idle_days` idle.
- If one exit draws more complaints than you can answer, switch it to an
  **entry** (`role = "entry"` in `/etc/hidravpn/node.toml`, restart): an entry
  sees addresses, not traffic, and complaints stop.

## If you want out

`sudo systemctl disable --now hidravpn-node`, remove the unit and the binary,
and tell the list maintainers so the node is withdrawn from the next list
(`make-node-list.sh --removed <its public key>`). Clients forget it the next
time they fetch the list.
