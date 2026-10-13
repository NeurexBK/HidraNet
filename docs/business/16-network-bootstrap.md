# 16 — Network bootstrap: who runs the first nodes, and why

Written in answer to a fair criticism from an experienced developer, received
in October 2026, paraphrased: *who is going to host this, and why? There is no
reward for hosting. There is no portless design; you have to open ports on
your router, and nobody does that.* He is right about the facts of today and
wrong about the conclusion. This document is the plan that makes the
difference, written down so anyone can hold us to it.

---

## 1. The facts, as they stand in the code

| Fact | Where | Consequence |
|---|---|---|
| **No reward exists for running a node.** | [04 §3](04-business-model.md) rejects a token under MiCA; [18 §3.1](../corporate/18-governance.md) lists node operators as volunteers | Nobody is paid, and we must not say otherwise anywhere |
| **A fresh relay finds nobody.** | `hidra-node/config.toml`: `bootstrap_nodes = []` | Without a seed list shipped with the software there is no network |
| **Every node needs a port reachable from the internet.** | `hidra-node` listens on TCP 9150; `hidravpn-node` on UDP 51820 | A node behind a home router needs port forwarding; behind carrier-grade NAT it is impossible |
| **No NAT traversal exists.** | No STUN, hole punching, UPnP or WebRTC anywhere in the tree | "Portless" volunteering is a roadmap item, not a feature |

What the criticism gets wrong is the deployment model: the nodes are built to
run on **servers** (`hidravpn-node init` and a systemd unit exist; the
one-command installer is for the client), not behind a living-room router. A server has no router to open, and an open
port on a server is as dangerous as the software behind it, no more. The real
danger of hosting is not the port. It is being an **exit** and receiving the
abuse complaints, which [10](10-legal-and-regulatory-risk.md) treats as an
architecture decision.

---

## 2. What history says

- **Tor** has run on seven to eight thousand volunteer relays for twenty years
  with no payment. It began with relays run by its own developers and a few
  universities, and volunteers followed reputation, not money.
- **Snowflake**, Tor's browser-based proxy, has well over ten thousand
  volunteers at a time who open no port at all: a browser tab or extension
  relays traffic over WebRTC. Portless volunteering exists, for the *entry*
  role.
- **Exit liability is carried by associations**, not individuals or product
  companies: Zwiebelfreunde (Germany), Nos Oignons (France), the Torservers.net
  network. That is the model for exits that survives contact with lawyers.
- **Token-paid networks** (Orchid, Mysterium, Sentinel) exist and are small.
  Payment did not make them large; it made them regulated.

The conclusion is not "it never works". It is: **a network never bootstraps
itself. The first nodes are always the project's own, and users must never
depend on volunteers early.**

---

## 3. Three kinds of node, three different burdens

| Node | Sees | Legal burden | Where it can run | Who runs it first |
|---|---|---|---|---|
| **Entry** (VPN) | The client's address, never the destination | Low; comparable to a Tor guard | Any server with a public UDP port; a home connection only once NAT traversal exists | Us |
| **Relay** (`hidra-node`, TCP 9150) | Encrypted cells, neither end | Low | Any server with a public TCP port | Us, then partners |
| **Exit** (VPN) | The traffic, not who sent it | **High**: abuse complaints, legal requests | A server, always, in a jurisdiction with a practice of hosting exits | Whoever knowingly accepts the liability; see §4 |

---

## 4. Phase 0 — our nodes (now, until the first public release)

**Target: ten nodes in at least three jurisdictions, two of them exits.**

- Small VPS instances cost **€4–6 per month each**; ten nodes are
  **≈ €50 per month**. This is paid by the founders personally, not by the
  company, consistent with Option B in [10](10-legal-and-regulatory-risk.md):
  the company publishes software, it does not operate the network.
- The two exits in this phase are run by the founders **as individuals, in
  jurisdictions where hosting Tor exits is established practice** (the
  Netherlands, Germany, Sweden, Finland), with a published abuse contact
  answered within one working day and an exit policy that blocks outbound mail
  (port 25) and the usual abuse ports. We know what this means. The
  alternative is launching with no exits, which is not a VPN.
- The client ships with these nodes as its **default pocket**, and
  `bootstrap_nodes` ships filled with the relays. A new user connects on the
  first try without knowing any of this.
- The test node that exists today is the first of the ten.

**Done when:** ten nodes, three jurisdictions, thirty days of measured uptime
above 99%, a stranger connects with the default pocket and passes the leak
test.

---

## 5. Phase 1 — partners and businesses (after the first release)

[06](06-go-to-market.md) says "every HidraReview business is a node". Read
against §1, that sentence needs a correction: a shop's router, usually behind
carrier-grade NAT, **cannot** be a node today. What a business can do is
**sponsor a node**: a €5 VPS in its name, installed with us in a video call
with the one-command installer, its name on the public operator list. The
business gets a line in its privacy story; the network gets a node whose
operator is a legal entity with an address, which is exactly what an entry or
relay operator should be.

Exits are **not** offered to businesses in this phase. An exit is offered only
to a partner who has read [10](10-legal-and-regulatory-risk.md), has an abuse
contact of its own and says yes in writing.

**Done when:** twenty-five nodes, at least five operators who are not us.

---

## 6. Phase 2 — volunteers (after reputation, not before)

Volunteers arrive when the software has a name, an audit, and a story of nodes
that stayed up. We prepare for them now and promise them only what exists:

- **A one-command node install** and documentation that assumes a rented
  server, not a home connection. The service file and the init command exist;
  the installer for nodes is the piece to finish.
- **Recognition, not payment.** A public operator list, the operator's chosen
  name on the node, a yearly report that names them. Nothing financial is
  promised until it is real.
- **A written exit code of conduct**, and no exit offered to anyone who has
  not read it.

**On paying operators.** [04](04-business-model.md) records why a token is
not the plan under MiCA. That decision stands and is revisited only when all
three hold: the company is incorporated and advised on MiCA; the network has
at least fifty nodes without payment; a payment model exists that does not
require the company to custody anything. Until then, no page, README or post
says that operators are paid. The VPN README said so until this document was
written; it no longer does.

**Done when:** one hundred nodes, thirty operators, and fewer than half of the
exits run by the founders.

---

## 7. Portless entry: the roadmap item

Volunteers at home will never open a port, and should not have to. Two
designs make an *entry* portless; neither applies to exits, which must stay on
servers.

| Design | How | Precedent | Cost |
|---|---|---|---|
| **Browser proxy** | A tab or extension relays the first hop over WebRTC to a server-side entry; the volunteer's address is what the network sees | Snowflake | A broker service, a WebRTC transport, a browser extension |
| **UDP hole punching** | The client and a home entry meet through a rendezvous server; works through most home NATs, not through carrier-grade NAT | WireGuard-based mesh VPNs | A rendezvous service and a fallback relay |

Proposed for the roadmap after Phase 0 is done; it does not go on the roadmap
before, because a portless entry with no exits behind it protects nobody.

---

## 8. What "working" means, in numbers

| Phase | Nodes | Jurisdictions | Operators other than us | Exits not ours |
|---|---|---|---|---|
| 0 | 10 | 3 | 0 | 0 |
| 1 | 25 | 4 | 5 | 1 |
| 2 | 100 | 6 | 30 | more than half |

A phase that does not reach its numbers is not skipped; it is understood.

---

## 9. Open decisions, for the founders

1. **Who carries exit liability after Phase 0**: the founders as individuals,
   or an association founded for the purpose, on the Zwiebelfreunde model.
   The association is the answer that scales; it costs a registration and a
   board.
2. **Which portless design** goes first, once Phase 0 is done.
3. **The date** on which the payment decision in §6 is next reviewed.

---

*Changed because of this document: the HidraVPN README no longer says
operators are paid; the "every business is a node" line in 06 is to be read
with §5.*
