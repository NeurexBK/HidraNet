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
| **No reward exists for running a node.** | [04 §3](04-business-model.md) limits HNET to paying for services, not rewarding operators; [18 §3.1](../corporate/18-governance.md) lists node operators as volunteers | Nobody is paid, and we must not say otherwise anywhere |
| **A fresh relay finds nobody.** | `hidra-node/config.toml`: `bootstrap_nodes = []` | Without a seed list shipped with the software there is no network |
| **Every node needs a port reachable from the internet.** | `hidra-node` listens on TCP 9150; `hidravpn-node` on UDP 51820 | A node behind a home router needs port forwarding; behind carrier-grade NAT it is impossible |
| **No NAT traversal exists.** | No STUN, hole punching, UPnP or WebRTC anywhere in the tree | "Portless" volunteering is a roadmap item, not a feature |

What the criticism gets wrong is the deployment model: the nodes are built to
run on **servers** (`hidravpn-node init`, a systemd unit and a one-command
installer, `hidravpn/scripts/install-node-linux.sh`), not behind a living-room
router. A server has no router to open, and an open
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
- **Independent entries, by decision of the founders (October 2026).** Phase 0
  also takes entries run by operators who are not us: entries only, each
  operator checked before their node goes into the list, at most two nodes per
  operator (`hidravpn/docs/operators/running-an-entry.md`). An entry draws no
  abuse mail for web or mail traffic, and a second operator is what makes
  Privado's "no node sees both" true of people (§6). Users still do not depend
  on them: a client that allows one operator on both hops keeps the founders'
  own entries.
- The two exits in this phase are run by the founders **as individuals, in
  jurisdictions where hosting Tor exits is established practice** (the
  Netherlands, Germany, Sweden, Finland), with a published abuse contact
  answered within one working day. Every node's firewall blocks outbound
  mail (port 25) and the usual abuse ports from the tunnel, an entry-role
  node forwards nothing but WireGuard, and the reply to an abuse complaint is
  written down in `hidravpn/docs/operators/abuse-response.md`, template
  included. We know what this means. The alternative is launching with no
  exits, which is not a VPN.
- The client learns of these nodes from a **signed node list** the
  maintainers publish (`nodes.json` + `nodes.json.sig`, made with
  `hidravpn/scripts/make-node-list.sh` from the records the nodes print):
  the client checks the signature against the list key built into it before
  reading a byte, refuses a list that expired or is older than the one it
  holds, strikes the nodes the list withdrew, and writes the rest down as
  known. The browser fetches the list by itself from
  `https://hidranet.org/vpn/nodes.json` and hands it to the service to
  verify; the command line takes the file.
- **A stranger connects on the first try** because every Phase 0 node runs
  with **open admission** (`--open-admission`): a small service beside the
  tunnel that hands an invite to any client that asks, three per address and
  120 per node every ten minutes, up to 4000 clients per node, with a lease
  that lapses after thirty days without use. The client asks every known
  open node on its own when it connects. Admission by hand
  (`hidravpn-node admit`) stays for nodes whose operator wants it: the list
  says which is which, and the client tells the person whom to ask. Phase
  5's passes are what will make admission accountable; open admission is
  what makes it exist now. The relay engine's `bootstrap_nodes` is still
  empty and is to ship filled with the relays.
- **What ten nodes cost and how to get them** is in
  `hidravpn/docs/running-nodes.md`: a small VPS per node, one command to
  install it (`install-node-linux.sh --role exit|entry --operator ...
  --contact ... --open-admission`), its record into the list, the list
  signed and published, and `probe-nodes.sh` run from a machine that is not
  a node so "uptime above 99%" is a measured number.
- The test node that exists today is the first of the ten.

**Done when:** ten nodes, three jurisdictions, thirty days of uptime above
99% as the prober measures it, a stranger connects with the published list
alone and passes the leak test.

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
  server, not a home connection: `hidravpn/scripts/install-node-linux.sh`,
  which installs the node with its role (entry, exit or both), its
  operator's name and contact, and open or by-hand admission; opens the one
  UDP port (and the admission port, if open); prints the node's record for
  the list; and says in plain words what running an exit means.
  `hidravpn/docs/running-nodes.md` is the guide, and
  `docs/operators/abuse-response.md` is what an exit operator reads first.
- **An entry needs less courage than an exit.** A volunteer who will not run
  an exit can run an entry: it forwards only WireGuard to other nodes, sees
  the client's address and nothing of what they do, and draws no abuse mail.
  Entries run by people other than the founders are what make Privado's
  "no node sees both" true of the operators and not only of the nodes; the
  client already prefers such a pair and says when it could not find one.
- **Recognition, not payment.** A public operator list, the operator's chosen
  name on the node, a yearly report that names them. Nothing financial is
  promised until it is real.
- **A written exit code of conduct**, and no exit offered to anyone who has
  not read it.

**On paying operators.** [04](04-business-model.md) records why HNET pays
for services and does not reward operators under MiCA. That decision stands and is revisited only when all
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

On the roadmap as a proposal scheduled after Phase 0 is done, not before,
because a portless entry with no exits behind it protects nobody.

---

## 8. What "working" means, in numbers

| Phase | Nodes | Jurisdictions | Operators other than us | Exits not ours |
|---|---|---|---|---|
| 0 | 10 | 3 | entries only | 0 |
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
