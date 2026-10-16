# 04 — Business Model

## 1. The guiding principle

The sector's evidence (see [02, section 3](02-market-analysis.md)) says one thing
clearly: **nobody pays for privacy; they pay for useful services and choose the
provider that respects privacy.**

Proton reached $97.5M ARR selling mail, storage and VPN — not selling
cryptography. Brave reached >$100M with tracking-free advertising, but it needed
100 million users to get there. The Tor Project, which sells pure anonymity, is a
non-profit sustained by donations.

HidraNet follows the Proton model, with one difference: **the first billable
service is B2B, not B2C**, because a business has a budget and a browser user
does not.

---

## 2. The revenue lines

Five lines, ordered by when they start producing money.

### Line 1 — HidraReview SaaS *(main revenue, starts now)*

Monthly subscription per business, plus margin on the NFC hardware.

| Tier | Price/month | Includes |
|---|---|---|
| **Free** | €0 | Public page, 1 `.hidra` address, unlimited reviews |
| **Pro** | €19 | NFC card, owner panel, HidraMail notifications, review replies, confirmed badge |
| **Multi** | €49 | Up to 5 locations, reports, comparison between locations |
| **Chain** | on request | 5+ locations, API, account manager |

**Hardware:** NFC card/plaque with margin. Unit cost in the order of €1–3, sold
at €15–25 or included in the Pro tier with a commitment. The review NFC card
market is worth $31.4M in 2026, but the value is in the software on top, not in
the plastic.

**Why a business pays:** NFC cards convert at **60–80%** against 35–50% for a QR
code, and reviews are one of the main ranking signals in local search. It is a
sale with demonstrable return, not an ideological sale.

### Line 2 — HidraNet Pro *(B2C, the Proton model)*

Freemium on useful services, not on privacy:

| | Free | Pro (~€5/month) |
|---|---|---|
| Browser + Tor | ✅ | ✅ |
| HidraSearch | ✅ | ✅ |
| HidraMail | basic | extended storage, own domain |
| `.hidra` domains | 1 | 10 |
| Circuit priority | — | ✅ |
| Support | community | direct |

**A note of realism:** this line only makes sense above ~50,000 active users.
Below that, the typical freemium conversion rate (1–3%) produces irrelevant
revenue. It is in the plan, not in the start.

### Line 3 — `.hidra` domains *(recurring, high margin)*

Registration and renewal of readable addresses on the network. Every HidraReview
business already has one — it is a natural upsell. Marginal cost near zero.

### Line 4 — Engine licensing *(B2B, opportunistic)*

`hidra-node` is onion routing with a hybrid **X25519 + ML-KEM-1024** handshake,
in Rust, under MIT. There is
enterprise demand for quantum-resistant transport layers. Commercial licence,
support and integration — high-value, low-volume revenue. Do not plan for it;
accept it when it appears.

### Line 5 — Grants and donations *(non-dilutive, starts now)*

Not revenue in the accounting sense, but money that funds the protocol layer at
no cost of capital. See [document 13](13-funds-and-applications.md). NGI Zero
(€5–50k) should be submitted at the next deadline.

---

## 3. What we reject, and why

An investor will ask. Having the answer ready is worth more than the answer.

| Option | Why not |
|---|---|
| **Selling user data** | Destroys the only value proposition we have. Not negotiable. |
| **Advertising with tracking** | Same. |
| **A token as revenue or as a reward (the BAT model)** | HNET exists, and its role is narrow on purpose: it pays for HidraVPN and other services inside the HidraNet network ([HNET whitepaper](../../landing/token/index.html)). We do not sell it as a product, promise returns, or pay node operators in it. Under MiCA a wider role is a heavy regulatory burden and alienates the privacy community, which is our initial audience; legal advice comes before payments in HNET go live. |
| **Operating exit nodes as a company** | Inherits abuse complaints and legal requests. An architecture decision, not a product one. See [document 10](10-legal-and-regulatory-risk.md). |
| **Selling anonymity as the main product** | The competitor charges zero. |

---

## 4. Unit economics (assumptions, to be validated)

> **These numbers are declared assumptions, not forecasts.** Replace them with
> real data as soon as there are 20 paying customers. Presenting them to a VC as
> facts is the fastest way to lose the next meeting.

**HidraReview Pro, per business:**

| Metric | Assumption | Note |
|---|---|---|
| ARPU | €19/month → €228/year | Pro tier |
| Gross margin | ~85% | SaaS; marginal server cost |
| NFC card cost | €1–3 | One-off, amortised |
| CAC (direct sales) | €40–80 | Door-to-door / phone; **the most uncertain of all** |
| Monthly churn | 3–5% | Typical in micro-business SaaS; it is high and it is the main risk |
| Lifetime | ~20–33 months | 1/churn |
| **LTV** | **~€390–640** | ARPU × margin × lifetime |
| **LTV:CAC** | **~5:1 to 8:1** | Healthy **if** the CAC holds up |

**The number that decides the business is churn.** SaaS sold to micro-businesses
has structurally high churn. If real churn is 8%, lifetime falls to 12 months and
LTV to ~€190 — and the economics stop working with direct sales. **First metric
to measure, before hiring any salesperson.**

---

## 5. How the two halves sustain each other

```
  GRANTS (NGI Zero, EIC)              →  fund the protocol and the browser
            │                             (open source, no dilution)
            ▼
  NETWORK + BROWSER                   →  technical credibility, users,
            │                             differentiation
            ▼
  HIDRAREVIEW (B2B, paid)             →  recurring revenue, which funds the team
            │
            ▼
  Each business = 1 .hidra address    →  real content and real users on the
  on the network                         network, which is what kills new networks
            │
            └──────────────────────────┘  (the loop closes)
```

**The sentence for the deck:** *"The local reputation business pays the bills.
The network is the moat. Every customer we close is a new node on the network."*

This is only true if the product makes it true — see [roadmap](08-roadmap.md) for
the work to get there.
