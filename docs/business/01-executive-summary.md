# 01 — Executive Summary

**HidraNet** · September 2026 · Leonardo Mello (28) · João Brandão (26)

---

## In one sentence

We sell reputation to local businesses, on top of an open-source
post-quantum privacy network that no review competitor can copy.

---

## The problem

A local business has revenue tied directly to its online reviews. Today the
invitation to review is a QR code on a table, which **converts at 35–50%**. And
the page holding the reviews belongs to Google, not to the business.

## The solution

An NFC card: one tap, **60–80% conversion**. The page belongs to the business,
with its own `.hidra` address on the HidraNet network.

## What already exists

| Component | State |
|---|---|
| `hidra-node` — Rust engine, onion routing + post-quantum **Kyber1024** | ~17,000 lines, compiles clean |
| `hidra-browser` — bundled Tor, per-tab isolation, **verified anonymity** | ~7,800 lines |
| HidraReview, HidraSearch, HidraChat, HidraMail, Forum, `.hidra` sites | Working |
| Landing page, PWA, Win/Linux/macOS packaging | Done |
| MIT licence | ✅ eligible for European funds |

**Commercial state: pre-revenue.**

## Market

- Review NFC cards: **$31.4M (2026) → $90M (2035)** — small, but the value is in
  the SaaS on top of it.
- Privacy/VPN, where we are positioned: **$83–108bn** in 2026, ~20% a year.
- **Regulatory tailwind:** Chat Control was rejected by **one vote** in March
  2026 and went back to the EU Council. Every cycle generates demand for privacy
  that legislators do not stop.

## Business model

Free · **Pro €19/month** + NFC card · Multi €49/month · Chains on request.
Second line: `.hidra` domains, recurring, marginal cost ~0.

Assumptions still to validate: LTV ~€400, CAC ~€60, margin 85%.

## The ask

**€300–500k pre-seed**, 18 months, to prove the HidraReview sales engine in
Portugal and prepare Brazil.

Before that: **NGI Zero (NLnet), €5–50k non-dilutive**, to be submitted at the
next deadline.

---

## The three things this plan assumes that could be wrong

Put here on purpose. An executive summary with nothing but good news does not
survive a second meeting.

**1. That churn is around 4%.**
SaaS sold to micro-businesses has structurally high churn. At 8%, LTV halves and
direct selling stops closing. It is the first metric to measure, and until then
the model is a hypothesis.

**2. That the network really is a moat.**
Today the link between HidraReview and the network is one `.hidra` address per
business. To be a real moat it has to give the business something it values —
and that is work still to be done, not an existing feature.

**3. That we can sell without a sales team.**
Two founders, with no declared sales track record, selling to a customer that
expects someone to show up in person. The first 100 customers are sold by them
or they are not sold at all.

---

## What this project has that most do not

- **A product that is built and running**, not a presentation.
- **Real, verifiable technical differentiation**: onion routing with Kyber1024
  in production, which Tor does not yet have.
- **Immediate eligibility for non-dilutive money** — MIT, decentralised,
  privacy-focused: literally the NGI Zero mandate, with €21.6M + €9.6M in open
  funds through 2027.
- **A revenue path that does not depend on convincing anyone to pay for
  privacy** — it depends on convincing a restaurant that it wants more reviews,
  which is a far easier sale.
- **Honesty as a product feature:** the browser checks its exit IP against the
  Tor Project's own verifier and, when it cannot confirm it, **tells the user it
  could not**, instead of asserting an anonymity it has not verified. That is a
  rare choice, and it is the best indicator of the kind of company this can be.

---

## Next steps (30 days)

| # | Action |
|---|---|
| 1 | **Submit to NGI Zero** — does not require an incorporated company |
| 2 | Consultation with a digital-law solicitor |
| 3 | Incorporate **HidraNet, Lda** (Portugal — see [11](11-jurisdiction-comparison.md)) |
| 4 | Shareholders' agreement with **vesting** and IP assignment |
| 5 | Close the browser's privacy gaps ([03 §1.4](03-product-and-technology.md)) |
| 6 | Billable HidraReview + 10 in-person pilots |

---

*Supporting document. The full package is in [`00-INDEX.md`](00-INDEX.md).*
