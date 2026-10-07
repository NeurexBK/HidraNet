# 08 — Roadmap (24 months)

Organised by **unblockers**, not by features. Every quarter exists to remove a
specific blocker to the next one.

---

## Q1 — Make it sellable and fundable

| # | Work | Unblocks |
|---|---|---|
| 1 | **Network kill switch** in the browser ([03 §1.4](03-product-and-technology.md)) | Being able to claim privacy without caveats |
| 2 | Fix the WebRTC leak at the network level (`setWebRTCIPHandlingPolicy`) | Same — today there is only a JavaScript protection, which is bypassable |
| 3 | Inject the fingerprint at document start, not at `dom-ready` | Scripts in `<head>` currently read the real values |
| 4 | **NGI Zero application** | €5–50k non-dilutive + an audit |
| 5 | **Billable HidraReview**: multi-tenant, sign-up, payment | Being able to charge |
| 6 | Split `main.rs` (9,600 lines) into the modules that already exist | Technical due diligence |
| 7 | Legal consultation + incorporating the Lda | Everything else |

**End of Q1:** a chargeable product, an application submitted, a company
incorporated.

---

## Q2 — Prove that somebody pays

| # | Work | Unblocks |
|---|---|---|
| 1 | 10 in-person pilots, free | **Measuring real churn and CAC** |
| 2 | Owner panel: metrics that justify the invoice | Retention |
| 3 | NFC card production | Sales |
| 4 | First 30 paying customers | Market proof |
| 5 | Security audit (via NGI Zero, if approved) | Public browser launch |
| 6 | `.hidra` domain registry | 2nd revenue line |

**End of Q2:** 30 paying customers, churn measured, audit under way.
**Decision gate:** if churn is >8%, **stop selling and fix the product**. Do not
scale a funnel that does not retain.

---

## Q3 — Repeat the channel

| # | Work |
|---|---|
| 1 | 100 paying customers |
| 2 | Reseller channel (local agencies, accountants) |
| 3 | Public browser launch — only after the audit |
| 4 | HidraReview mobile apps (the end customer is on a phone) |
| 5 | Volunteer relay programme — **makes the network real** |

**End of Q3:** a repeatable channel, the browser launched with an audit behind
it.

---

## Q4 — Prepare the round

| # | Work |
|---|---|
| 1 | 200+ paying customers, 6 months of churn history |
| 2 | Complete data room ([15](15-data-room.md)) |
| 3 | Approach pre-seed VCs |
| 4 | 2nd NGI Zero application (next phase) |
| 5 | HidraNet Pro (B2C) — only if there is a user base that justifies it |

---

## Year 2 — Scale

| Quarter | Focus |
|---|---|
| Q5 | Pre-seed closed · 1st salesperson hired |
| Q6 | 2nd and 3rd cities · 600 customers |
| Q7 | Brazil structure · begin market entry |
| Q8 | 1,000+ customers · prepare the seed |

---

## What is **not** on the roadmap, and why

| Idea | Why not |
|---|---|
| A Firefox fork instead of Electron | Technically correct, costs 12 months. Re-evaluate in year 2 with a funded team. |
| Token / crypto | See [04 §3](04-business-model.md) — MiCA, banking, credibility |
| Our own exit network operated by the company | See [10 §1](10-legal-and-regulatory-risk.md) — structural risk |
| International expansion (non-Portuguese-speaking) | Before repeating the channel in one city, it is dispersion |
| HidraNet Pro in Q1 | With no user base, it converts ~0 |
