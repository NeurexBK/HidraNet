# 14 — Pitch Deck

12 slides. Content ready to lay out. Rule: **one slide, one idea, one number.**

---

### 1 — Cover
> # HidraNet
> **Reputation for local business, on a post-quantum privacy network.**
>
> Leonardo Mello · João Brandão · September 2026

---

### 2 — The problem
> A restaurant with 12 reviews loses to the one on the corner with 200.
> The difference is not the food — it is how many customers were asked to review.
>
> Today that invitation is a QR code on a table: **converts at 35 to 50%**.
>
> And the page holding the reviews does not belong to the restaurant. It belongs
> to Google.

---

### 3 — The solution
> An NFC card on the table. One tap. **Converts at 60 to 80%.**
>
> The page belongs to the business, with its own `.hidra` address, and it does
> not disappear if Google changes its policy.

*Visual: a photograph of a card on a table + the page on a phone.*

---

### 4 — Product (what already exists)
> - **HidraReview** — reviews, NFC, owner panel, HidraMail notifications
> - **HidraNet Browser** — bundled Tor, per-tab isolation, verified anonymity
> - **hidra-node** — 17,000 lines of Rust: onion routing + **Kyber1024** (post-quantum)
> - HidraSearch · HidraChat · HidraMail · Forum · `.hidra` sites
>
> Open source, MIT.

*Visual: a screenshot of the owner panel, not an architecture diagram.*

---

### 5 — Market
> **Where we sell:** micro-businesses and local commerce in PT and BR.
> Review NFC cards: **$31.4M (2026) → $90M (2035)**.
>
> **Where we are positioned:** privacy and VPN, **$83–108bn** in 2026, growing
> ~20% a year.
>
> **Tailwind:** Chat Control was rejected by **one vote** in March 2026 and went
> back to the Council. Every one of those cycles generates demand for privacy
> that legislators cannot stop.

---

### 6 — Business model
> | | Price |
> |---|---|
> | Free | €0 |
> | **Pro** | **€19/month** + NFC card |
> | Multi (5 locations) | €49/month |
>
> **Assumptions to validate:** LTV ~€400 · CAC ~€60 · margin 85%
>
> *Second line:* `.hidra` domains, recurring, marginal cost ~0.

---

### 7 — Why this is a moat
> Birdeye copies the NFC card in three months.
>
> **It does not copy the network.**
>
> Every business that joins becomes a node with its own address. The reputation
> business pays the bills; the network is what no review competitor can
> replicate.

*This is the slide that decides the meeting. Rehearse it until it comes out in 30
seconds.*

---

### 8 — Competition
> | | Price | Owns the data | NFC | PT/BR |
> |---|---|---|---|---|
> | Google Business | Free | Google | ✗ | partial |
> | Birdeye/Podium | €200–400/month | The platform | add-on | ✗ |
> | NFC cards | €15–30 | — | hardware only | ✗ |
> | **HidraNet** | **€0–49/month** | **The business** | **✓** | **✓** |
>
> We do not replace Google. We are what makes Google work better for the business
> — and what gives it a page that is its own.

---

### 9 — Go-to-market
> **Phase 1** — one city, direct selling, 100 customers, churn measured
> **Phase 2** — resellers (local agencies, accountants), 450 customers
> **Phase 3** — Brazil
>
> The browser is not sold: it is technical credibility and top of funnel.

---

### 10 — Traction and funding
> **Today:** product built, open source, pre-revenue.
>
> **Under way:** an **NGI Zero** (NLnet) application — €5–50k **non-dilutive**,
> plus an external security audit.
>
> **Milestones:** 20 customers with 3 months of history → 100 customers → round.

*If, at the time of the pitch, there are already customers or NGI Zero has been
approved, this slide moves to position 3.*

---

### 11 — Team
> **Leonardo Mello**, 28 — *[role and background]*
> **João Brandão**, 26 — *[role and background]*
>
> **What we are missing:** sales. The plan: the founders sell the first 100;
> first salesperson at the 100th customer.

*Acknowledge the gap. It is stronger than hiding it.*

---

### 12 — The ask
> **€300–500k pre-seed**, 18 months of runway.
>
> 45% sales · 25% product · 15% marketing · 10% legal and audit · 5% contingency
>
> **To reach:** 450 paying customers, churn <5%, a working reseller channel,
> Brazil prepared.

---

## Appendix (backup slides, for questions)

| # | Slide | For the question |
|---|---|---|
| A1 | Technical architecture | "How does it work?" |
| A2 | Legal risk and mitigation | "What about Chat Control?" — [10](10-legal-and-regulatory-risk.md) |
| A3 | Detailed financial model | "Show me the numbers" |
| A4 | Churn sensitivity | "What if churn is double?" |
| A5 | Why PT and not EE/BR | "Where will you incorporate?" |
| A6 | 24-month roadmap | "What do you do with the money?" |

---

## Presentation rules

1. **Do not say "our market is worth a hundred and eight billion".** Say the SOM.
2. **Do not hide that it is two products.** Raise it before they ask, with slide
   7 as the answer.
3. **Do not present projections as forecasts.** Say "assumptions"; offer to
   change the model live.
4. **Do not promise a working anonymity network of our own.** Today it is our own
   protocol + the Tor network. Say that.
5. **Raise Chat Control first.** A privacy VC knows it better than we do.
