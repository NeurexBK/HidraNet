# 07 — Financial Projections

> **A warning, and it is meant seriously.** Everything that follows is a set of
> **declared assumptions**, not forecasts. A pre-revenue startup does not have
> projections — it has a model that shows how it thinks. The value of this
> document is in the assumptions being explicit and arguable, not in the totals.
>
> An experienced investor will ignore the numbers and attack the assumptions.
> That is exactly what they are for.

---

## 1. Key assumptions

| # | Assumption | Value | Confidence | How to validate |
|---|---|---|---|---|
| A1 | HidraReview Pro ARPU | €19/month | Medium | Test €15 vs €19 vs €29 in the pilots |
| A2 | **Monthly churn** | **4%** | **Low** | **Measure on the first 20 customers — it is the metric that decides everything** |
| A3 | Direct-sales CAC | €60 | Low | Measure in phase 1 |
| A4 | SaaS gross margin | 85% | High | Sector standard |
| A5 | Free→Pro conversion | 15% | Low | Measure |
| A6 | New customers/month (year 1, from month 4) | 10 → 30 | Medium | Direct sales, one city |
| A7 | Server cost per customer | €0.50/month | High | Light infrastructure |
| A8 | Founder salary | €1,500/month gross each, from month 6 | — | A decision |

**A2 is the critical assumption.** At 4% churn, lifetime is 25 months and LTV
~€400. At 8%, it falls to 12.5 months and ~€200 — and direct sales at €60 CAC
stops being comfortable. **Measure this before hiring anybody.**

---

## 2. Base case — 36 months

### Year 1 (validation)

| | Q1 | Q2 | Q3 | Q4 | **Year 1** |
|---|---|---|---|---|---|
| Paying customers (end) | 0 | 15 | 45 | 100 | **100** |
| MRR (end, €) | 0 | 285 | 855 | 1,900 | **1,900** |
| Revenue (€) | 0 | 500 | 1,700 | 4,100 | **6,300** |
| Grants (NGI Zero) | — | 25,000 | — | — | **25,000** |
| Costs (€) | 4,000 | 8,000 | 12,000 | 15,000 | **39,000** |
| **Result (€)** | −4,000 | +17,500 | −10,300 | −10,900 | **−7,700** |

### Year 2 (scale in one geography)

| | Year 2 |
|---|---|
| Paying customers (end) | **450** |
| MRR (end) | **€8,550** |
| Annual revenue | **~€62,000** |
| Grants | €25,000 (2nd NGI Zero phase) |
| Team | 2 founders + 1 salesperson + 1 developer |
| Costs | ~€120,000 |
| **Result** | **−€33,000** |

### Year 3 (multi-city + pre-seed)

| | Year 3 |
|---|---|
| Paying customers (end) | **1,400** |
| MRR (end) | **€26,600** |
| Annual revenue | **~€230,000** |
| Team | 8 people |
| Costs | ~€290,000 |
| **Result** | **−€60,000** |

**Reading:** the business does not fund itself within 36 months on direct sales.
That is why the year 2 pre-seed round exists. **A model showing profit in year 2
without funding would be a sign the assumptions were not taken seriously.**

---

## 3. Cost structure (year 1 in detail)

| Item | Year 1 (€) | Notes |
|---|---|---|
| Founder salaries (from month 6) | 21,000 | €1,500/month × 2 × 7 months |
| Incorporation and accounting | 3,000 | Lda + certified accountant |
| **Legal** | **3,500** | See [10](10-legal-and-regulatory-risk.md) — do not cut here |
| Infrastructure (servers, domains) | 1,200 | |
| NFC hardware (initial stock) | 1,500 | ~500 cards |
| Tools and software | 1,200 | |
| Marketing and travel | 3,600 | In-person selling |
| Public liability insurance | 800 | |
| Contingency (10%) | 3,200 | |
| **Total** | **39,000** | |

**Year 1 capital need: ~€39,000**, of which **€25,000 can come from NGI Zero with
no dilution**. The remainder (~€14,000) is founder capital or early revenue. **It
is a viable start without an investor** — and that is the strongest negotiating
position they can have when the time comes to talk to one.

---

## 4. Capital need and round

| Phase | Amount | Source | Dilution |
|---|---|---|---|
| Start-up (year 1) | ~€39,000 | NGI Zero + founders | **0%** |
| Pre-seed (year 2) | €300,000–500,000 | VC / angels | 10–18% |
| Seed (year 3–4) | €1.5–3M | VC | 15–20% |

**Use of the pre-seed (€300–500k), 18 months of runway:**
- 45% sales team (this is the bottleneck: the product exists, the distribution
  does not)
- 25% product and engineering
- 15% marketing and acquisition
- 10% legal, compliance and security audit
- 5% contingency

**Context:** European pre-seed typically sits at €500k–3M and seed at €1–5M.
€300–500k is the lower bound — deliberately. Asking for the minimum needed to
reach the next milestone preserves dilution and signals discipline.

---

## 5. Sensitivity analysis — what breaks the model

| Variable | Bad case | Effect | What to do |
|---|---|---|---|
| **Churn 4% → 8%** | LTV falls ~50%, to ~€200 | **The model stops closing on direct sales** | Stop selling, fix the product |
| CAC €60 → €150 | LTV:CAC falls to ~1.3:1 | Unsustainable | Change channel (resellers, associations) |
| ARPU €19 → €12 | Revenue −37% | Survivable | Move customers up tiers, upsell `.hidra` domains |
| NGI Zero refused | −€25,000 in year 1 | ~6 month delay | Reapply (deadlines every 2 months) + Portugal 2030 |
| Google launches its own NFC | Differentiation eroded | **High** | The moat is the network and data ownership, not the NFC |

**The churn line is the one that decides whether this is a company.** All the
others are manageable.

---

## 6. Milestones that unblock the next round

| Milestone | Why |
|---|---|
| **20 paying customers with 3 months of history** | Gives real churn and CAC; replaces A2 and A3 with facts |
| 100 paying customers | Proves the channel repeats |
| NGI Zero approved | Independent technical validation + security audit |
| Security audit completed | Unblocks the public browser launch |
| Churn <5% for 3 months | Proves the product retains |

**Without the first two, any VC conversation is premature.**

---

## 7. The model file

These numbers should move into a spreadsheet with the assumption cells
**separated and linked**, so an investor can change the churn and see the effect
live. Doing that in a meeting is one of the gestures that buys the most
credibility: it shows the numbers are a model, not a sales argument.
