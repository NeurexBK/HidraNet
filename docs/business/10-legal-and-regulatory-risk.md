# 10 — Legal and Regulatory Risk

> **This is not legal advice.** It is a survey of the risks, to prepare the
> conversation with a digital-law solicitor — a conversation that has to happen
> **before** incorporation, not after. The decisions in section 1 are structural:
> changing them later means restructuring the company.

---

## 1. The decision that has to be made first

**Does the company operate the network, or does it only make the software?**

It is the most consequential decision in this entire package. Everything else
depends on it.

### Option A — The company operates exit nodes ❌ **Not recommended**

Whoever operates an exit node on an anonymity network receives anonymous users'
traffic leaving for the open internet, under their own IP. In practice that
means:

- Abuse complaints directed at the company
- Data requests from law enforcement
- Liability risk for content the company neither controls nor sees
- IP blocking by third-party services
- Difficulty obtaining banking and insurance

The Tor Project has dealt with this since day one — and it is a non-profit with
specialised legal support, not a two-founder startup.

**A company with two founders should not carry exit operator liability.**

### Option B — The company makes software; the network belongs to volunteers ✅ **Recommended**

The company:
- Publishes open-source software (MIT — already the case)
- Sells services (HidraReview SaaS, subscriptions, `.hidra` domains)
- **Does not operate exit nodes**
- **Does not host third-party content** (or, if it does, knowingly takes on
  hosting-provider status under the DSA — see section 3)

Relays are run by volunteers, as with Tor. The company supplies the software and,
eventually, a foundation supports the network.

**This is the Proton model:** Proton AG (the company, selling services) + Proton
Foundation (the mission). In practice it is also Tor's model.

### Recommended structure

```
   ┌──────────────────────────┐      ┌────────────────────────────┐
   │  HidraNet, Lda           │      │  HidraNet association /    │
   │  (commercial company)    │      │  foundation (optional, Q2+)│
   ├──────────────────────────┤      ├────────────────────────────┤
   │ • HidraReview SaaS       │      │ • Protocol and spec        │
   │ • HidraNet subscriptions │      │ • Relay community          │
   │ • .hidra domains         │      │ • Receives grants          │
   │ • Engine licensing       │      │ • Operates no exits        │
   │ • Employs the founders   │      │                            │
   └──────────────────────────┘      └────────────────────────────┘
              │                                    │
              └────── MIT licence, both ───────────┘
                      contribute to the code
```

**A note of pragmatism:** the foundation is not necessary on day one and it adds
cost and complexity. Incorporate only the company; keep the separation **in the
technical design** from the start (the company never operates exits) and create
the separate legal structure when grants or third-party relays justify it.

---

## 2. Chat Control / CSAR

**Current state (September 2026):** rejected on 26 March 2026 by one vote,
returned to the EU Council. **Neither dead nor in force.**

What it would require: client-side scanning of messages before encryption, in
practice bypassing E2E protection.

**HidraNet's exposure:** if it passes in a form covering "number-independent
interpersonal communication services", **HidraChat** and **HidraMail** may fall
within scope.

**Mitigations:**
1. **Content-blind architecture.** HidraChat is already E2E in the client over a
   relay. The company should not be in a position to access content, even if it
   wanted to. Keep it that way and document it.
2. **Software, not a service.** If the chat is software the user runs and the
   relay belongs to a third party, the legal position is substantially different
   from operating a messaging service.
3. **Follow it actively.** This goes back to the Council. Joining EDRi or an
   equivalent gives early warning and places the company on the right side of the
   debate — which is also marketing to the audience we want.

**How to present it to an investor:** do not hide it. A VC who invests in privacy
knows Chat Control better than we do. Showing it is mapped and mitigated signals
maturity; not mentioning it looks naive.

---

## 3. DSA — Digital Services Act

Applies if the company **hosts third-party content**. Relevant to:
- `.hidra` sites (SevenNine)
- The forum
- HidraReview reviews ← **this is the one that counts**

**HidraReview hosts reviews written by users about identified businesses.** That
is third-party content hosting, with defamation risk. Likely obligations: a
notice-and-action mechanism, a contact point, clear terms, complaint handling.

> **Note:** the defamation problem in reviews is not theoretical. It is the
> classic litigation of this market — a business sues over a false review.
> Trustpilot and Google have legal teams for it. What is needed: a content
> policy, a dispute process for the business owner (the owner panel already
> exists — that is the basis), and public liability insurance.

For `.hidra` sites and the forum, the position is safer if the company **does not
host**: if the content lives on the user's machine or on volunteer relays, the
company is a software supplier, not a host.

---

## 4. GDPR

It applies, and it is a competitive advantage if done well — but it is a real
obligation.

| Obligation | Applicable | Notes |
|---|---|---|
| Legal basis for processing | ✅ | Contract (SaaS), consent (marketing) |
| Record of processing activities | ✅ | Art. 30 — a mandatory document |
| Privacy policy | ✅ | Must reflect what the software **actually** does |
| Data subject rights | ✅ | Access, rectification, erasure, portability |
| Data Protection Officer (DPO) | Probably not | Not mandatory at initial scale; re-evaluate |
| Data protection impact assessment (DPIA) | **Probably yes** | Anonymity technology + review data |
| Breach notification (72h) | ✅ | Needs a written procedure, before it is needed |
| Processors | ✅ | A contract with each supplier (hosting, payments, email) |

**A note specific to anonymity:** HidraNet, by design, **does not collect**
browsing data. This hugely simplifies GDPR on the browser side, and should be
documented as a deliberate architectural decision. The data that does exist is
all on the HidraReview side: business accounts, emails, billing, review content.

---

## 5. Payments and banking — the underestimated operational risk

**Real problem:** payment processors and banks restrict or refuse services
associated with anonymity. Privacy companies are refused by banks regularly.

**Mitigations:**
1. **Bill HidraReview as reputation and local marketing SaaS** — which is what it
   is. Not as an "anonymity service". The activity description and the
   classification code matter.
2. **Do not mix billing entities**: B2B SaaS is a perfectly conventional business
   in a bank's eyes.
3. **Have an alternative processor ready** before you need it.
4. **Keep HNET away from the SaaS billing.** HNET pays for HidraVPN and other
   HidraNet services; HidraReview is billed in euros, by its own entity or
   account. Mixing them multiplies compliance scrutiny and narrows the banking
   options further. Legal advice on MiCA comes before payments in HNET go live.

---

## 6. Other risks

| Risk | Exposure | Mitigation |
|---|---|---|
| Reputational association with illicit markets | Medium-high | Public positioning in legitimate local commerce; explicit terms of use |
| Liability for content on `.hidra` sites | Medium | The company does not host |
| Defamation in reviews | **High** | Policy, dispute process, insurance |
| Cryptography export control | Low | Published open-source code generally benefits from exemptions; **confirm with a solicitor** |
| Data retention (varies by country) | Medium | The company does not operate the network, so it has nothing to retain |
| Founders' intellectual property | Medium | IP assignment signed by both, **before** any round |

---

## 7. Concrete actions, in order

| # | Action | When | Estimated cost |
|---|---|---|---|
| 1 | Consultation with a digital-law solicitor (not a generalist) | **Before incorporating** | €300–800 |
| 2 | Decide Option A vs B (recommendation: **B**) | Before incorporating | — |
| 3 | IP assignment from the founders to the company | At incorporation | included |
| 4 | Terms of Service + Privacy Policy + Content Policy | Before the first customer | €500–1,500 |
| 5 | Record of processing activities (GDPR art. 30) | Before the first customer | internal |
| 6 | DPIA | Before the public launch | internal + review |
| 7 | Professional liability insurance | Before 100 customers | €400–1,200/year |
| 8 | Breach notification procedure | Before the first customer | internal |

**First-year legal budget: €2,000–5,000.** It is one of the best investments
available at this stage, and it is a line an experienced investor expects to see
in the plan. Its absence is a warning sign.
