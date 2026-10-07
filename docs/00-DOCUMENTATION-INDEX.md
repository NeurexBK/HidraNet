# HidraNet — Documentation Index

**Version 1.0 · September 2026 · Lisbon, Portugal**
Founders: João Brandão · Leonardo Mello

---

## Documents

### 📐 Technical — `docs/technical/`

| # | Document | Audience |
|---|---|---|
| 01 | [Technical Whitepaper](technical/01-whitepaper.md) | Investors, fund evaluators, the technical community |
| 07 | [Installation Guide](technical/07-installation-guide.md) | Users, node operators |
| 08 | [User Guide](technical/08-user-guide.md) | Users |
| 09 | [API Documentation](technical/09-api.md) | Developers, integrators |

### ⚖️ Legal — `docs/legal/`

| # | Document | State |
|---|---|---|
| 03 | [Terms and Conditions](legal/03-terms-of-use.md) | ⚠️ Template — review with a lawyer |
| 04 | [Privacy Policy](legal/04-privacy-policy.md) | ⚠️ Template — GDPR + LGPD |
| 05 | [Acceptable Use Policy](legal/05-acceptable-use-policy.md) | ⚠️ Template |
| 06 | [NDA](legal/06-nda.md) | ⚠️ Mutual template |

### 💼 Corporate — `docs/corporate/`

| # | Document | Note |
|---|---|---|
| 02 | [Cap Table](corporate/02-cap-table.md) | Seed US$50k / 5% · See §6: Lda or SA |
| 16 | [Stock Option Policy (ESOP)](corporate/16-esop.md) | 10% pool · See §8: tax |
| 18 | [Governance Guide](corporate/18-governance.md) | Separation of company and network |

### 🔒 Security — `docs/security/`

| # | Document |
|---|---|
| 14 | [Information Security Policy](security/14-information-security-policy.md) |
| 15 | [Incident Response Plan](security/15-incident-response-plan.md) |

### 🤝 Community — `docs/community/`

| # | Document |
|---|---|
| 10 | [Contributing Guide](community/10-contributing-guide.md) |
| 11 | [Code of Conduct](community/11-code-of-conduct.md) |
| 19 | [Ambassador Programme](community/19-ambassador-programme.md) |

### 🎨 Brand and Communication — `docs/brand/`

| # | Document | Note |
|---|---|---|
| 12 | [Brand Manual](brand/12-brand-manual.md) | ⚠️ See §1: two identities to unify |
| 13 | [Press Kit](brand/13-press-kit.md) | |
| 20 | [FAQ](brand/20-faq.md) | |

### 👥 Internal — `docs/internal/`

| # | Document |
|---|---|
| 17 | [Onboarding Handbook](internal/17-onboarding.md) |

### 📊 Business — `docs/business/`

The earlier package: market, business model, competition, go-to-market,
projections, roadmap, legal risk, jurisdiction, funds, pitch deck, data room.
See [`business/00-INDEX.md`](business/00-INDEX.md).

---

## Before you use these: six points to resolve

Raised while writing them. They are not opinions — they follow from checking the
code and the numbers.

### 1. ⚠️ The whitepaper does not claim an anonymity network of our own in production

Verified in the code: the engine's relays are configured at
`127.0.0.1:7001-7003`, and the code itself documents that our own circuit exits
from the user's machine without changing the IP. Exit anonymity comes today from
the **bundled Tor**.

The protocol is implemented and tested; the **relay population** is being built.
The whitepaper (§8) says so expressly, because the opposite claim does not
survive technical verification — and losing technical credibility in a
cryptography project is irreversible.

**The same caution applies to the number of active nodes:** use only numbers you
can demonstrate.

### 2. ⚠️ Lda or SA — decide before incorporating

An Lda has **quotas**, not shares. Every option exercise is a quota assignment,
with a notarised deed, registration and pre-emption rights. It makes an ESOP
operationally heavy.

See [Cap Table §6](corporate/02-cap-table.md). Fixing it later costs a corporate
conversion, usually under the time pressure of a round.

### 3. ⚠️ Tax treatment of options

In Portugal, an employee can be taxed at exercise on a gain they have not yet
realised in cash, because the holdings are illiquid. It is a real and recurring
problem.

**Obtain a tax opinion before the first grant.** See
[ESOP §8](corporate/16-esop.md).

### 4. ⚠️ Intellectual property assignment

All the code written so far belongs to the founders **personally**. Without a
formal assignment, the company does not own the product it says it sells.

It is an absolute blocker in due diligence. Sign it at incorporation.

### 5. ⚠️ Two visual identities

The website uses neon green `#00ff88`; the product uses teal `#00d4aa`. They are
different brands. The decision and the verified contrast ratios are in
[Brand Manual §1 and §3.3](brand/12-brand-manual.md).

A verified accessibility note: teal **fails** on white (1.91:1) — use `#00695c`
on light backgrounds and in print.

### 6. ⚠️ A HIDRA token and MiCA

Under the MiCA regulation, an EU-based company that issues a token takes on a
significant regulatory burden, with an impact on timelines, compliance cost and
its relationship with banks.

It is not covered in these documents, by a scoping decision. **Obtain specialist
legal advice before any announcement or issuance.**

---

## State of the documents

| Category | State |
|---|---|
| Technical | ✅ Ready — verified against the code |
| Legal | ⚠️ Templates — **review by a lawyer is mandatory** |
| Corporate | ⚠️ Structural decisions open (points 2 and 3) |
| Security | ✅ Ready |
| Community | ✅ Ready |
| Brand | ⚠️ The unification decision is not yet applied |
| Internal | ✅ Ready — `[name]` fields to fill in |

**The legal documents are not legal advice.** They prepare the conversation with
a digital-law solicitor; they do not replace it. An anonymity network has
particularities a generalist lawyer does not cover.

---

## Conventions

- English throughout
- The legal documents remain governed by Portuguese law; where an official
  Portuguese version is produced, the contract must say which version prevails
- Fields in `[brackets]` are to be filled in
- ⚠️ marks a pending decision or a risk to handle
- Markdown, convertible to PDF/DOCX with `pandoc`

```bash
pandoc docs/technical/01-whitepaper.md -o whitepaper.pdf
```
