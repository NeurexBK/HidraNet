# Governance Guide — HidraNet

**Version 1.0 · September 2026**

---

## 1. The structuring principle: two separate things

HidraNet has two natures that **must not be conflated**:

```
┌────────────────────────────────┐   ┌────────────────────────────────┐
│  HidraNet, Lda                 │   │  The HidraNet protocol         │
│  (the company)                 │   │  (a common good)               │
├────────────────────────────────┤   ├────────────────────────────────┤
│ • Develops software            │   │ • MIT licence                  │
│ • Sells services (HidraReview) │   │ • Anyone may implement it      │
│ • Employs people               │   │ • Anyone may operate nodes     │
│ • Decides through management   │   │ • Decides by technical consensus│
│                                │   │                                │
│ ❌ Does NOT operate exit nodes │   │ • Operated by volunteers       │
│ ❌ Does NOT control the network│   │ • Nobody owns it               │
└────────────────────────────────┘   └────────────────────────────────┘
```

**Why it matters.** Whoever operates exit nodes on an anonymity network receives
abuse complaints and legal requests about traffic they neither control nor can
see. A young company should not carry that liability.

It is Tor's model and Proton's: the commercial entity makes software and sells
services; the network belongs to its participants.

**This separation is an architectural decision, not a communications one.** It is
reflected in the technical design: the company does not run exit nodes.

---

## 2. Company governance

### 2.1 Bodies

| Body | Composition | Authority |
|---|---|---|
| Shareholders' meeting | João Brandão, Leonardo Mello, investors | Structural decisions |
| Management | João Brandão, Leonardo Mello | Day-to-day management |
| Advisory board | To be formed after the round | Advice, with no binding power |

### 2.2 Founder roles

**To be formally assigned before the round.** An investor will ask who decides
what, and "we both decide everything" is not an answer.

| Function | Responsibility |
|---|---|
| **CEO** | Revenue, investors, applications, legal, hiring. Represents the company. |
| **CTO** | Product, engineering, architecture, security, audits. |

**A useful criterion for deciding who is who:** whoever has more appetite for
uncomfortable conversations — sales, investors, lawyers — should be CEO. It is
not necessarily whoever knows the product best.

**In the first year, both talk to customers.** A CTO who has never heard a
customer builds the wrong thing with great technical competence.

### 2.3 Decision matrix

| Decision | Who decides |
|---|---|
| Day-to-day operations | Whoever holds the function |
| Hiring up to [level] | CEO |
| Spending up to [€1,000] | Either founder |
| Spending above [€1,000] | Both |
| Price changes | Both |
| Technical architecture | CTO, having heard the CEO |
| **Security decisions** | **CTO has a veto** — see 2.4 |
| Senior hiring | Both |
| Investment round | Shareholders' meeting |
| Change of strategy | Both |
| Sale of the company | Shareholders' meeting |

### 2.4 Veto on security matters

**The CTO may veto the release of a feature that compromises users' security or
privacy, even under commercial or schedule pressure.**

A deliberate clause. In a privacy company, the temptation to ship before it is
safe is permanent and the consequences are irreversible: a publicly disclosed
flaw in a privacy browser destroys the trust that is the product's only real
asset.

The veto is recorded in writing, with reasons, and can be overridden only by a
unanimous decision of the shareholders' meeting — which thereby expressly assumes
the risk.

### 2.5 Tie-breaking mechanism

With two founders at 50/50, a disagreement locks up the company.

**Mechanisms to provide for in the shareholders' agreement** (pick one):

| Mechanism | How it works |
|---|---|
| **Asymmetric holding** | 52/48 — whoever holds more decides. See doc 02 §5. **Preferable.** |
| Casting vote by area | CEO breaks ties on commercial matters; CTO on technical |
| Independent third party | An adviser agreed by both decides in a deadlock |
| Shotgun clause | One names a price, the other chooses to buy or sell. A last resort. |

**Decide this now**, while it is an abstract conversation. Once there is a real
disagreement, a tie-breaking mechanism is no longer negotiable.

### 2.6 Meeting rhythm

| Meeting | Frequency | Participants | Record |
|---|---|---|---|
| Status check | Weekly, 30 min | Founders | Short minutes |
| Metrics review | Monthly | Team | Shared dashboard |
| Strategy review | Quarterly | Founders + advisers | Document |
| Shareholders' meeting | Annual + extraordinary | Shareholders | Formal minutes |
| Investor report | Quarterly | — | Written email |

> **Start the quarterly reports before you have investors.** It builds the habit,
> and when the first round comes there is already a track record — which impresses
> more than any presentation.

---

## 3. Open-source project governance

### 3.1 Current model

**Maintainer-led.** Appropriate to the stage: fast decisions, clear
responsibility.

| Role | Who | Powers |
|---|---|---|
| Maintainers | The founders | Final decision; merging changes |
| Contributors | The community | Propose changes, discuss, report |
| Node operators | Volunteers | Run their own infrastructure autonomously |

### 3.2 How a technical change is decided

```
Proposal (issue or RFC)
        ↓
Public discussion — minimum 7 days for structural changes
        ↓
Maintainers' opinion
        ↓
Implementation + peer review
        ↓
Merge
```

**Changes that require a written RFC:**
- A protocol change that breaks compatibility
- A change to cryptographic primitives
- A change that affects the threat model
- Removal of a feature

**Principle:** no change to the cryptographic core is merged without review by at
least two people, one of whom is the CTO.

### 3.3 Planned evolution of governance

| Phase | Model |
|---|---|
| Today | Maintainers (the founders) |
| >10 regular contributors | A technical committee with external members |
| >50 independent nodes | A formal community structure |
| Maturity | An independent foundation holding the protocol |

**A declared commitment:** as the network grows, protocol governance opens up. A
decentralised network governed indefinitely by two people is not decentralised —
it is centralised with extra steps.

---

## 4. Transparency

### 4.1 What we publish

| Document | Frequency |
|---|---|
| Transparency Report (authority requests, abuse reports) | Every six months |
| Security audit reports | When completed |
| Register of known limitations and vulnerabilities | Continuous |
| Changes to the Terms and the Privacy Policy | 30 days in advance |
| Development roadmap | Quarterly |

### 4.2 What we do not publish

- Data that identifies people
- Vulnerabilities not yet fixed (coordinated disclosure: 90 days or until fixed)
- Commercial information subject to contractual confidentiality

---

## 5. Conflicts of interest

The founders declare, in writing and annually:

- Holdings in other companies in the sector
- Relationships with suppliers, customers or competitors
- Positions in entities that may conflict

Where there is a conflict, the person affected does not take part in the
decision.

---

## 6. Relations with authorities

**A policy, defined calmly now, before it is needed:**

1. We respond to **legally valid** requests, in the applicable jurisdiction.
2. We provide **only what we have** — which is little, by design (see Privacy
   Policy §3).
3. We **notify the person concerned**, unless expressly prohibited by law.
4. We **contest requests we consider excessive or without legal basis.**
5. We record and publish the numbers in the Transparency Report.
6. **We do not build surveillance capabilities that do not exist.** A request to
   change the software so as to allow access to content is refused and, if
   necessary, contested in court.

Point 6 is the reason encryption happens in the client: it is not a revocable
policy, it is a property of the system.

---

## 7. Review

This guide is reviewed **annually** or whenever there is a relevant corporate
change. Current version: 1.0. Next review: [date].
