# Onboarding Handbook — HidraNet

**For new team members** · Version 1.0

---

## Welcome

This handbook covers the first week. If anything here is wrong or missing,
**fix it** — it is a document by the team, not a document about the team.

---

## 1. What we do, in two minutes

HidraNet builds private communication infrastructure: a decentralised network
with post-quantum cryptography, a browser, and applications that encrypt on the
user's device.

**One thing to understand before anything else:**

> The people who use this may be depending on it.

We do not know who they are — by design, we cannot know. They may be
journalists, they may be ordinary people who simply do not want to be watched. A
mistake of ours does not produce an incident report: it can produce real
consequences for someone.

This is not to create anxiety. It is to explain why we are meticulous about
things that at other companies would be details.

---

## 2. Our principles

### 2.1 Not collecting beats protecting

Data that does not exist cannot be stolen, leaked or demanded by anyone. Before
adding a field, a metric or a log, the question is: **do we actually need this?**
The default answer is no.

### 2.2 Under-promise, always

We never assert guarantees we have not verified. "100% anonymous" is not written
here — not in marketing, not in the interface, not in a conversation.

If someone trusts an exaggerated promise and suffers consequences, the
responsibility lies with whoever exaggerated.

### 2.3 Honesty about limitations is a feature

The browser tells the user when it **cannot** confirm anonymity. It is the
product decision that best defines this company. When you have to choose between
looking competent and being accurate, choose accurate.

### 2.4 Reporting mistakes early is never sanctioned

An incident reported in 10 minutes is manageable. One hidden for a week may not
be.

**If you make a mistake, say so immediately.** There has never been and will
never be a disciplinary consequence for reporting your own mistake. There is one
for hiding it.

### 2.5 Neutrality

We are a technical tool. We do not engage in political confrontation and do not
position ourselves against governments. We defend privacy in technical and legal
terms — it is a recognised right, and that is enough.

---

## 3. First day

### Checklist

- [ ] Contract signed, including the **intellectual property assignment**
- [ ] NDA signed
- [ ] Password manager installed and configured
- [ ] **Multi-factor authentication enabled everywhere** — no exceptions
- [ ] Disk encryption confirmed on the machine
- [ ] Access granted (least privilege)
- [ ] Read: Code of Conduct, Information Security Policy
- [ ] Introduction to the team

### Required reading for the first week

| Order | Document | Why |
|---|---|---|
| 1 | Technical Whitepaper, **especially section 5** | The threat model is what defines what counts as a mistake |
| 2 | Information Security Policy | The working rules |
| 3 | Code of Conduct | How we treat each other |
| 4 | Contributing Guide, **section 6** | The non-negotiable rules |
| 5 | Brand Manual, **section 7** | How we talk about the product |
| 6 | Incident Response Plan | Before you need it |

> **If you read only one thing:** Whitepaper §5.2 — what we do **not** protect
> against. It is what distinguishes a privacy professional from someone who
> thinks cryptography solves everything.

---

## 4. Development environment

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet

# Engine (Rust ≥ 1.80)
cd hidra-node
cargo build && cargo test

# Browser (Node ≥ 20)
cd ../hidra-browser
npm install
npm run fetch-tor
npm start
```

**Suggested first task:** install the browser, use it for a day as an ordinary
user, and write down what annoyed you. Fresh eyes see what we have stopped
seeing. That list is welcome, not presumptuous.

---

## 5. How we work

### 5.1 Rhythm

| When | What |
|---|---|
| Monday, 10:00 | Status check (30 min) |
| Daily | A written, asynchronous update |
| Monthly | Metrics review |
| Quarterly | Strategy review |

**Asynchronous by default.** Meetings are expensive; call one when written
discussion is not resolving it.

### 5.2 Code

- Branch from `main`
- Conventional Commits — see Contributing Guide §5.3
- Review mandatory before merging
- **Cryptography and protocol: two reviews, including the CTO**
- `cargo fmt`, `clippy` with no warnings, and tests before submitting

### 5.3 The rules that do not bend

| ❌ Never |
|---|
| Telemetry or analytics that identifies users |
| External dependencies loaded at runtime in cryptographic code |
| Cryptographic primitives implemented from scratch |
| Logging of user content — **not even for debugging** |
| Secrets in the repository |
| Customer data on personal devices |

If a task seems to require one of these, **stop and ask**. It is not bureaucratic
obstruction: it is probably a sign that the problem has another solution.

---

## 6. Who is who

| Role | Who | Go to them for |
|---|---|---|
| CEO | [name] | Strategy, customers, investors, legal |
| CTO | [name] | Architecture, security, technical decisions |

**A useful rule:** ask early. A question asked after 20 minutes costs 20 minutes.
Asked after two days, it costs two days.

---

## 7. Channels

| Channel | Use |
|---|---|
| [Internal chat] | Day-to-day conversation |
| GitHub Issues | Technical work |
| GitHub Discussions | Proposals and open discussion |
| security@hidranet.org | **Vulnerabilities — always through here** |
| conduct@hidranet.org | Code of Conduct violations |

---

## 8. First 30 days

### Week 1 — Understand
- [ ] Required reading
- [ ] Environment working
- [ ] Use the product as a user
- [ ] First small contribution merged (documentation counts)

### Week 2 — Contribute
- [ ] First real task
- [ ] Review someone else's code
- [ ] Understand your area in depth

### Weeks 3–4 — Autonomy
- [ ] A task with autonomy
- [ ] Propose an improvement of your own
- [ ] A review conversation with your manager

### At 30 days

A two-way conversation. We ask how it went and what we would improve in the
onboarding; we want to hear what did not make sense.

**At 30 days you still have the advantage of seeing the company from outside. Use
it before it fades.**

---

## 9. Terms

| | |
|---|---|
| Hours | Flexible; a few hours of overlap for joint work |
| Location | [Remote / hybrid / Lisbon] |
| Holiday | [days] |
| Equipment | Provided, with mandatory disk encryption |
| Training | An annual budget — discuss with your manager |
| **Stock options** | Subject to eligibility — **ask for document 16 and read it** |

> **On the options:** if you are granted any, you will receive in writing the
> number, the exercise price, the vesting schedule and the company total. If any
> of those is missing, ask for it. An option whose holder does not know what it
> represents is worth nothing as an incentive — and that would be our fault, not
> yours.

---

## 10. Frequently asked questions

**What if I break something?**
It happens. Say so immediately, fix it, and then we work out what in the system
allowed it. We do not look for culprits — we look for the cause.

**Can I use AI to write code?**
Yes, on two conditions: you review everything you submit, and **never paste
generated cryptographic code without review by two people**. Responsibility for
the code lies with whoever submits it.

**Can I talk publicly about my work?**
About what is public (MIT code, documentation), yes. About an unpublished
roadmap, unfixed vulnerabilities or commercial information, no — see the NDA.
Where in doubt, ask.

**Can I contribute to other open-source projects?**
Yes, and it is encouraged. Just confirm there is no conflict of interest.

**I disagree with a technical decision.**
Say so. In writing, with your reasoning. Reasoned disagreement is what stops bad
decisions from setting. If the decision stands, we move on — but the argument is
on the record.
