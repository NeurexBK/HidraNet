# 15 — Data Room (due diligence)

What an investor will ask for after saying "we are interested". Assemble it
**before** you need it: a data room ready in 24 hours conveys competence; three
weeks gathering documents conveys the opposite and cools the round.

Suggested structure in numbered folders, on a shared drive with access control.

---

## 01 — Corporate
- [ ] Permanent commercial certificate
- [ ] Articles of association (current version)
- [ ] Shareholders' agreement between founders
- [ ] **Cap table**, current, with vesting made explicit
- [ ] Board minutes
- [ ] Beneficial ownership register (RCBE)
- [ ] Register of beneficial owners

## 02 — Financial
- [ ] Accounts for closed financial years
- [ ] Trial balances for the current year
- [ ] Financial model with editable assumptions ([07](07-financial-projections.md))
- [ ] Bank statements (12 months)
- [ ] Tax and social security clearance certificates
- [ ] Debt schedule, if any

## 03 — Commercial
- [ ] Customer list (anonymised if necessary)
- [ ] Standard customer contract
- [ ] **Churn cohort by month of entry** ← what they will analyse most
- [ ] CAC per channel
- [ ] MRR and its evolution
- [ ] Pipeline

## 04 — Product and technology
- [ ] Repository access (or a code audit)
- [ ] Architecture documentation
- [ ] **Open-source licence inventory**
- [ ] **Security audit report**
- [ ] Roadmap ([08](08-roadmap.md))
- [ ] Incident log (including the IP leak window and its fix — see the note below)

## 05 — Intellectual property
- [ ] **Founders' IP assignment** ← an absolute blocker if missing
- [ ] Contractor and freelancer IP assignments
- [ ] Trade mark registration (INPI / EUIPO)
- [ ] Registered domains

## 06 — Legal and compliance
- [ ] Terms and Conditions
- [ ] Privacy Policy
- [ ] Content Policy
- [ ] **Record of processing activities (GDPR art. 30)**
- [ ] DPIA
- [ ] Processor contracts
- [ ] Data breach procedure
- [ ] Insurance policies
- [ ] Legal opinion on regulatory risk ([10](10-legal-and-regulatory-risk.md))

## 07 — Team
- [ ] Employment and service contracts
- [ ] Organisation chart
- [ ] ESOP plan, if any
- [ ] Confidentiality agreements

## 08 — Prior funding
- [ ] Grant agreements (NGI Zero, etc.)
- [ ] Progress reports delivered
- [ ] Any convertible instruments issued

---

## A note on the incident log

Include the IP leak window described in
[03 §1.4](03-product-and-technology.md), with dates, analysis and the fix.

Handing an investor a list of your own failures looks counter-intuitive. It is
not. In a privacy company, the question is not *"have you had failures?"* — it is
*"how do you find and fix failures?"*. A log showing a flaw found internally,
understood and fixed before the public launch answers that question better than
any assertion.

A security company with no incident log is saying it does not look.

---

## The five questions they will ask

Prepare the answers in writing, beforehand:

1. **"Show me the churn cohort."** — If there are not 3 months of data, it is too
   early for this conversation.
2. **"Who owns the code?"** — Correct answer: the company, by written assignment.
3. **"What happens if Google launches this?"** — The moat is the network and data
   ownership, not the NFC.
4. **"What is your exposure to Chat Control?"** — [10 §2](10-legal-and-regulatory-risk.md).
5. **"Why is this two companies?"** — [04 §5](04-business-model.md) and slide 7.
