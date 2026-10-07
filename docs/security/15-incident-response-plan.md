# Incident Response Plan — HidraNet

**Version 1.0 · September 2026**
Owner: CTO · Tested: every six months

---

## 1. How to use this document

In a real incident, go straight to what you need:

| Situation | Section |
|---|---|
| It is happening now — what do I do first? | **§2 — The first 15 minutes** |
| How severe is it? | §3 |
| Who do I contact? | §4 |
| Personal data breach — legal deadlines | §6 |
| Vulnerability reported by an external researcher | §7 |
| What to say publicly | §8 |

**Print this document.** An incident response plan reachable only on the system
that is compromised is not a plan.

---

## 2. The first 15 minutes

### Step 1 — Do not switch anything off yet

**Isolate, do not destroy.** Switching off a compromised system wipes volatile
memory, which is the main source of evidence about what happened.

- Take the system off the network (unplug the cable, or a firewall rule)
- **Do not reboot**
- **Do not delete files**
- Do not sign in to the affected system with privileged credentials

### Step 2 — Keep a log

Open a log file (on another machine) and note, with the time:

```
[HH:MM] What I observed:
[HH:MM] What I did:
[HH:MM] What I saw as a result:
```

Log it **while you act**. Reconstructing afterwards is always incomplete, and it
is precisely what the data protection authority will ask for.

### Step 3 — Tell the other person

Contact the other founder immediately. **No incident is handled by one person
alone.** Whoever is responding loses perspective; whoever arrives from outside
asks the questions that are missing.

### Step 4 — Classify

See §3. The classification determines the deadlines.

---

## 3. Severity classification

| Level | Criterion | Response | Communication |
|---|---|---|---|
| **P0 — Critical** | Signing keys compromised · Actively exploited vulnerability that de-anonymises users · Supply chain compromise | **Immediate, everything else stops** | Public within 24h |
| **P1 — High** | Customer data exposed · Critical vulnerability with no known exploitation · Unauthorised access to production | 4 hours | Those affected within 72h |
| **P2 — Medium** | Vulnerability with no direct user impact · Prolonged outage | 24 hours | As relevant |
| **P3 — Low** | Theoretical vulnerability · Configuration problem with no exposure | 7 days | Release notes |

### Classification when in doubt

**Classify upwards.** A P2 treated as a P1 costs a few hours; a P1 treated as a
P2 can cost the project. Reclassifying downwards is always possible once it is
better understood.

---

## 4. Roles

With a small team, one person holds several roles. What cannot happen is for
nobody to hold a role.

| Role | Who | Responsibility |
|---|---|---|
| **Coordinator** | CTO (deputy: CEO) | Decides, coordinates, keeps the log |
| **Technical** | CTO | Containment, analysis, fix |
| **Communications** | CEO | Users, customers, press |
| **Legal** | CEO + external lawyer | Authorities, legal obligations |

**Emergency contacts** (keep current and available offline):

| | Contact |
|---|---|
| CTO | [phone] |
| CEO | [phone] |
| Lawyer | [name, phone] |
| CNPD | www.cnpd.pt |
| Hosting | [24h support] |

---

## 5. Phases of the response

### 5.1 Detection

Possible sources: monitoring, a user report, an external researcher, a
communication from an authority, or the team's own observation.

### 5.2 Containment

**Immediate:**
- Isolate affected systems
- Revoke compromised credentials
- Block suspicious access
- If there is active risk to users, **consider withdrawing the affected version
  from distribution**

**Over time:**
- Fix the cause
- Restore from a verified backup
- Rotate every related credential

### 5.3 Eradication and recovery

1. Identify the root cause — not just the symptom
2. Fix and test
3. Verify that the attacker's access has been eliminated
4. Restore the service
5. Monitor more closely for 30 days

### 5.4 Post-incident review

**Mandatory for P0 and P1, within 7 days.** A document with:

- A timeline of the facts
- The root cause
- Impact: what was affected, how many people
- What went well
- What went badly
- Corrective actions, with an owner and a deadline

**No individual blame.** A review that looks for culprits teaches the team to
hide incidents, which guarantees the next one will be worse. What is being looked
for is what in the system allowed the mistake.

---

## 6. Personal data breach

### 6.1 Legal deadlines

```
      Becoming aware of the breach
                │
                ├── Assess the risk to data subjects ── immediately
                │
                ├── Notify the CNPD ──────────────────── 72 HOURS
                │   (if there is risk to rights and freedoms)
                │
                └── Notify the data subjects ─────────── without delay
                    (if the risk is HIGH)
```

**The 72 hours run from awareness, not from confirmation.** If you do not have
all the elements, notify with what you have and complete it later — phased
notification is expressly permitted. Missing the deadline is a separate
infringement.

### 6.2 Content of the notification to the CNPD

1. The nature of the breach, the categories and approximate number of data
   subjects and records
2. The controller's contact (or the DPO's, if appointed)
3. The likely consequences
4. The measures adopted or proposed, including mitigation

### 6.3 Notification to data subjects

In clear, plain language, stating:
- What happened
- Which data was affected
- What we did
- **What the person should do**
- Where to get more information

### 6.4 Exemption from notifying data subjects

Where the data was encrypted in a way that renders it unintelligible. **This is
the practical effect of client-side encryption:** content we do not hold in the
clear does not constitute a notifiable breach, because it is not intelligible to
whoever obtains it.

### 6.5 Brazil (LGPD)

Where there are data subjects in Brazil, notify the ANPD within a reasonable
period, under Article 48 LGPD.

---

## 7. Externally reported vulnerability

| Timeframe | Action |
|---|---|
| 48 hours | Acknowledge receipt |
| 7 days | Assess, classify, inform the researcher |
| According to severity | Fix (P0: days; P1: 30 days; P2: 90 days) |
| On the fix | Publish, credit the researcher |
| 90 days | Disclosure, fixed or not, with justification if not fixed |

**Rule of conduct:** we treat whoever reports as an ally, not as a threat.
Threatening a good-faith researcher with legal action is, besides being wrong,
the fastest way to guarantee that the next vulnerability is published with no
warning.

---

## 8. Public communication

### 8.1 Principles

1. **Communicate early**, even without all the answers
2. **Do not minimise.** If users are at risk, say so clearly
3. **Say what the person should do** — that is the part that matters to them
4. **Update** as more is known
5. **Never state "no data was affected"** before having verified it

### 8.2 What not to do

| ❌ | Why |
|---|---|
| Wait until you have the whole story | Silence is read as a cover-up |
| Vague language ("a security incident") | Erodes trust more than the incident itself |
| Blame third parties | The responsibility to the user is ours |
| Promise what cannot be guaranteed | |

### 8.3 Initial communication template

```markdown
# Security incident — [date]

## What happened
[A factual description, without unnecessary jargon.]

## Who is affected
[Who, how many, which data.]

## What we have already done
[Concrete actions, with times.]

## What you should do
[Clear, actionable instructions.]

## What we are going to do
[Next steps and when we will update.]

## Contact
security@hidranet.org

*Last updated: [date and time]*
```

---

## 9. Specific scenarios

### 9.1 Signing key compromised — P0

1. **Revoke immediately** and announce publicly
2. Withdraw from distribution every version signed with that key
3. Generate a new key in a hardware module
4. Re-sign and republish, with new checksums
5. **Tell all users to verify before updating**
6. Public post-incident review

### 9.2 Vulnerability that de-anonymises users — P0

1. Assess active exploitation
2. If active: **warn publicly before a fix exists** — people need to know so they
   can stop using it
3. Fix and publish
4. A clear note in the release notes
5. A detailed report after the fix

> This is the hardest scenario: warning without an available fix gives the
> attacker information. **But the user has a right to know they are at risk.** The
> decision leans towards warning.

### 9.3 Supply chain compromise — P0

1. Withdraw all packages immediately
2. A prominent public warning on the website
3. Verify the integrity of every artefact
4. Rebuild from verified source, in a clean environment
5. Republish with new checksums
6. Explicit verification instructions

### 9.4 Request from an authority

1. **Do not answer immediately.** Forward it to the CEO and the lawyer
2. Verify legal validity and jurisdiction
3. Determine what we actually hold (see Privacy Policy §3 — normally very
   little)
4. Contest it if excessive or without legal basis
5. Notify the person concerned, unless prohibited by law
6. Record it for the Transparency Report

**Never:** modify the software to create an access capability that does not
exist. A request of that kind is refused and, if necessary, contested in court.

---

## 10. Testing

| Test | Frequency |
|---|---|
| Tabletop exercise | Every six months |
| Backup restore test | Quarterly |
| Verification of emergency contacts | Quarterly |
| Phishing simulation | Annually |
| Review of this plan | Annually or after every P0/P1 |

**A plan that has never been tested is a document, not a plan.** The first
exercise always reveals that contacts are missing, that nobody knows where the
emergency credentials are, and that the coordinator is on holiday.

---

## 11. Incident register

| Date | Severity | Description | Status | Review |
|---|---|---|---|---|
| | | | | |

*To be kept current. Include minor incidents too — the pattern over time is more
informative than any single incident.*
