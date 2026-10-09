# Information Security Policy — HidraNet

**Version 1.0 · September 2026 · Classification: Public**
Owner: CTO · Review: annual

---

## 1. Scope and principle

This policy applies to all employees, service providers and systems of HidraNet,
Lda.

**Guiding principle: the best way to protect data is not to have it.**

HidraNet's architecture deliberately minimises collection. It is not a compliance
measure bolted on at the end — it is the design decision from which everything
else follows. Data that does not exist cannot be stolen, leaked or demanded.

---

## 2. Information classification

| Level | Definition | Examples | Rule |
|---|---|---|---|
| **Public** | Disclosure carries no risk | MIT source code, whitepaper, policies | Open |
| **Internal** | Internal use | Roadmaps, minutes, metrics | Team only |
| **Confidential** | Harm if disclosed | Customer data, contracts, cap table | Need to know |
| **Critical** | Serious harm | Signing keys, credentials, unfixed vulnerabilities | Named, logged access |

---

## 3. What we do not hold

Stated expressly, because it is the core of the security model:

| | Why |
|---|---|
| ❌ Users' private keys | Generated and held on the device |
| ❌ Message content | Encrypted in the client, before it leaves |
| ❌ Browsing history | Not collected |
| ❌ Search queries | Not logged |
| ❌ Browser users' IPs | Not logged |

**A deliberate consequence:** we cannot hand over what is asked of us about these
items, neither under a court order, nor through a compromise of our systems, nor
by our own mistake.

---

## 4. Development security

### 4.1 Code

| Control | Rule |
|---|---|
| Peer review | Mandatory before merging |
| Cryptographic core | **At least two people**, one of them the CTO |
| Main branch | Protected; no direct writes |
| Dependencies | Pinned by version and integrity-checked |
| Automated analysis | Run on every change |
| Secrets in the repository | **Prohibited**, with automated checking |

### 4.2 Rules on dependencies

Three rules, which exist because the alternative is handing the product to third
parties:

1. **No runtime dependency loaded from an external CDN in code that handles
   cryptographic material or user content.** Libraries are shipped inside the
   application package.
2. Versions **pinned exactly**, never by range.
3. A dependency change requires review like any other code change.

> **Status: met.** The applications used to load `mqtt` from `unpkg.com` with no
> integrity check and with a version range (`@5`). They now serve `mqtt` 5.16.0
> and `qrcode-generator` 1.4.4 from the package itself, with exact versions in
> `package.json`, served through a fixed-allowlist route.

### 4.3 Cryptography

| Rule | |
|---|---|
| Do not implement your own primitives | Use established, audited libraries |
| Approved algorithms | ML-KEM-1024, X25519, Ed25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE3, SHA-256, Argon2id |
| Prohibited | MD5, SHA-1, DES, 3DES, RC4, AES-ECB |
| Randomness | Cryptographic generators only (`getRandomValues`, `OsRng`) |
| Password derivation | **Argon2id** with a unique salt per user or context |
| Key material in memory | Wiped after use (zeroize) |

---

## 5. Operational security

### 5.1 Access

| Control | Rule |
|---|---|
| Multi-factor authentication | **Mandatory** on every system |
| Password manager | Mandatory; no sharing over text channels |
| Least privilege | Access only to what the role needs |
| Access review | Quarterly |
| Revocation on departure | **Same day** |
| Release signing keys | In a hardware module or equivalent |

### 5.2 Devices

- Full-disk encryption mandatory
- Automatic lock after 5 minutes
- Security updates within 7 days
- No customer data on personal devices
- Loss or theft reported **immediately**

### 5.3 Infrastructure

| Control | |
|---|---|
| Encryption in transit | TLS 1.3, HSTS |
| Encryption at rest | On every system holding customer data |
| Backups | Daily, encrypted, **with restores tested quarterly** |
| Administrative access logs | Retained 12 months |
| Vulnerability remediation | Critical within 7 days; high within 30 |
| Environment separation | Production separate from development |

> A backup whose restore has never been tested is not a backup — it is an
> assumption.

---

## 6. Responsible vulnerability disclosure

### 6.1 How to report

**security@hidranet.org** · PGP key published at `/.well-known/security.txt`

Include: a description, reproduction steps, the impact and, if possible, a
suggested fix.

### 6.2 Our commitment

| Timeframe | Action |
|---|---|
| 48 hours | We acknowledge receipt |
| 7 days | Initial assessment and classification |
| 90 days | A fix, or a written justification for the delay |
| On the fix | Public credit, unless anonymity is requested |

**We undertake to:**
- Take no legal action against anyone researching in good faith who respects
  these rules
- Keep the researcher informed of progress
- Publish the vulnerability after it is fixed

**We ask that you:**
- Do not access or alter third-party data
- Do not degrade the service
- Give us a reasonable period before disclosing

After 90 days without a fix, coordinated disclosure by the researcher is
legitimate and we will not contest it.

### 6.3 Scope

**In scope:** hidranet.org, HidraNet Browser, hidra-node, the applications, the
API.
**Out of scope:** third-party services, social engineering of employees, physical
attacks, volumetric denial of service.

---

## 7. Public register of known limitations

**We keep a public register of known security limitations and the state of their
remediation.**

It is unusual and it is deliberate. In a security tool, the relevant question is
not "are there vulnerabilities?" — there always are. It is **"who is looking for
them and what happens when they are found?"**. A project with no register of
limitations is saying it does not look.

The register distinguishes:
- **Inherent limitations** — of the threat model, not fixable (e.g. an adversary
  with global observation of the network defeats any low-latency network)
- **Limitations being fixed** — with a deadline
- **Fixed** — with a date and version

---

## 8. Hardening plan

Public, because credibility is measured by what you promise to fix and then fix.

| # | Item | Priority | Status |
|---|---|---|---|
| 1 | Block non-loopback traffic until the anonymity layer is ready | Critical | ✅ **Done** |
| 2 | Third-party libraries shipped locally, with integrity verified | Critical | ✅ **Done** |
| 3 | Encryption at rest for key material on the device | Critical | Planned |
| 4 | Sender authentication in HidraMail | High | Planned |
| 5 | WebRTC blocked at the network level | High | ✅ **Done** |
| 6 | Our own message transport infrastructure | High | Planned |
| 7 | Profile injection at document start, in every frame | High | Planned |
| 8 | Argon2id with a per-context salt in HidraChat | Medium | Planned |
| 9 | **Independent external security audit** | High | Planned |

**Item 9 is a condition for broad public release of the browser.** We do not
announce a privacy tool to a wide audience before somebody outside has tried to
break it and we have published the result.

---

## 9. Training

| When | Content |
|---|---|
| On joining | This policy, classification, password manager, MFA |
| Quarterly | Current threats, real cases |
| Annually | Full review and a phishing simulation |

---

## 10. Breach of this policy

Breach of this policy is treated as a disciplinary matter, which may lead to
termination and, where an offence has been committed, a report to the
authorities.

**Reporting your own mistake is never sanctioned.** An incident reported in 10
minutes is manageable; one hidden for a week may not be. We want the team to
report early, and that requires reporting to cost nothing.

---

## 11. Related documents

- Incident Response Plan (document 15)
- Privacy Policy (document 04)
- Whitepaper, section 5 — threat model
- `/.well-known/security.txt`

---

**security@hidranet.org** · Reviewed annually · Approved by: CTO
