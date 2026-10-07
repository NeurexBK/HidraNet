# Contributing Guide — HidraNet

Thank you for your interest. This guide tells you how to contribute in a way that
gets your work merged quickly.

---

## 1. Before you start

| I want to… | Start at… |
|---|---|
| Report a bug | §3 |
| **Report a vulnerability** | **§2 — do not open a public issue** |
| Propose a feature | §4 |
| Submit code | §5 |
| Translate | §7 |
| Run a node | The Installation Guide |
| Improve documentation | §5 — one of the most useful contributions |

---

## 2. ⚠️ Security vulnerabilities

**Never report a vulnerability in a public issue.**

📧 **security@hidranet.org** · PGP key at `/.well-known/security.txt`

Include a description, reproduction steps, the impact and, if possible, a
suggested fix.

**Our commitment:** a response within 48h, an assessment within 7 days, a fix or
a justification within 90 days, public credit on the fix, and **no legal action
against good-faith research**. The detail is in the Information Security Policy.

---

## 3. Reporting a bug

First check whether an issue about the same thing is already open.

```markdown
**Description**
What happens.

**To reproduce**
1. …
2. …

**Expected / Observed**
What should happen / what happened.

**Environment**
- Operating system:
- HidraNet version:
- Component: browser / node / HidraMail / HidraChat / …

**Logs**
If applicable. ⚠️ REMOVE personal data, @hidra addresses and keys.
```

> **An important warning.** Before pasting logs, remove addresses, IPs and any
> key material. A log pasted into a public issue is indexed forever.

---

## 4. Proposing a feature

Open an issue with the `enhancement` label, explaining **the problem** before the
solution. Proposals that describe a solution without the problem are hard to
assess.

### Proposals that require an RFC

Structural changes require a written document and **7 days** of public
discussion:

- A protocol change that breaks compatibility
- A change to cryptographic primitives
- A change that affects the threat model
- Removal of a feature

---

## 5. Contributing code

### 5.1 Setting up

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet

# Engine (Rust ≥ 1.80)
cd hidra-node && cargo build && cargo test

# Browser (Node ≥ 20)
cd ../hidra-browser && npm install && npm run fetch-tor && npm start
```

### 5.2 Workflow

```bash
git checkout -b fix/short-description
# … changes …
cd hidra-node && cargo fmt && cargo clippy -- -D warnings && cargo test
git commit -m "fix(onion): fix circuit leak on close"
git push -u origin fix/short-description
```

### 5.3 Commit messages

Conventional Commits format:

```
<type>(<scope>): <description in the imperative>

<body: why, not what — the diff already shows the what>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `security`.
Scopes: `onion`, `dht`, `relay`, `proxy`, `crypto`, `browser`, `mail`, `chat`,
`search`, `review`, `sevennine`.

**A good message:**
```
fix(browser): block traffic until Tor is ready

At startup the first tab was created while Tor was still bootstrapping,
and for 20-40s traffic left from the real IP while the panel said
"starting". Inverts the default: blocked until confirmed.
```

**A bad message:** `update code`, `fix bug`, `changes`.

### 5.4 Style

**Rust:** `cargo fmt`, `clippy` with no warnings, no `unwrap()` in production
code (use `?` or handle the error), documentation on public items.

**JavaScript:** 2 spaces, single quotes, semicolons, `const`/`let`,
`async`/`await`.

**Comments.** Write **why**, not what. The code already says what. A good comment
explains the reason for a non-obvious decision — especially when it documents a
mistake already made.

### 5.5 Tests

| Change | Requirement |
|---|---|
| Bug fix | A test that fails before and passes after |
| Feature | Tests for the main cases and the edges |
| **Cryptography** | **Known test vectors** + review by two people |
| Documentation | No tests |

### 5.6 Review

| Type | Reviewers |
|---|---|
| Documentation | 1 |
| Fix or feature | 1 |
| **Cryptography or protocol** | **2, including the CTO** |

Usual turnaround: 3 working days for a first response. If a week passes with no
response, comment on the PR — it is not disinterest, it is lack of availability.

---

## 6. Non-negotiable rules

| Rule | Why |
|---|---|
| **No telemetry or analytics that identifies users** | It contradicts the project's reason to exist |
| **No external dependency loaded at runtime in cryptographic code** | It hands the product to a third party |
| **No cryptographic primitives implemented from scratch** | Use established libraries |
| **No logging of user content** | Not even for debugging |
| Dependencies pinned to exact versions | Reproducibility and the supply chain |

Contributions that break these rules are refused, regardless of technical
quality.

---

## 7. Translations

The project started in Portuguese and is international in intent. Translations
are welcome — priority for **Spanish** and **French**.

Files in `locales/`. Keep technical terms consistent; where in doubt, open an
issue instead of deciding alone.

---

## 8. Licence

By contributing, you accept that your contribution is licensed under **MIT**, the
project's own licence.

Substantial contributions may require a **Contributor Licence Agreement (CLA)**.
It is not to appropriate your work — it is so the project can, if necessary,
change licence or defend itself legally without having to track down hundreds of
contributors.

---

## 9. Community

The **Code of Conduct** (document 11) applies in all the project's spaces.

| Channel | Use |
|---|---|
| GitHub Issues | Bugs and features |
| GitHub Discussions | Questions and ideas |
| security@hidranet.org | Vulnerabilities |
| conduct@hidranet.org | Code of Conduct violations |

---

## 10. Quick reference

**Security vulnerabilities:** do **not** open a public issue. Email
**security@hidranet.org** (PGP key at `/.well-known/security.txt`). We respond
within 48h, assess within 7 days, fix or explain within 90 days, credit you
publicly, and **will not pursue legal action against good-faith research**.

**Setup:**
```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-node && cargo build && cargo test
cd ../hidra-browser && npm install && npm run fetch-tor && npm start
```

**Workflow:** branch from `main`, use Conventional Commits, run `cargo fmt`,
`cargo clippy -- -D warnings` and `cargo test` before pushing, open a PR.

**Review:** 1 reviewer for docs and ordinary changes; **2 including the CTO for
cryptography or protocol changes**.

**Non-negotiable rules:** no user-identifying telemetry · no runtime external
dependencies in cryptographic code · no hand-rolled cryptographic primitives ·
no logging of user content · exact-pinned dependencies.

**Licence:** contributions are licensed under **MIT**. Substantial contributions
may require a CLA.

Issues and pull requests in any language are read, but English keeps the
discussion open to everyone.
