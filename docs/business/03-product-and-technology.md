# 03 — Product and Technology

**Rule for this document:** only what has been verified in the repository's code
goes in here. What is a plan is in section 5, marked as a plan. A deck that
presents roadmap as existing product does not survive technical due diligence.

---

## 1. What exists today (verified in the repository)

### 1.1 `hidra-node` — the engine, in Rust

~17,000 lines of Rust (2024 edition).

> **Correction to an earlier version of this document.** It said here that the
> engine "compiles clean, verified". **That was false**, and the verification was
> badly done: it trusted an exit code instead of reading the output. What was
> actually happening, established afterwards:
>
> - `disable_core_dumps()` is behind `#[cfg(target_os = "linux")]` and uses
>   `libc::prctl`, but `libc` was not in `Cargo.toml`. **On Linux the binary did
>   not compile.** On Windows and macOS the `cfg(not(linux))` variant applies,
>   which is why it went unnoticed — and why the `build:linux` target could never
>   have worked.
> - The four files in `tests/` do `use hidra_node::…`, but there was no library
>   target. **They never compiled and never ran.**
>
> Both fixed: `libc` declared as a Linux-only dependency, and `src/lib.rs`
> created to expose the module tree that already existed under `src/`.
>
> **Current state, verified by reading the output:** `cargo build` and
> `cargo check --all-targets` at zero errors; **`cargo test --all` with 71 tests,
> all passing** (41 unit + 30 integration). `cargo clippy` still fails on the
> binary — 26 stylistic warnings that `main.rs`'s `#![deny(warnings)]` turns into
> errors; they are not functional defects and are listed as technical debt.

| Component | State | Notes |
|---|---|---|
| Onion routing | Implemented | Circuit construction, cells, layers |
| Post-quantum cryptography | Implemented | **ML-KEM-1024** (`ml-kem`) |
| Classical cryptography | Implemented | X25519, Ed25519, ChaCha20-Poly1305, AES-GCM, BLAKE3, Argon2 |
| DHT (Kademlia) | Implemented | k-buckets, discovery, bootstrap |
| SOCKS5 proxy | Implemented | Gateway for the browser |
| Relay / registry / router | Implemented | |
| `.hidra` sites (SevenNine) | Implemented | Builder and hosting for hidden sites |
| HidraChat / HidraMail (engine) | Implemented | |
| Integration tests | **Passing** | 30 tests: `onion_routing`, `dht_discovery`, `key_agreement`, `integration` |

**Real technical differentiator:** onion routing combined with **ML-KEM-1024** in
production. Tor is moving towards post-quantum but HidraNet already has it in the
core. This is material for an NGI Zero Entrust application (the privacy and trust
fund) and is the strongest technical argument we have.

**Technical debt to declare (honesty in due diligence):** `main.rs` is ~9,600
lines with every module inlined, and a parallel `src/` tree exists with the same
modules in separate files. A fund's CTO will see this in five minutes. Better to
arrive with it already resolved, or declared as a known item with a date. See
[roadmap](08-roadmap.md), Q1.

### 1.2 `hidra-browser` — the browser, in Electron

~7,800 lines. It bundles Tor and adds layers of protection:

| Protection | State | Notes |
|---|---|---|
| Bundled Tor, with visible bootstrap | Implemented | Own manager, ports 9052/9053, cookie authentication |
| Independent exit IP verification | Implemented | Queries `check.torproject.org` — the browser **confirms** anonymity instead of asserting it |
| New identity (`SIGNAL NEWNYM`) | Implemented | Closes open connections and re-confirms the IP |
| Per-tab isolation | Implemented | Own in-memory session partition, wiped on close |
| Randomised fingerprint per tab | Implemented | Canvas, WebGL, audio, timezone, screen — internally consistent profiles |
| Client hints removed (`Sec-CH-UA-*`) | Implemented | |
| Cross-origin referer stripped | Implemented | Keeps same-origin, which is functional |
| DNS rebinding protection on the apps server | Implemented | `Host` and `Origin` checks |
| **Network kill switch** | **Implemented** | See 1.4 |

### 1.3 Applications

Served by the browser itself at `127.0.0.1:8090` (they do not depend on the
engine running — a sound decision, it reduces points of failure):

- **HidraSearch** — meta-search (DuckDuckGo + SearXNG), 109 languages, requests
  routed through Tor.
- **HidraChat** — E2E in the client, over a relay.
- **HidraMail** — network mail.
- **Forum**.
- **HidraReview** — business reviews, a `.hidra` address per business for NFC
  cards, owner notification over HidraMail, owner panel. **This is the
  commercial product.** See [04](04-business-model.md).
- **SevenNine** — publishing `.hidra` sites.

### 1.4 Known gap, now fixed: the IP leak window

Declared here out of honesty and because the fix is in place.

At startup the browser used to create and show the first tab while Tor was still
bootstrapping (20–40 s). During that window traffic left directly or through the
local engine — that is, **from the user's real IP** — while the panel said
"starting Tor". The same happened if Tor failed or died mid-session.

**Fixed.** The kill switch (`src/main/network-lock.js`) starts closed and only
opens when Tor reaches 100% bootstrap and the rules are applied to every session
— the default session and each tab's partition. It closes again on disconnect and
when Tor dies unasked. Anything that is not loopback, `file://`, `data:` or
`hidra://` is blocked until then, and a blocked navigation shows the user the
reason instead of a Chromium error.

Verified with the application running and Tor unavailable: the search API answers
`"Search is blocked until Tor is ready"`, and the local applications keep
serving.

**Why this is in the deck:** an investor with technical advice will look for
exactly this. Presenting the flaw already fixed, with the reasoning, shows
engineering maturity. Hiding it and being caught in due diligence kills the
round.

### 1.5 Distribution

- Landing page + PWA (`landing/`), free downloads.
- Packaging scripts for Windows, Linux and macOS.
- Operations panel (`hidra-monitor/`) with a node beacon.
- **MIT** licence — relevant: it is a prerequisite for NGI Zero eligibility.

---

## 2. The architecture, in one sentence for the deck

> A Rust engine that does onion routing with post-quantum cryptography, a browser
> that wraps Tor and randomises the fingerprint per tab, and a set of
> applications that gives the network a reason to exist — the first of them a
> reputation product for local business.

---

## 3. What differentiates us technically

1. **Post-quantum already in production** (ML-KEM-1024) — Tor does not have it yet.
2. **Verified anonymity, not asserted** — the browser checks its exit IP against
   the Tor Project's own verifier and, if it cannot confirm it, **says so**
   instead of lying to the user. A rare and defensible product choice.
3. **Per-tab isolation with a consistent fingerprint** — every tab is a different
   and internally coherent user (a Windows UA does not arrive with an Apple GPU).
4. **Integrated applications** — Tor Browser is only a browser. HidraNet brings
   search, mail, chat, forum and reviews onto the network.

---

## 4. What does *not* differentiate us (and has to be said)

- **The anonymity itself is Tor's**, not ours. The volunteer network that
  provides the real anonymity is the Tor Project's. Our own engine, with its
  relays pointed at `127.0.0.1` in the current configuration, encrypts in layers
  but exits from the user's own machine — it does not change the IP. The code
  already documents this correctly. **We cannot tell an investor that we have our
  own anonymity network running.** We have the protocol; we do not yet have the
  volunteers.
- **Electron** — an Electron browser has a ceiling on performance and a larger
  attack surface than a Firefox fork (Tor Browser, Mullvad Browser). It is a
  defensible choice for reaching the market quickly; it is a debt to acknowledge.

---

## 5. Plan (not yet built)

| Item | Why | When |
|---|---|---|
| A real relay network, with volunteers | Without it, "the HidraNet network" is protocol, not network | See roadmap |
| Split `main.rs` into modules | Technical debt visible in due diligence | Q1 |
| HidraReview as multi-tenant SaaS with billing | It is the revenue line | Q1–Q2 |
| `.hidra` domain registry | Recurring revenue line | Q2 |
| External security audit | A credibility requirement; NGI Zero offers one to grantees | Q2–Q3 |
| Mobile apps | Where the review user is | Q3–Q4 |

---

*Verifications made on 21 September 2026 against commit `da05f65` of the
NeurexBK/HidraNet repository.*
