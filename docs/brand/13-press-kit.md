# Press Kit — HidraNet

**Updated: September 2026** · https://hidranet.org/press
Contact: **press@hidranet.org**

---

## 1. Descriptions — use whichever fits

### One line (90 characters)
> HidraNet: an open-source decentralised network with post-quantum cryptography.

### Short (280 characters)
> HidraNet is an open-source decentralised network with post-quantum
> cryptography. Browser, chat, mail, search and sites — private by design. If we
> cannot confirm you are anonymous, we tell you.

### Medium (one paragraph)
> HidraNet is an open-source overlay network that combines onion routing with
> quantum-resistant cryptography (CRYSTALS-Kyber-1024). It includes a browser
> with per-tab isolation and fingerprinting protection, and applications for
> messaging, mail, search, forums and site publishing — all encrypted on the
> user's device. Founded in Lisbon by João Brandão and Leonardo Mello, it is
> distributed under the MIT licence.

### Long (corporate)
> HidraNet is an open-source project building private communication
> infrastructure. The network combines onion routing — in which traffic crosses
> several nodes and none knows both the origin and the destination — with
> CRYSTALS-Kyber-1024, the key encapsulation algorithm standardised by NIST to
> resist cryptanalysis by a quantum computer.
>
> On that base run applications that encrypt on the user's device: HidraChat,
> HidraMail with self-certifying addresses, a forum, meta-search with no query
> logging, and SevenNine, for publishing sites reachable without revealing where
> they are hosted.
>
> The HidraNet Browser gives each tab an isolated session and its own
> fingerprint profile, and verifies the exit address against the Tor Project's
> independent checker — telling the user when it **cannot** confirm it, instead
> of asserting an unverified anonymity.
>
> The software is distributed under the MIT licence. The company develops
> software and provides services; the network is operated by independent
> participants.
>
> Founded in 2026 in Lisbon, Portugal, by João Brandão and Leonardo Mello.

---

## 2. Reference facts

| | |
|---|---|
| Founded | 2026 |
| Headquarters | Lisbon, Portugal |
| Founders | João Brandão, Leonardo Mello |
| Licence | MIT |
| Repository | github.com/NeurexBK/HidraNet |
| Website | hidranet.org |
| Platforms | Windows, macOS, Linux |
| Engine | Rust · ~17,000 lines |
| Cryptography | Kyber-1024, X25519, Ed25519, ChaCha20-Poly1305, AES-256-GCM, BLAKE3, Argon2 |

---

## 3. What makes HidraNet newsworthy

Three angles, with the honest framing of each.

### 3.1 Post-quantum, already implemented

HidraNet uses **CRYSTALS-Kyber-1024** in production. It answers the *harvest now,
decrypt later* attack: traffic captured today and stored stays unreadable when a
cryptographically relevant quantum computer exists.

*Framing:* most privacy tools are still in transition to post-quantum.

### 3.2 Anonymity verified, not asserted

The browser queries the Tor Project's checker and, **when it cannot confirm,
tells the user**.

*Why that is unusual:* the industry standard is to show "connected" and let the
user assume the rest. It is a product decision that trades appearance for
honesty.

### 3.3 Built in Portugal, in Portuguese

Privacy infrastructure developed in Lisbon, with a product designed from the
start for the Portuguese-speaking market — not a translation.

---

## 4. Facts we ask you to check with us

To avoid inaccuracies that then circulate:

| Claim | Correction |
|---|---|
| "HidraNet replaces Tor" | **No.** The browser uses Tor as its exit layer. The HidraNet protocol is implemented; its relay population is being built. |
| "Total anonymity" | No tool offers it. Our threat model states expressly what it does **not** protect against. |
| "A network for the dark web" | HidraNet is a privacy tool for ordinary use. The Acceptable Use Policy prohibits unlawful activity. |
| "Impossible to intercept" | It makes interception much harder. An adversary with global observation of the network defeats any low-latency network, including Tor. |

**We would rather have an accurate piece than a favourable one.** If you need
technical confirmation before publishing, write to us — we respond quickly and
without asking to approve the text.

---

## 5. Attributable quotes

**On the purpose:**
> "Privacy should not require technical knowledge. A person does not need to
> understand cryptography to deserve that their conversations stay their own."
> — [Founder], HidraNet

**On post-quantum:**
> "Whoever captures traffic today does not need to be able to read it today. They
> only need to store it. That is why quantum resistance has to exist before it is
> urgent, not after."
> — [Founder], HidraNet

**On verification:**
> "We would rather tell someone we could not confirm their anonymity than let
> them assume they are protected. In a privacy tool, an unverified claim is worse
> than no claim."
> — [Founder], HidraNet

**On open source:**
> "Nobody should have to take our word for it. The code is published — read it,
> and tell us where we got it wrong."
> — [Founder], HidraNet

*Attribute to the right founder according to the area. For an interview, contact
press@hidranet.org.*

---

## 6. Visual resources

Downloadable at https://hidranet.org/press

| Resource | Format |
|---|---|
| Primary logo | SVG, PNG (transparent) |
| Symbol alone | SVG, PNG |
| Browser screenshots | PNG, 2560×1600 |
| Application screenshots | PNG |
| Founder photographs | JPG, high resolution |
| Architecture diagram | SVG, PNG |
| Colour palette | See the Brand Manual |

**Use:** the logos may be used to illustrate content **about** HidraNet, without
prior authorisation. Do not alter colours or proportions — see the Brand Manual,
section 5.4.

---

## 7. Frequently asked questions from journalists

**How many users do you have?**
We cannot know, and that is intentional: there is no telemetry. We can give
download numbers.

**How do you make money?**
Services for businesses (HidraReview), subscriptions and grants for open-source
development. **We do not sell data.** It is not part of the model — it is
incompatible with the architecture.

**How do you prevent misuse?**
With honesty about the limits: we cannot read encrypted content or remove content
from nodes we do not operate. We can suspend accounts on the services we operate
and cooperate with authorities within the limits of what we hold — which is
little, by design. It is the unavoidable trade-off of any privacy tool, and we
own it.

**Have you been audited?**
Not yet by an independent external body. An audit is planned and the report will
be published, whatever the result. Until then, we do not assert guarantees that
have not been verified by a third party.

**Do you receive funding?**
[Update according to the state.] We are actively seeking non-dilutive funding for
the protocol layer, as open source and a common good.

**Can I speak to a founder?**
Yes. **press@hidranet.org** — we respond within 48 hours.

---

## 8. Contacts

| Subject | Address |
|---|---|
| Press and interviews | press@hidranet.org |
| Technical questions | tech@hidranet.org |
| Security | security@hidranet.org |
| General | contact@hidranet.org |

**Response time:** 48 hours on working days. If you are on deadline, say so in
the subject line — we prioritise it.
