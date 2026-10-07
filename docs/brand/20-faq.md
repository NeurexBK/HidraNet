# Frequently Asked Questions — HidraNet

---

## About the product

**What is HidraNet?**
An open-source decentralised network and a set of private applications: browser,
chat, mail, search, forum and site publishing. Traffic is routed through several
nodes and encrypted with quantum-resistant cryptography.

**Is it free?**
The software is free and open source (MIT), and will stay that way. There are
paid services for businesses (HidraReview) and an optional subscription with
additional features.

**Which systems does it support?**
Windows 10+, macOS 11+ and 64-bit Linux.

**Do I need to know anything technical?**
Not to use it. Download it, open it, and the browser handles the rest. To run a
node, the Installation Guide takes you through it step by step.

---

## About privacy

**Can HidraNet read my messages?**
No. Encryption happens on your device, before the message leaves. We do not have
the keys.

It is not a policy we could change — it is the architecture. If we were compelled
to hand over the content, we would have nothing to hand over.

**What data do you keep about me?**
From the browser: none. No history, no IP, no search queries, no telemetry. If
you are a HidraReview customer, we keep your email, billing details and the
content you publish. The detail is in the Privacy Policy.

**Do you sell data?**
No, and we never will. Besides contradicting the project's reason to exist, we
have nothing to sell.

**Am I really anonymous?**
**Not absolutely, and no tool can achieve that.**

HidraNet hides your IP from sites, encrypts the content and makes it much harder
to link your activities to each other.

It does not protect you if you sign in to a personal account, if your computer is
compromised, or against an adversary able to watch the entire internet. The
Whitepaper, section 5.2, states expressly what we do **not** protect against.

**How do I know I am protected?**
The panel shows the exit IP **verified** against the Tor Project's checker. If we
cannot confirm it, the browser says so instead of assuming.

**What is the biggest mistake I can make?**
Signing in to an account that identifies you — personal email, social media. It
links that session to you permanently, and no circuit switch undoes it.

---

## Comparisons

**Is it better than a VPN?**
Different. A VPN routes traffic through **one** server, which knows who you are
and what you visit — you have to trust the provider. HidraNet routes through
**several** nodes, and none knows both ends. You do not have to trust us.

**In exchange:** it is slower and some sites block known exit nodes.

**Is it better than Tor Browser?**
**We do not claim it is.**

For maximum anonymity against well-resourced adversaries, **use Tor Browser** —
it has a decade of peer review we do not yet have.

HidraNet offers privacy with integrated applications (chat, mail, search, sites,
reviews) that Tor Browser does not have, and post-quantum cryptography, which Tor
is still adopting.

They are different tools. Saying otherwise would be a disservice to anyone
relying on the answer.

**How does it differ from Brave?**
Brave is a fast browser with ad blocking and an advertising model of its own.
HidraNet is an anonymity network with applications. Brave has 100 million users
and we are starting out — but Brave does not route traffic through multiple nodes
and has no post-quantum cryptography.

**Why is it slower?**
Traffic crosses several hops, in different parts of the world. It is the
intrinsic cost of anonymity, not an implementation flaw.

---

## Applications

**How does HidraMail work?**
You get an `@hidra` address that derives mathematically from your public key —
nobody can claim it without your key. Messages are encrypted on your device to
the recipient's key.

**I lost my HidraMail address. Can you recover it?**
No. We do not have your keys — they live on your device. It is the same property
that stops anyone compelling us to hand them over.

Make a backup.

**Can I trust the sender of a HidraMail?**
**Not yet.** At present the "From" field is an unverified claim. You know the
message was encrypted for you, but you cannot prove who sent it. Sender
authentication by signature is on the hardening plan.

Until then, **do not make important decisions based on the sender**.

**How do HidraChat rooms work?**
The encryption key derives from the room password. Whoever has the password
reads; whoever does not sees "encrypted message". Choose a long phrase and share
it over a secure channel — never in the room itself.

**What is SevenNine?**
The `.hidra` site builder. It publishes a site reachable on the network without
revealing where it is hosted. Keep the key: without it you cannot update it.

---

## Legality and use

**Is it legal to use HidraNet?**
Yes. Privacy is a right recognised in Article 12 of the Universal Declaration of
Human Rights and Article 8 of the European Convention on Human Rights. Using
privacy tools is legal in the jurisdictions where we operate.

**What is prohibited on the network?**
The Acceptable Use Policy prohibits, among other things: exploitation of minors,
attacks on systems, distribution of malware, fraud, spam and fake reviews.

**How do you prevent misuse?**
With honesty about the limits. **We cannot** read encrypted content or remove
content from nodes we do not operate. **We can** suspend accounts on our
services, remove content from our servers and cooperate with authorities within
the limits of what we hold.

It is the unavoidable trade-off of any privacy tool: what protects the journalist
also protects whoever abuses it. We own that rather than hide it.

**How do I report abuse?**
**abuse@hidranet.org**. Child abuse cases: report them to the Polícia Judiciária
or INHOPE as well — do not wait for us.

---

## Project and company

**Who is behind it?**
João Brandão and Leonardo Mello, in Lisbon, Portugal. HidraNet, Lda develops
software and provides services. **The company does not operate exit nodes** — the
network belongs to volunteers.

**How do you make money?**
Services for businesses (HidraReview), optional subscriptions, `.hidra` domains
and grants for open-source development. We do not sell data.

**Is the code really open?**
Yes, MIT licence, at github.com/NeurexBK/HidraNet. You can read it, audit it,
modify it and fork it.

**Have you been audited?**
Not yet by an independent external body. It is planned, and the report will be
published — whatever the result. Until then, we do not assert guarantees verified
by third parties.

**How can I help?**
Run a node (Installation Guide) · Contribute code or documentation (Contributing
Guide) · Translate · Spread the word (Ambassador Programme) · Report problems.

**I found a vulnerability.**
**security@hidranet.org** — do not open a public issue. We respond within 48
hours, credit you on the fix, and **take no legal action against good-faith
research**.

---

## Common problems

**Tor does not get past 0%.**
Your network may be blocking Tor. Configure a bridge in the settings.

**"Port 8090 is in use."**
Another copy of the browser is open. Close it and restart.

**A site blocks me.**
Some sites block known exit nodes. Try **Switch circuit**.

**macOS says the application is damaged.**
The download is fine. The app is not signed by Apple and, on Apple Silicon, macOS
refuses unsigned code and calls it "damaged". In Terminal, in the extracted
folder:

```bash
xattr -cr HidraNet.app
codesign --force --sign - \
  HidraNet.app/Contents/Resources/bin/tor/tor
codesign --force --deep --sign - HidraNet.app
open HidraNet.app
```

The `codesign` commands are the ones that fix it. Tor has to be signed separately
and before the app — `--deep` does not reach binaries inside `Resources/`.
Without that line the app opens but does not connect, and reports
`tor exited with code null`.

The ZIP includes `Start HidraNet.command`, which does all of this for you.

**macOS still blocks it.**
On macOS 15 (Sequoia) and later, right-click → Open no longer works. Go to
**System Settings → Privacy & Security**, scroll down, and click **Open Anyway**.

**I lost everything when I cleared the data.**
Addresses and messages live on your device. Without a backup there is no
recovery — we do not have your keys.

---

## Contacts

| Subject | Address |
|---|---|
| General | contact@hidranet.org |
| Security | security@hidranet.org |
| Privacy | privacy@hidranet.org |
| Abuse | abuse@hidranet.org |
| Press | press@hidranet.org |
| Ambassadors | ambassadors@hidranet.org |
