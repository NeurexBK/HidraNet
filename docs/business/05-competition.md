# 05 — Competition

## 1. Market A — Anonymity network and browser

| | Tor Browser | Brave | Mullvad Browser | Proton | **HidraNet** |
|---|---|---|---|---|---|
| Price | Free | Free | Free | Freemium | Freemium |
| Base | Firefox ESR | Chromium | Firefox ESR | — | **Electron** |
| Users | 2–2.5M/day (network) | **100M MAU** | — | — | Pre-launch |
| Revenue | Donations/grants | **>$100M ARR** | Flat subscription | **$97.5M ARR** | 0 |
| Post-quantum | In transition | No | No | Partial | **✅ Kyber1024** |
| Integrated apps | No | Wallet, VPN | No | Mail, VPN, Drive, Docs | **Chat, Mail, Search, Forum, Reviews** |
| Fingerprint | Uniformity | Randomisation | Uniformity | — | **Per-tab randomisation** |
| Anonymity verified for the user | No | N/A | No | N/A | **✅** |

### Where we realistically win

1. **Post-quantum already in production.** Kyber1024 in the core. None of the
   others has it. A strong argument for grants and for technical users.
2. **Verified anonymity, not asserted.** The browser confirms its exit IP against
   the Tor Project's verifier and, if it cannot, says so. No competitor does
   this. It is honesty as a feature.
3. **Applications on the network.** Tor Browser is a browser. We bring search,
   mail, chat, forum and reviews.
4. **Native Portuguese, Portuguese-speaking market.** Tor Browser in Portuguese
   is a translation; HidraNet is built here, with HidraReview designed for
   Portuguese and Brazilian local commerce. It is a defensible niche and it is
   where the sale is.

### Where we lose, and it has to be acknowledged

1. **Years of security auditing.** Tor Browser has a decade of peer review. We do
   not. In an area where one flaw is catastrophic, this is their biggest moat.
2. **Electron.** Worse performance and attack surface than a Firefox fork.
3. **The anonymity network is Tor's.** See
   [03, section 4](03-product-and-technology.md). We have our own protocol, we do
   not have volunteers. Telling an investor otherwise is unsustainable.
4. **Distribution.** Brave has 100M users. We have a landing page.

> **Conclusion for the deck:** *we do not compete head-on with Tor Browser.*
> Anyone who wants maximum anonymity should use Tor Browser and we should say so.
> We compete for people who want privacy **with useful services on top**, in
> Portuguese, and for whoever reaches us through HidraReview.

---

## 2. Market B — HidraReview (this is where the battle matters)

| | Google Business Profile | Trustpilot | Generic NFC cards | Birdeye / Podium | **HidraReview** |
|---|---|---|---|---|---|
| Price | Free | ~€50–250/month | €15–30 (no software) | €200–400/month | **€0–49/month** |
| Owns the data | Google | Trustpilot | — | The platform | **The business** |
| NFC included | No | No | Hardware only | Add-on | **✅** |
| Native PT/BR | Partial | Partial | — | No | **✅** |
| Target | Everyone | Medium/large | Micro | Medium | **Micro and small** |

### The honest reading of that table

**The real competitor is Google Business Profile, and it is free.** No business
is going to replace Google with us — people search on Google.

**So the proposition cannot be "replace Google".** It has to be:

> *"We help you get more reviews — on Google and on your own page, which is yours
> and not Google's. The NFC card converts at 60–80% against 35–50% for a QR code.
> And your page does not disappear if Google changes its mind."*

That is: **complementary to Google at the top of the funnel, an alternative on
data ownership.** That is a sellable position. "Alternative to Google" is not.

**Where we beat Birdeye/Podium:** price. They sell at €200–400/month to
mid-sized chains. The café on the corner was never their customer. It is our
market.

**Where we beat generic NFC cards:** they sell plastic with no software. We sell
the panel, the owner notification, the page and the recurrence.

**Where we are weak:** we are two founders with no sales force, selling to a
customer that expects an in-person sale and has high churn. See
[06 — Go-to-Market](06-go-to-market.md).

---

## 3. Answers to the three objections a VC will raise

**"Why doesn't Tor Browser do this tomorrow?"**
It will not. It is a non-profit with a narrow mandate and an aversion to
commercial scope. Restaurant reviews is outside what they are. The real risk is
not Tor — it is a review competitor adding privacy, which is easier than us
adding scale.

**"Why is this one company and not two projects?"**
Because HidraReview needs a differentiator that Birdeye cannot copy in three
months, and the network needs real users. Each solves the other's problem. The
full answer is in [04, section 5](04-business-model.md) — and the product has to
make it true, not just the deck.

**"Two founders, two products, zero revenue. Why now?"**
Because the regulatory context (Chat Control, see [02](02-market-analysis.md)) is
generating demand for privacy that legislators cannot stop, and because the
non-dilutive money for the protocol layer is available now (NGI Zero, €21.6M
through 2027). The plan does not ask a VC to fund the network — it asks them to
fund HidraReview's distribution, which already has a paying customer.
