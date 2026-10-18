# Brand Manual — HidraNet

**Version 1.0 · September 2026**

---

## 1. ⚠️ A problem to solve first

**HidraNet currently has two different visual identities.**

| Surface | Main colour | |
|---|---|---|
| Corporate website | `#00ff88` neon green + `#00ccff` cyan | Background `#070809` |
| Browser and applications | `#00d4aa` teal | Background `#06070d` |

They are distinct brands. Someone who arrives via the website and installs the
application sees two products.

### Decision

**Adopt `#00d4aa` (teal) as the main brand colour.**

Rationale:
1. It is used consistently across the product's **eight interfaces** — changing
   the website means changing one page; changing the product means changing
   eight.
2. Teal stands out better: neon green on black is the "hacker" visual convention
   used by dozens of projects.
3. It is verified for accessibility (section 3.3).

**Action:** align the corporate website with the product palette.

---

## 2. The brand

### 2.1 Name

**HidraNet** — one word, capital H and N. Never "Hidra Net", "HIDRANET" or
"hidranet" in running text (the lower-case domain is acceptable).

Products: **HidraNet Browser**, **HidraChat**, **HidraMail**, **HidraSearch**,
**HidraReview**, **SevenNine**.

### 2.2 Origin

From the Hydra: cut off one head, two grow back. It is how a decentralised
network behaves — removing one node does not stop it; the network reroutes and
carries on.

### 2.3 Positioning

> Privacy you can verify.

---

## 3. Colours

### 3.1 Primary

| Colour | Hex | RGB | Use |
|---|---|---|---|
| **Hidra Teal** | `#00d4aa` | 0, 212, 170 | Brand colour, primary actions, highlights |
| **Dark Teal** | `#00a888` | 0, 168, 136 | Interaction states, gradients |
| **Background** | `#06070d` | 6, 7, 13 | Main background |
| **Background 2** | `#0b0d16` | 11, 13, 22 | Raised background |

### 3.2 Secondary

| Colour | Hex | Use |
|---|---|---|
| Card | `#10131f` | Surfaces |
| Card 2 | `#161a2b` | Raised surfaces |
| Border | `#1c2133` | Dividers |
| Primary text | `#e9ecf5` | Body text |
| Secondary text | `#9aa3bd` | Supporting text |
| Tertiary text | `#5b6480` | See the warning in 3.3 |
| Blue | `#4f8cff` | Links, information |
| Warning | `#f5a623` | Alerts |
| Danger | `#ff5c6c` | Errors, destructive actions |

### 3.3 Accessibility — verified values

WCAG 2.1 contrast ratios, calculated:

| Combination | Ratio | Level |
|---|---|---|
| Teal `#00d4aa` on background `#06070d` | **10.53:1** | ✅ AAA |
| Primary text `#e9ecf5` on background | **17.03:1** | ✅ AAA |
| Secondary text `#9aa3bd` on background | **8.00:1** | ✅ AAA |
| Tertiary text `#5b6480` on background | **3.43:1** | ⚠️ AA-large only |
| **Teal `#00d4aa` on white** | **1.91:1** | ❌ **FAILS** |

**Two rules follow from these numbers:**

1. **Tertiary text `#5b6480` may only be used at 18px or above** (or 14px bold).
   Below that it does not meet the 4.5:1 minimum and is illegible for some users.
   For small supporting text, use `#9aa3bd`.

2. **Never use teal on white.** It fails by a wide margin. On light backgrounds —
   print, documents, presentations — use **`#00695c`** (darkened teal, ~7:1 on
   white) or the brand's dark background.

---

## 4. Typography

### 4.1 Families

| Use | Font | Fallback |
|---|---|---|
| Headings and interface | **Inter** | -apple-system, Segoe UI, Roboto, sans-serif |
| Monospace | **JetBrains Mono** | SF Mono, Consolas, monospace |

Both are free and may be embedded in the products.

### 4.2 Scale

| Level | Size | Weight | Line height |
|---|---|---|---|
| H1 | 40 px | 800 | 1.15 |
| H2 | 30 px | 700 | 1.2 |
| H3 | 22 px | 700 | 1.3 |
| H4 | 18 px | 600 | 1.4 |
| Body | 16 px | 400 | 1.6 |
| Small | 14 px | 400 | 1.5 |
| Caption | 12 px | 500 | 1.4 |

### 4.3 Use of monospace

Reserved for: `.hidra` and `@hidra` addresses, keys, checksums, commands and
code. **Never for running text.**

---

## 5. Logo

The logo is the three-headed hydra, in green (`#268D00`) on black. Every
file below is made from the one master, `brand/logo/hidranet-logo-black.jpg`;
the script that makes them is described in `brand/README.md`.

| File in `brand/logo/` | Use |
|---|---|
| `hidranet-logo.png`, `hidranet-logo-640.png` | The logo alone, transparent background: pages, headers |
| `hidranet-logo-square.png` | The logo centred in a transparent square |
| `hidranet-icon-1024.png` and `-512` … `-16` | App icon: the logo on a black rounded square |
| `hidranet.ico` | Windows (16–256 px) |
| `hidranet.icns`, `hidranet-macos-1024.png` | macOS, on Apple's icon grid |
| `favicon.ico`, `favicon-32.png` | Browser tabs |
| `hidranet-social-1200x630.png` | Link previews (Open Graph, X) |

### 5.1 Variants

| Variant | Use |
|---|---|
| Primary | Dark background — preferred use |
| Light monochrome | Dark background with restrictions |
| Dark monochrome | Light background, print |
| Symbol alone | App icon, avatar, favicon |

### 5.2 Clear space

The minimum margin around the logo equals the **height of the "H"**. Nothing —
text, image or border — enters that space.

### 5.3 Minimum size

| Medium | Minimum |
|---|---|
| Screen, full logo | 120 px wide |
| Screen, symbol | 24 × 24 px |
| Print, logo | 25 mm |

### 5.4 Prohibited uses

| ❌ |
|---|
| Changing the colours |
| Distorting, stretching or compressing |
| Rotating |
| Applying shadows, outlines or effects |
| Placing it on a background with insufficient contrast |
| Placing it on a photograph without clear space |
| Recreating it in another font |
| Changing the proportions between symbol and wordmark |

---

## 6. Third-party use of the brand

**Important:** the software is MIT; **the marks are not**.

### 6.1 Permitted, without authorisation

- Referring to HidraNet in articles, reviews and content
- Stating that a project is compatible with HidraNet
- Using the logos to illustrate content **about** HidraNet
- Ambassadors: using the materials provided, under the programme's terms

### 6.2 Requires written authorisation

- Using "Hidra" or "HidraNet" in a product or company name
- Registering domains with the mark
- Merchandise for sale
- Suggesting sponsorship, partnership or approval that does not exist

### 6.3 Prohibited

- Using the mark on a **modified fork** of the software in a way that could
  confuse users as to its origin

> **The rule on forks, and the reason for it.** Forking the code is a right
> granted by the MIT licence, and we not only respect it, we encourage it. But a
> modified version presenting itself as "HidraNet" can mislead someone about the
> security guarantees they are getting. In a privacy tool, that has real
> consequences for whoever trusts the name.
>
> Fork freely — give it another name.

Requests: **brand@hidranet.org**

---

## 7. Tone of voice

### 7.1 Principles

| We are | We are not |
|---|---|
| Direct | Sensationalist |
| Technical when needed | Obscure |
| Honest about limitations | Alarmist |
| Sober | Solemn |
| Useful | Condescending |

### 7.2 The main rule: never promise more than you deliver

It is the characteristic that defines HidraNet's communication.

| ❌ Do not write | ✅ Write |
|---|---|
| "100% anonymous" | "Hides your IP from the sites you visit" |
| "Impossible to trace" | "Makes tracing much harder — see the threat model" |
| "Military-grade security" | "ML-KEM-1024, resistant to quantum computing" |
| "Nobody can stop you" | "The network is decentralised: there is no single point of failure" |
| "Better than Tor" | "Different from Tor: it brings integrated applications" |

**Why.** If someone trusts an exaggerated promise and suffers real consequences,
the responsibility lies with whoever exaggerated. In a privacy tool, overselling
can carry a human cost. **Under-promising is policy, not modesty.**

### 7.3 Neutrality

HidraNet is a technical tool. Our communication does **not** engage in political
confrontation and does not position itself against governments or institutions.

We defend privacy in **technical and legal** terms — it is a right recognised in
Article 12 of the Universal Declaration of Human Rights. We do not need more than
that.

| ❌ | ✅ |
|---|---|
| "Against government surveillance" | "Privacy is a recognised right" |
| "Escape state control" | "Your communications are yours alone" |
| "They are watching you" | "Fewer people watching than you might think" |

### 7.4 Examples

**Short description (280 characters):**
> HidraNet is an open-source decentralised network with post-quantum
> cryptography. Browser, chat, mail, search and sites — private by design. If we
> cannot confirm you are anonymous, we tell you.

**Error message:**
> We could not confirm your exit IP. The connection is active, but the
> independent check failed. Do not treat this session as anonymous until it is
> confirmed.

*(It says what happened, what it means, and what to do. Without blaming the user,
without minimising.)*

---

## 8. Files

| Resource | Location |
|---|---|
| Logos (SVG, PNG) | `/brand/logo/` |
| Fonts | Inter and JetBrains Mono — Google Fonts |
| Palette (CSS, Figma) | `/brand/colors/` |
| Press kit | https://hidranet.org/press |

### CSS variables

```css
:root {
  --hidra-teal:      #00d4aa;
  --hidra-teal-dark: #00a888;
  --hidra-teal-print:#00695c; /* light backgrounds — see §3.3 */

  --bg:        #06070d;
  --bg-2:      #0b0d16;
  --card:      #10131f;
  --card-2:    #161a2b;
  --border:    #1c2133;

  --text:      #e9ecf5;
  --text-2:    #9aa3bd;
  --text-3:    #5b6480; /* minimum 18px — see §3.3 */

  --blue:      #4f8cff;
  --warning:   #f5a623;
  --danger:    #ff5c6c;
}
```

---

📧 **brand@hidranet.org**
