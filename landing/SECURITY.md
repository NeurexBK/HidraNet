# Landing Page Security — HidraNet

What is actually hardened in the page, and what has to be done in the
infrastructure, because it cannot be solved inside an HTML file.

---

## ⚠️ An important technical truth

A landing page is **a static file** served to whoever visits. So:

| Request | Can HTML do it? | Where it is really solved |
|---|---|---|
| "Close all ports" | ❌ No | Host / firewall. On managed hosts **there are no ports of yours** to open. |
| "Harden against DDoS" | ❌ No | CDN/WAF (e.g. Cloudflare) in front of the site. |
| "Encrypt everything" | ⚠️ In transit, yes (HTTPS) | The host's TLS. Page content is **public by nature**. |
| Anti-XSS / anti-clickjacking / hardening | ✅ Yes | Security headers, which this repository ships. |

Anyone promising "I hardened the HTML against DDoS" is misleading you. Real
protection is **layered**.

---

## 1. Ports

On **GitHub Pages, Netlify, Vercel and Cloudflare Pages** you **administer no
server**, so **there are no ports for you to open or close**. The platform
exposes only:

- **443** (HTTPS)
- **80** (redirects to 443)

Everything else is closed by default. "Close all ports" is already the default
state of those hosts. If you ever run on your **own VPS**, then configure the
firewall:

```bash
# Example (UFW, Linux) — allow only HTTPS and HTTP, deny the rest
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

---

## 2. DDoS — the part that actually matters

DDoS defence does not live **in the site**. It lives in a **CDN/WAF in front of
it**.

**Recommended: Cloudflare** — the free plan covers most of it.

1. Create an account and add your domain.
2. Point the domain's DNS at Cloudflare (change nameservers at the registrar).
3. Enable **proxy (orange cloud)** on the records → this **hides the origin IP**.
4. Turn on:
   - **DDoS Protection** (L3/L4/L7) — on by default
   - **WAF** — rules against common attacks
   - **Rate Limiting** — caps requests per IP
   - **Bot Fight Mode**
   - **"Under Attack Mode"** — switch on during an active attack
5. Bonus: Cloudflare can also **add the security headers** via Transform Rules,
   if your host does not.

---

## 3. Security headers

Shipped in this repository, in two forms so either host picks them up:

| File | Used by |
|---|---|
| `_headers` | Netlify, Cloudflare Pages |
| `vercel.json` | Vercel |

What they set:

| Header | Why |
|---|---|
| `Strict-Transport-Security` | Forces HTTPS, with preload |
| `X-Content-Type-Options: nosniff` | Stops MIME sniffing |
| `X-Frame-Options: DENY` | Blocks clickjacking |
| `Referrer-Policy: no-referrer` | Sends no referrer anywhere |
| `Permissions-Policy` | Denies camera, microphone, geolocation, USB and the rest |
| `Cross-Origin-Opener-Policy: same-origin` | Isolates the browsing context |
| `X-DNS-Prefetch-Control: off` | No speculative DNS lookups |
| `Content-Security-Policy` | Restricts what the page may load at all |

---

## 4. Content Security Policy — current state

```
default-src 'self'; base-uri 'self'; form-action 'self';
frame-ancestors 'none'; object-src 'none';
img-src 'self' data:;
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com;
script-src 'self' 'unsafe-inline';
connect-src 'self' wss://broker.emqx.io:8084 wss://broker.hivemq.com:8884;
manifest-src 'self'; upgrade-insecure-requests
```

### What changed, and why

Three things were removed from this policy, and they are worth recording:

**Google Analytics is gone.** `googletagmanager.com` and `google-analytics.com`
were allowed in `script-src`, `img-src` and `connect-src`, and the page loaded
`gtag.js`. On a privacy product whose own Privacy Policy states that no
tracking takes place, that was a contradiction anyone inspecting the page would
find. Analytics, if it returns, has to be self-hosted and free of transfers to
third countries.

**`unpkg.com` is gone from `script-src`.** The PWA at `/r/` loaded the MQTT
library from a public CDN with no integrity check. It now serves it from
`/r/vendor/`, at a pinned version.

**`'unsafe-inline'` remains, and should not.** It is still there because the
page carries inline `<style>` and `<script>`. Removing it means moving both out
to files, or adding per-block nonces. Until that happens, the CSP is weaker
than it looks: it blocks external injection but not inline injection. Declared
here rather than glossed over.

---

## 5. What is left to do

| Item | Where | Priority |
|---|---|---|
| Put Cloudflare (or equivalent) in front | DNS / CDN | High |
| Remove `'unsafe-inline'` — extract inline CSS/JS or use nonces | Page | Medium |
| Self-hosted analytics, if analytics is wanted at all | Infrastructure | Low |
| Subresource Integrity on the Google Fonts stylesheet | Page | Low |
| Self-host the fonts and drop `fonts.googleapis.com` entirely | Page | Low |

The last item is worth weighing: loading fonts from Google means every visitor's
browser contacts Google before the page finishes rendering. Self-hosting two
font families removes that, and removes two entries from the CSP.

---

## 6. What this document deliberately does not claim

- That the page is "unhackable". It is a static file; the interesting attack
  surface is the host and the DNS, not the HTML.
- That the headers stop a determined attacker. They raise the cost of common,
  automated attacks. That is their job, and it is worth doing.
- That DDoS is handled. It is not, until something sits in front of the origin.
