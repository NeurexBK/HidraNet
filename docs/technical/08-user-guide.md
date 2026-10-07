# User Guide — HidraNet

---

## 1. Before you start: what this tool does and does not do

Reading this saves you trouble.

**It does:**
- Hide your IP address from the sites you visit
- Encrypt your messages and mail so that not even we can read them
- Stop different tabs from being linked to each other
- Make it harder to identify your machine by fingerprint

**It does not:**
- Protect you if you sign in to an account that identifies you
- Protect you if your computer is compromised
- Protect you from an adversary watching the entire internet
- Make anything illegal legal

**The rule that matters:** anonymity breaks because of what a person does, not
because the tool failed. Signing into your personal email inside HidraNet links
that session to you — permanently and irreversibly.

---

## 2. Browsing

### The status panel

When it opens, the first tab shows:

| Indicator | Meaning |
|---|---|
| **Starting Tor — N%** | Building a circuit. Wait. |
| **Connected — exiting via `<IP>`** | Anonymous, exit IP **verified** |
| **Connected, but verification did not confirm** | Connected, but with no independent confirmation — do not assume anonymity |
| **Disconnected** | Browsing leaves from your own IP |

This distinction is deliberate. We would rather tell you we did not confirm than
tell you that you are anonymous without having verified it.

### New identity

The **Switch circuit** button asks the network for a new path, with a different
exit node. Use it when you want to separate one activity from the previous one.

Honest notes:
- The network may hand back the same exit node. When that happens, the browser
  says so rather than pretending something changed.
- It can take a few seconds (the network rate-limits these requests).
- **It does not erase what you have already revealed.** If you signed into an
  account, switching circuit does not undo that link.

### Isolated tabs

To websites, every tab is a different visitor: separate cookies, storage and
fingerprint, wiped when the tab closes.

**Practical consequence:** your session on a site does not carry from one tab to
another. That is intentional.

### Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl/Cmd + T` | New tab |
| `Ctrl/Cmd + W` | Close tab |
| `Ctrl/Cmd + L` | Focus the address bar |
| `Ctrl/Cmd + R` / `F5` | Reload |

---

## 3. HidraMail

Mail with `@hidra` addresses, encrypted end to end. Neither we nor any
intermediary can read the content.

### Creating an address

Open HidraMail. An address is generated automatically, like:

```
k3mz7qp2vx@hidra
```

The address **derives mathematically from your public key**. Nobody can claim
your address without holding your key.

### Several addresses

Button **⚙ → Generate new anonymous address**. Use different addresses for
different contexts — it is the simplest way to keep them unlinked.

They all receive at the same time; you choose which one you send from.

### Sending

1. **Compose**
2. Recipient: `address@hidra`
3. Subject and body
4. **Send 🔒**

Before sending, the client checks that the public key it obtained matches the
destination address. If it does not, it refuses. This protects you against key
substitution.

> **The recipient must have opened HidraMail at least once**, so that their
> public key is published on the network. Otherwise you will see "address not
> found".

### Limitations you should know about

| Limitation | What it means |
|---|---|
| **The sender is not authenticated** | The "From" field is an unverified claim. You can receive mail that says it comes from an address and does not. **Do not trust the sender for important decisions.** A fix is planned. |
| Leave HidraMail open to receive | Messages arrive while the application is open |
| Stored on this device | No synchronisation between machines |
| Maximum ~500 KB per message | No large attachments |

### Backup

Your address and your mail live **on this device**. If you clear the
application's data or lose the computer, you lose the address and the history.
There is no recovery — we do not have your keys, by design.

---

## 4. HidraChat

End-to-end encrypted chat rooms.

### Joining a room

1. Choose a name (do not use your real name)
2. A room name
3. **A room password** — this is what generates the encryption key

Everyone who joins with the same password reads the messages. Anyone without it
sees only "encrypted message".

### The password is the security

- Choose a **long, unpredictable phrase** — not `123456`, not the room name
- **Share it over a secure channel**, never in the room itself
- Whoever obtains the password reads everything sent afterwards

The room's technical identifier also derives from the password, so the transport
does not reveal the room name.

---

## 5. SevenNine — publishing a `.hidra` site

Publishes a site reachable on the network without revealing where it is hosted.

1. In the browser, open SevenNine
2. Create the pages in the editor
3. **Publish**
4. You receive an address:

```
7k2mx9qpvz3nd8fw4h6j.hidra
```

The address derives from the site's key. Keep the key: **without it you cannot
update or recover the site.**

To visit, type the `.hidra` address in the address bar.

---

## 6. HidraSearch

Meta-search that queries several engines and returns results without logging your
queries. Requests leave through the network, not from your IP.

You can fix the results language in the preferences.

---

## 7. Good practice

### Do

- ✅ Check the exit IP before doing anything sensitive
- ✅ Use different HidraMail addresses for different contexts
- ✅ Long phrases for HidraChat rooms
- ✅ Keep the browser up to date
- ✅ Keep a copy of the keys for any site you publish

### Do not

- ❌ **Do not sign in to personal accounts** — it is the mistake that undoes
  everything else
- ❌ Do not download and open files outside the browser (a PDF or .doc can
  contact the internet directly, outside the network, and reveal your IP)
- ❌ Do not maximise the window if you care about fingerprinting (window size is
  a signal)
- ❌ Do not reuse usernames you already use elsewhere
- ❌ Do not assume anonymity when the panel says it did not confirm

---

## 8. Frequently asked questions

**Can HidraNet read my messages?**
No. Encryption happens on your device, before the message leaves. We do not have
the keys. This is not a policy we could change — it is the architecture.

**Is it legal?**
Yes, in the jurisdictions where HidraNet operates. Privacy is a right. The
Acceptable Use Policy defines what is not allowed on the network.

**Why is it slower?**
Traffic crosses several hops, in different parts of the world. It is the cost of
anonymity, and it is intrinsic.

**I lost my HidraMail address. Can you recover it?**
No. We do not have your keys. It is the same property that stops anyone forcing
us to hand them over.

**Does it replace Tor Browser?**
No, and we do not claim it does. For maximum anonymity against well-resourced
adversaries, Tor Browser has a decade of auditing we do not yet have. HidraNet
offers privacy with integrated applications — chat, mail, search, sites — that
Tor Browser does not have.

**Can I help?**
Yes: run a node (Installation Guide), contribute code (Contributing Guide) or
spread the word (Ambassador Programme).
