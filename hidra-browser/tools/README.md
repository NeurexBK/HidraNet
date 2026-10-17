# Operator tools

## forum-registrar.js

The forum keeps its accounts on a public MQTT relay, and the relay enforces
nothing: anyone can overwrite the claim on a username. The registrar is the
one party whose word on names the forum page takes over the relay's. It
watches the claims, records the first key seen for each name, and publishes
the whole list signed under `hforum/registry`. The page ships the public
half of the registrar's key and trusts nothing else for names in that list.

It needs Node 22 or newer and nothing else: it loads the same MQTT bundle
the browser ships.

### What it sees

Only what every client of the relay sees: usernames, public keys and the
time of each claim. No address reaches it, and it logs counts and key
fingerprints, not names, unless started with `--verbose`.

What it adds is authority, not visibility: whoever holds the key decides
which key owns a name. Keep the key accordingly.

### Setting it up, once

1. On the machine that will run it, make the key pair:

   ```
   node hidra-browser/tools/forum-registrar.js keygen /path/to/registrar
   ```

   This writes `/path/to/registrar/registry.secret` (mode 600; back it up;
   never commit it: `*.secret` is in `.gitignore`) and prints the public
   key.

2. Paste the printed public key into `REGISTRY_PUBKEY` in
   `hidra-browser/src/ui/forum.html`, and ship the browser.

3. Run it, and keep it running:

   ```
   node hidra-browser/tools/forum-registrar.js run /path/to/registrar
   ```

   Options: `--broker <url>` (default `wss://broker.emqx.io:8084/mqtt`),
   `--interval <seconds>` (republish at least this often, default 1800),
   `--verbose`.

### How it behaves

- On connecting it collects the retained claims for five seconds, then
  publishes the list if anything is new, and again on every change and on
  the interval. A list wiped from the relay is republished.
- `registry-state.json` beside the key holds what has been recorded and the
  sequence number. The sequence only grows; the page refuses a list with a
  sequence below the one it holds, so an old list cannot be replayed.
- Run exactly one copy per key. A second copy on the same key would publish
  competing sequence numbers; the log warns when it sees one.
- A name recorded here stays with its key. There is no command to reassign
  one; editing `registry-state.json` by hand and restarting is the only way,
  and that is deliberate.

### Limits

- A public relay refuses large retained messages. The tool warns when the
  list passes 200 KB (a few thousand names). Beyond that the list needs
  splitting, or the forum needs the hub on HidraNet's own infrastructure.
- Pages that never received a list, because the registrar was down and the
  relay's copy was wiped, fall back to first-seen until the next list.
