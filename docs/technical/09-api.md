# API Documentation — HidraNet

**Version 1.0** · Every service binds to `127.0.0.1` only.

> ⚠️ **No endpoint should be exposed to the public network.** The API has no
> authentication, because it assumes only local processes reach it. Exposing it
> on `0.0.0.0` hands control of the node to whoever can reach it.

---

## 1. Ports

| Port | Service | Protocol |
|---|---|---|
| 9051 | Node API | HTTP/JSON |
| 9050 | Proxy | SOCKS5 |
| 8084 | SevenNine | HTTP |
| 8082 | Analytics panel | HTTP/JSON |
| 8080 | Standalone HidraMail | HTTP/JSON |
| 8081 | Standalone HidraChat | HTTP/WebSocket |
| 8090 | Browser applications | HTTP |
| 9150 | Node-to-node network | TCP (Noise) |
| 7000 | DHT | UDP |

---

## 2. Node API — port 9051

### `GET /api/status`

```bash
curl http://127.0.0.1:9051/api/status
```

```json
{
  "node_id": "a3f9c2...",
  "state": "running",
  "relay_count": 3,
  "uptime_seconds": 8420,
  "dht_peers": 27
}
```

### `GET /api/resolve`

Resolves a `.hidra` name to a network address.

| Parameter | Type | Description |
|---|---|---|
| `name` | string | The name without the `.hidra` suffix |

```bash
curl "http://127.0.0.1:9051/api/resolve?name=7k2mx9qpvz3nd8fw4h6j"
```

```json
{ "address": "127.0.0.1:8084", "found": true }
```

Not found:

```json
{ "found": false }
```

---

## 3. HidraMail API — port 8080

Available with `hidra-node --apps` or `--mail`.

### `GET /api/identity`

```json
{ "address": "k3mz7qp2vx@hidra", "created": 1758412800 }
```

### `GET /api/pubkey`

```json
{ "pubkey": "BFq2n8...", "format": "raw-p256-base64" }
```

### `GET /api/inbox`

```json
{
  "messages": [
    {
      "mid": "m1758412800123",
      "from": "x9k2mqp4vz@hidra",
      "subject": "Subject",
      "date": 1758412800000,
      "read": false
    }
  ],
  "total": 1
}
```

> **Security note:** the `from` field is an unsigned claim. Do not use it for
> authorisation. See Whitepaper §4.2.

### `GET /api/sent`

Same structure as `/api/inbox`.

### `GET /api/mail/{mid}`

```bash
curl http://127.0.0.1:8080/api/mail/m1758412800123
```

```json
{
  "mid": "m1758412800123",
  "from": "x9k2mqp4vz@hidra",
  "to": "k3mz7qp2vx@hidra",
  "subject": "Subject",
  "body": "Decrypted body.",
  "date": 1758412800000
}
```

### `POST /api/send`

```bash
curl -X POST http://127.0.0.1:8080/api/send \
  -H 'Content-Type: application/json' \
  -d '{"to":"x9k2mqp4vz@hidra","subject":"Hello","body":"A message."}'
```

| Field | Type | Required |
|---|---|---|
| `to` | string | yes |
| `subject` | string | yes |
| `body` | string | yes |

Success:

```json
{ "ok": true, "mid": "m1758412800456" }
```

Error:

```json
{ "ok": false, "error": "Address not found on the network" }
```

Limit: ~500 KB of body.

### `POST /api/deliver`

Internal delivery between nodes. Receives the message already encrypted; the node
cannot read it. Not intended for use by applications.

### `DELETE /api/mail/{mid}`

```json
{ "ok": true }
```

---

## 4. Analytics API — port 8082

Available with `hidra-node --dashboard`. **It aggregates only operational metrics
from the node itself; it logs neither content nor who connects to what.**

### `GET /api/stats`

```json
{
  "total_circuits": 1482,
  "active_circuits": 12,
  "bytes_relayed": 8402934721,
  "uptime_seconds": 864000
}
```

### `GET /api/traffic`

```json
{
  "series": [
    { "t": 1758412800, "in_bytes": 84029, "out_bytes": 91882 }
  ]
}
```

### `GET /api/geo`

Aggregated distribution of peers by region, for network sizing.

```json
{ "regions": [ { "code": "PT", "peers": 4 } ] }
```

---

## 5. SOCKS5 proxy — port 9050

Standard SOCKS5 (RFC 1928), no authentication, loopback only.

```bash
curl --socks5-hostname 127.0.0.1:9050 https://example.com
```

> Use `--socks5-hostname`, **not** `--socks5`. The first form resolves DNS
> through the proxy; the second resolves locally and **leaks DNS**, revealing to
> your internet provider the domains you visit.

Python:

```python
import requests

proxies = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
r = requests.get("https://example.com", proxies=proxies, timeout=30)
```

> `socks5h://` — the `h` makes DNS resolution go through the proxy. Without it,
> it leaks.

Node.js:

```js
const { SocksProxyAgent } = require('socks-proxy-agent');
const agent = new SocksProxyAgent('socks5h://127.0.0.1:9050');
fetch('https://example.com', { agent });
```

---

## 6. Browser applications — port 8090

Served by the browser process. They only answer requests with their own `Host`
and `Origin` — protection against DNS rebinding.

| Path | Method | Description |
|---|---|---|
| `/` | GET | HidraChat |
| `/mail` | GET | HidraMail |
| `/forum` | GET | Forum |
| `/search` | GET | HidraSearch |
| `/reviews` | GET | HidraReview |
| `/sites`, `/publish` | GET | Publishing |
| `/site?addr=` | GET | View a `.hidra` site |
| `/prefs` | GET, POST | Preferences |
| `/search/api?q=&p=&lang=` | GET | Search (JSON) |

```bash
curl "http://127.0.0.1:8090/search/api?q=example&p=1&lang=en-US"
```

```json
{
  "results": [
    { "title": "…", "url": "https://…", "snippet": "…", "engine": "duckduckgo" }
  ],
  "total": 10,
  "query": "example",
  "elapsed_ms": 842
}
```

---

## 7. Status codes

| Code | Meaning |
|---|---|
| 200 | OK |
| 400 | Invalid request |
| 403 | Untrusted origin (anti-rebinding protection) |
| 404 | Resource not found |
| 500 | Internal error |
| 503 | Service unavailable (node starting up) |

---

## 8. Stability

The API is **v1 and may change**. Breaking changes will be announced in the
`CHANGELOG` at least one minor version in advance.

For integrations, pin the version of `hidra-node` you tested against.

---

## 9. Complete example

Sending mail over HidraNet from a script:

```python
#!/usr/bin/env python3
"""Sends a HidraMail through the local node."""
import json
import urllib.request

NODE = "http://127.0.0.1:8080"


def api(path, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        f"{NODE}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


me = api("/api/identity")
print("My address:", me["address"])

result = api("/api/send", "POST", {
    "to": "x9k2mqp4vz@hidra",
    "subject": "Test via API",
    "body": "Sent from a script.",
})

print("Sent" if result["ok"] else f"Failed: {result['error']}")
```
