# Installation Guide — HidraNet

Covers installing the **HidraNet Browser** and running a **network node**.

---

## Part I — HidraNet Browser

### Requirements

| System | Minimum version |
|---|---|
| Windows | 10 (64-bit) |
| macOS | 11 Big Sur (Intel and Apple Silicon) |
| Linux | 64-bit distribution with glibc 2.31+ |

Recommended: 4 GB RAM, 500 MB of disk, an internet connection without outbound
port filtering.

### Installing from the website

1. Download the package for your system from https://hidranet.org.
2. **Verify the checksum** before running it:

```bash
# Linux / macOS
sha256sum HidraNet-Browser-1.1.0-Linux-x64.zip
# Windows (PowerShell)
Get-FileHash .\HidraNet-Browser-1.1.0-Windows-x64.zip -Algorithm SHA256
```

Compare it with the value published in `SHA256SUMS.txt` on the site. **If it does
not match, do not run the file.** A modified package in a privacy browser is the
worst possible case.

3. Extract and run:

| System | Open |
|---|---|
| Windows | `Start HidraNet.bat` (or `HidraNet.exe`) |
| macOS | `Start HidraNet.command` (see below) |
| Linux | `bash start.sh` |

On Linux, use `start.sh` rather than the `hidranet` binary directly. Chromium
sandboxes every page, and Ubuntu 23.10 and later restrict the mechanism it
normally uses for that; run directly, the browser aborts before a window opens.
`start.sh` detects this and sets up the helper the sandbox needs instead, which
takes one `sudo` command and asks for your password once. It never turns the
sandbox off.

### First run

On opening, the browser starts the bundled Tor automatically. The panel shows
bootstrap progress (typically 20 to 40 seconds).

When it finishes, the panel shows the **verified exit IP**. If it says it could
not confirm the IP, the browser is connected but the independent verification
failed — do not treat the session as anonymous until it is confirmed.

### macOS — first launch

The package is **not signed or notarised by Apple**. This has two consequences,
and the first one misleads most people.

**On Apple Silicon (M1–M4), macOS says the app is damaged.**

```
"HidraNet.app is damaged and can't be opened. You should move it to the Trash."
```

The download is not corrupt. What happens is that the macOS kernel refuses to
load unsigned arm64 code, and the message Apple chose to show is "damaged". To
the person reading it, that is indistinguishable from a corrupted file — and it
is why users report this as "I could not download it".

**Fix — in Terminal, in the extracted folder:**

```bash
xattr -cr HidraNet.app
codesign --force --sign - \
  HidraNet.app/Contents/Resources/bin/tor/tor
codesign --force --deep --sign - HidraNet.app
open HidraNet.app
```

The `codesign` commands are the ones that fix it: they apply local *ad-hoc*
signatures, which is what lets macOS load the code. Clearing quarantine on its
own is **not enough** on Apple Silicon.

**Tor has to be signed separately, and before the app.** It lives at
`Contents/Resources/bin/tor/tor`, and `--deep` does not reach it — it only
descends into the standard nested-code locations (`Frameworks`, `PlugIns`,
`XPCServices`, `Helpers`). If you sign only the bundle, the app opens but nothing
connects: the kernel kills the unsigned Tor the moment the browser launches it,
and the panel reports `tor exited with code null`.

If `codesign` is missing: `xcode-select --install`.

The ZIP includes `Start HidraNet.command`, which runs every step, and
`README-macOS.txt` with the full procedure.

**If macOS still blocks it:**

On **macOS 15 (Sequoia) and later**, the right-click → Open trick **no longer
works** — Apple removed that path. Instead:

1. Try to open the app once (it will be blocked)
2. **System Settings → Privacy & Security**
3. Scroll down to the line about HidraNet being blocked
4. **Open Anyway**, and confirm with your password or Touch ID

On macOS 14 and earlier, right-click the app → Open → Open also works.

> **Note for the team:** this is solved permanently with a paid Apple Developer
> account and notarisation. Until then, these instructions are the honest
> alternative — and they should be visible on the website, not hidden in a README
> inside the ZIP.

### Building from source

```bash
git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-browser
npm install
npm run fetch-tor     # downloads the Tor binary for your platform
npm start
```

Distribution packages:

```bash
npm run build:win        # Windows x64
npm run build:linux      # Linux x64
npm run build:mac        # macOS (arm64 + x64)
npm run pack             # portable, with Tor included
```

---

## Part II — Running a node

Running a node contributes capacity to the network. It is the most direct way to
help the project.

### Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 1 core | 2 cores |
| RAM | 512 MB | 2 GB |
| Disk | 1 GB | 5 GB |
| Bandwidth | 5 Mbps symmetric | 50 Mbps+ |
| Availability | — | always on |

### Building

Requires Rust 1.80 or later (2024 edition).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/NeurexBK/HidraNet.git
cd HidraNet/hidra-node
cargo build --release
```

The binary ends up at `target/release/hidra-node`.

### Configuration

Create `config.toml` next to the binary:

```toml
[node]
name = "my-node"

[network]
listen_addr = "0.0.0.0"
listen_port = 9150

[logging]
level = "info"        # use "info" in production, not "debug"
format = "json"       # "json" for automated collection; "pretty" for a console

[paths]
keys_dir = "keys"

[dht]
port = 7000
enabled = true
bootstrap_nodes = []  # the network's bootstrap addresses

[proxy]
listen_addr = "127.0.0.1"   # NEVER 0.0.0.0 — see the warning below
port = 9050

[hidden_service]
enabled = false
local_port = 8080
```

> ⚠️ **`proxy.listen_addr` must always be `127.0.0.1`.**
> If you expose it on `0.0.0.0`, anyone on the network can use your machine as an
> open proxy, and other people's traffic leaves with your IP and under your
> responsibility.

### Keys

On first run, the node generates its keys in `keys/`.

```bash
chmod 700 keys/
```

**Back up `keys/` and store the backup encrypted.** The node's identity on the
network is that folder. Losing it means losing the identity; exposing it means
losing control of it.

### Run modes

```bash
./hidra-node                          # relay mode (default)
./hidra-node --server                 # full server mode
./hidra-node --proxy                  # SOCKS5 gateway (9050) for other programs; the HidraNet Browser uses its own Tor
./hidra-node --sevennine              # .hidra site builder (port 8084)
./hidra-node --dashboard              # analytics panel (port 8082)
./hidra-node --apps                   # HidraMail (8080) + HidraChat (8081)
./hidra-node --config /path/config.toml
```

Diagnostics:

```bash
./hidra-node --dht-discover           # tests DHT discovery
./hidra-node --connect 1.2.3.4:9150   # tests a connection to a peer
```

### Ports

| Port | Service | Exposure |
|---|---|---|
| 9150 | Node-to-node network | **Public** |
| 7000 | DHT | **Public** |
| 9050 | SOCKS5 proxy | Loopback only |
| 9051 | Node API | Loopback only |
| 8084 | SevenNine | Loopback only |
| 8082 | Panel | Loopback only |

Firewall (Linux):

```bash
sudo ufw allow 9150/tcp
sudo ufw allow 7000/udp
sudo ufw enable
```

### Running as a service (systemd)

`/etc/systemd/system/hidra-node.service`:

```ini
[Unit]
Description=HidraNet Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hidra
Group=hidra
WorkingDirectory=/opt/hidranet
ExecStart=/opt/hidranet/hidra-node --config /opt/hidranet/config.toml
Restart=on-failure
RestartSec=10

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/hidranet
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin hidra
sudo chown -R hidra:hidra /opt/hidranet
sudo systemctl daemon-reload
sudo systemctl enable --now hidra-node
sudo journalctl -u hidra-node -f
```

### Docker

```dockerfile
FROM rust:1.80 AS build
WORKDIR /src
COPY hidra-node .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 hidra
COPY --from=build /src/target/release/hidra-node /usr/local/bin/
USER hidra
WORKDIR /data
EXPOSE 9150 7000
ENTRYPOINT ["hidra-node"]
```

```bash
docker build -t hidranet/node .
docker run -d --name hidra \
  -p 9150:9150 -p 7000:7000/udp \
  -v hidra-keys:/data/keys \
  -v $(pwd)/config.toml:/data/config.toml:ro \
  --restart unless-stopped \
  hidranet/node
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Tor does not get past 0% | The network blocks Tor | Configure a bridge; see the User Guide |
| "port 9052 already in use" | A previous instance is still shutting down | Wait 10 s; or close the other window |
| "port 8090 in use" | A second copy of the browser is open | Close the other window and restart |
| Node finds no peers | `bootstrap_nodes` is empty | Fill it in with bootstrap nodes |
| `Tor binary not found` | Tor was not downloaded | `npm run fetch-tor` |
| Node receives no connections | Firewall or NAT | Open 9150/tcp and 7000/udp; check port forwarding |
| `tor exited with code null` (macOS) | The bundled Tor is unsigned | Sign it separately — see the macOS section above |

Support: see the Contributing Guide for the channels, and for how to report a
problem usefully.
