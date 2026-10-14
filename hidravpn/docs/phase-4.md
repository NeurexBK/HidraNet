# HidraVPN — Phase 4: the VPN in the browser, and the first nodes

What exists after this phase: the HidraNet Browser drives the HidraVPN service
installed on the machine — connect in Rápido or Privado, disconnect, a new
identity, the kill switch and every hop read live from the service — without
ever holding an invite or a key; a **signed node list** the maintainers can
publish so a new client knows which nodes exist and who runs them, checked
against a release key built into the client before a byte of it is read; the
same release key verifying downloaded release files inside the browser; a
one-command installer for a node on a rented server; leases that survive a
node's reboot; and an exit policy in every node's firewall.

Everything is still in `hidravpn/` and the browser's own files; the relay
engine, mail, chat and forum are untouched.

This phase was shaped by a criticism received in October 2026 — *who will
host this, and why; there is no portless design* — and by the plan written in
answer to it, `docs/business/16-network-bootstrap.md`. What is here is the
code that plan needs: the first nodes are the maintainers' own, on servers,
a client has to be able to find them, and a stranger has to be able to
connect on the first try — which is what open admission below is. What it
does **not** do is make that admission accountable (Phase 5's passes) or run
a node behind a home router (doc 16 §7). The section at the end says so.

## What is new

- **The service picks the nodes.** Two commands on the control channel:
  `connect` (`mode`: `rapido` or `privado`) picks from the pocket this machine
  holds, uniformly and never logged, and brings the circuit up; `nodes` lists
  the pocket by slot, name and endpoint. No request returns a key, and the
  browser never sends an invite: `up` with invites stays for the command line.
- **The browser asks, the service decides.** `hidra://vpn` (also a card on
  the new tab page) talks to the service through the main process
  (`src/main/vpn-manager.js`): one request, one answer, one line of JSON, the
  token read fresh each time. The bridge (`window.hidra.vpn`) is offered to
  our own pages only, and the main process checks the caller again before
  every call. Nothing on the page is fixed: the kill switch reads "Unknown"
  until the service has said "Armed" or "Off"; the two sentences on what each
  mode hides are the service's own, word for word, checked by a test.
- **Who may drive the service, and how far.** The browser runs as the
  person, not as root, so on Linux the service's installer makes a `hidravpn`
  group and the client installer puts the person who ran it in it; the socket
  (0660), the token (0640) and their directory (0750) belong to that group.
  On Windows the control pipe's security descriptor lets any interactive user
  (console or Remote Desktop) open it for reading and writing — its default
  let a user read only — and the token under `ProgramData` is readable by
  interactive users and nobody else. What a member (or, on Windows, an
  interactive user) may do: `connect` from the pocket, `down`,
  `new_identity`, `nodes`, and import a *signed* list. What only root (an
  elevated prompt on Windows) may do: `up` with an invite, because an invite
  of one's own would route the whole machine through a node nobody vetted.
  The service learns who is asking from the socket (`SO_PEERCRED`) or the
  pipe (the client process's elevation). The client key stays root-only; no
  request returns a key.
- **The control channel holds its ground.** Sixteen connections at once on
  the socket, five seconds for a request and five for the answer, one
  mebibyte per request: a member of the group can be a nuisance, not a
  memory leak. On Windows the service holds all eight instances of its pipe
  for as long as it runs, and the pipe is made with eight as its limit, so no
  other user can ever add an instance of `\\.\pipe\hidravpn` and answer a
  client in the service's place; the command line also refuses to speak to a
  pipe whose server is not in session 0 (where services live). The data
  folder under `ProgramData` is taken and given rights inherited from nowhere
  at install, so no user can plant a `client.key` or a pocket there first.
- **A signed node list** (`hidravpn-core/src/directory.rs`). A JSON file —
  `version`, `generated`, `sequence`, `expires`, `removed`, `note`, and
  `nodes`, each a name, a public key, an endpoint, who runs it, how to ask
  them, its role and how it admits — signed with `hidravpn-sign sign` like any
  release file. `scripts/make-node-list.sh` builds one from the records the
  nodes print (`hidravpn-node record`), numbers it, dates it (ninety days by
  default) and signs it. `hidravpn nodes import nodes.json` (and the
  service's `import_nodes`, which the browser uses) verifies the signature
  over the exact bytes against the **list key built into the client**, and
  only then parses the list, validates every record and writes the nodes
  down as **known**. A client refuses a list past its expiry, refuses one
  whose sequence is older than the one it already holds, and strikes from
  its pocket every node the list names under `removed`. A refused list leaves
  the pocket on disk untouched; a node admitted by hand or openly is not
  demoted by a later import. A newer list (a higher sequence) brings what the
  pocket holds about a node that kept its key up to date — its endpoint,
  operator, role, contact and admission, known or admitted — so a node that
  moves servers is followed without a key rotation; an admitted node's slots
  follow its role, and what its admission gave the client (its tunnel
  address, the DNS) stays. The import says what changed about each. A list
  nobody signed, or changed after signing, or signed with another key, goes
  nowhere.
- **Open admission** (`hidravpn-core/src/admission.rs`,
  `hidravpn-node/src/admission.rs`). This is what lets a stranger connect. A
  node started with `--open-admission` runs a small HTTP service on TCP 51821
  beside the tunnel: `GET /` answers with the node's record, `POST /admit`
  with a client's public key and a name answers with an invite — the same
  invite `hidravpn-node admit` prints by hand. It admits at most three
  clients per address and 120 per node every ten minutes, holds at most
  `--max-clients` (4000) leases, keeps thirty-two connections and five
  seconds per request, and refuses a key that is not a key before it counts
  against anyone. On the client, `hidravpn nodes join NAME` (or `--all`), the
  browser's *Join* buttons, and `connect` itself when the pocket holds only
  known nodes, ask every known open node for admission; an invite whose key
  or endpoint differs from the record the signed list carried is refused, so
  a node that admits openly can admit a stranger but cannot send them
  somewhere else. Nor can anyone between them change where the client's
  lookups go: every invite, however it arrived, must name as its DNS server
  an address inside the client's own private tunnel subnet, which only the
  node answers; one that names a resolver anywhere else is refused. A lease granted openly expires after `--idle-days` (30)
  without a handshake — the node writes each client's last handshake down
  every quarter of an hour and when it stops, so a restart is not idleness —
  and one whose client never shook hands lapses within fifteen minutes, so
  filling a node costs real tunnels, not requests. A lease granted by hand
  never expires. What the pocket remembers about a node that admitted this
  client openly is what the signed list said — name, operator, role — not
  what the node claims. A node that admits
  by hand still describes itself on `GET /` and answers `/admit` with `403`
  and whom to ask. `hidravpn nodes discover IP[:PORT]` reads a node's record
  by address and, with `--trust`, writes it down as known — for a node you
  know by other means than a list, such as your own.
- **Roles** (`--role entry|exit|both`, `hidravpn-node/src/nat.rs`). An entry
  forwards only WireGuard (UDP 51820) onward and nothing to the internet; an
  exit forwards the internet and never mail (port 25) or the usual abuse
  ports (135–139, 445, 1433, 3389); both does both. Whatever the role, the
  tunnel reaches the node's outside interface and nothing else: not another
  interface of the host, and on the host itself only the DNS forwarder and a
  ping. The role travels in the record and in the invite, and the pocket's
  slots follow it: a node that admitted this client as an entry is not
  offered as an exit. An entry forwards to UDP 51820 only, so an exit meant
  to be reached through entries listens on that port, the default.
- **Who runs the pair.** Every record and invite names its operator. Privado
  prefers an entry and an exit run by different operators when the pocket
  has them, `status` says `same_operator` when it could not, and the page
  shows it in so many words. It does not refuse the pair: in Phase 0 every
  node is the maintainers', and refusing would mean no Privado at all.
- **A circuit belongs to the account that opened it.** The service remembers
  the user id (`SO_PEERCRED`) that sent `connect` or `up`; `down` and
  `new_identity` from another account are refused, with the reason. Root may
  do either, and a circuit root switched on is root's: a member of the group
  cannot switch it off. On Windows the caller is "elevated or not", so the
  owner is the elevated prompt or everyone interactive.
- **Two keys** (`hidravpn-core/src/release.rs`,
  `hidra-browser/src/main/release-verify.js`). The **release key** says "this
  file came from HidraVPN's maintainers"; the **list key** says "this node
  list did". Both are Ed25519. The maintainers made them offline with
  `hidravpn-sign keygen` (the secret halves never entered the repository or
  any build machine) and `scripts/embed-release-key.sh` pasted the public
  halves into the Rust and the JavaScript constants together; tests keep each
  pair identical. The same script rotates a key. A build with an empty
  constant verifies nothing: a client that accepted unsigned lists "for now"
  would be a client that accepts unsigned lists.
- **The list reaches the browser by itself.** *Get the list* on the VPN
  page fetches `https://hidranet.org/vpn/nodes.json` and its `.sig` through
  the main process (one mebibyte at most) and hands both texts to the
  service, which verifies them; the page never decides what is genuine. The
  address is a constant in `main.js`, to be served once Phase 0 has nodes to
  publish.
- **A prober** (`scripts/probe-nodes.sh`). From any machine with the client,
  it connects through each node in the pocket in turn, checks that the
  internet answers and sees the exit's address, writes `status.json` and a
  readable `status.md`, and puts the network back. Run it from cron on a
  machine that is not a node, and the uptime numbers in doc 16 become
  measured instead of hoped. On a machine without the service it holds the
  circuit in a `hidravpn up --direct` of its own and stops it with SIGTERM,
  which `up` now treats like Ctrl+C: the network is restored, never left
  behind a kill switch by a `kill`.
- **What an operator needs to know** is written down: `docs/running-nodes.md`
  (renting a server, installing a node, what open admission means, publishing
  the list, probing) and `docs/operators/abuse-response.md` (what an exit's
  operator answers to an abuse complaint, with a template).
- **Release files verified in the browser.** "Verify a downloaded file" on the
  VPN page checks FILE against FILE.sig with that key, in the same format
  `hidravpn-sign verify` uses; a test signs with one tool and verifies with the
  other, both ways.
- **A node in one command** (`scripts/install-node-linux.sh`): installs
  `hidravpn-node`, makes its key and settings once (`--role`, `--operator`,
  `--contact`, `--open-admission`, `--admission-port`), installs the hardened
  systemd unit, opens the UDP port and, for open admission, the TCP port in
  ufw or firewalld (or prints the rules), prints the node's record for the
  list — and says, in plain words, what running an exit means. `--dry-run`
  prints every step and changes nothing.
- **A limit on the control channel.** A request is one line; past 1 MiB it is
  cut and refused rather than buffered.
- **Leases survive a reboot** (`hidravpn-node/src/leases.rs`). Admitted
  clients now live in `/var/lib/hidravpn/peers.json` (systemd's
  `StateDirectory`), not in RAM: a kernel update on a rented server no longer
  throws every client out, which on the client looked like the worst case —
  kill switch armed, no session, no internet.
- **An exit policy in every node** (`hidravpn-node/src/nat.rs`). Mail (port
  25) and the usual abuse ports (135–139, 445, 1433, 3389) never leave a
  node from the tunnel, whatever its role. The browser suite checks it from
  the client's side: a connection to port 25 times out instead of being
  refused.

## What the browser never sees

The browser's module sends six commands — `status`, `connect`, `down`,
`new_identity`, `nodes`, `join` — and `import_nodes` with the text of a list
the person chose in a file dialog or that the main process fetched from the
published address. It never reads the pocket, never sees an
invite, never sees a key, and never decides whether a list is genuine: the
service that writes the pocket is the one that has to be convinced, so the
service checks the signature. The browser does not verify the list itself on
purpose; a convinced browser feeding an unconvinced service would be the wrong
way round, and a test guards against it. Admission is the same: `join` asks
the service, and the service asks the node; the invite goes from the node to
the service's pocket without passing through the browser.

## Command lines

```
sudo hidravpn nodes import nodes.json             # the maintainers' list, checked against the built-in list key
sudo hidravpn nodes import nodes.json --pubkey K  # a key that reached you by another channel
sudo hidravpn nodes list                          # what the pocket holds: role, admission, operator; never keys
sudo hidravpn nodes join --all                    # ask every known open node for admission
sudo hidravpn nodes join <name>                   # ask one
sudo hidravpn nodes discover <ip>[:51821] --trust # a node you know by other means (your own)
sudo hidravpn up --rapido --node <name>           # one hop through that node
sudo hidravpn up --privado                        # two hops; joins first if the pocket only knows nodes

# on a server
sudo bash hidravpn/scripts/install-node-linux.sh --endpoint <public-ip>:51820 --name <name> \
     --role exit --operator "<who>" --contact "<how>" --open-admission
hidravpn-node record                              # what the list carries about this node

# the maintainers
bash hidravpn/scripts/make-node-list.sh --key list.key --out nodes.json --sequence N record-*.json
sudo bash hidravpn/scripts/probe-nodes.sh --out probe/   # connect through every node, write status.md
bash hidravpn/scripts/embed-release-key.sh --release <pub> --list <pub>   # once, after keygen offline
```

In the browser: `hidra://vpn`, or the HidraVPN card on the new tab page.

## How to check it

On Linux, as root, with the release binaries built and `node` installed:

```
hidravpn/scripts/test-admission-netns.sh    # open admission, roles, the list with a sequence, the prober
hidravpn/scripts/test-browser-netns.sh      # the browser's module against a real service and node
hidravpn/scripts/test-directory.sh          # the signed list, through the command line
hidravpn/scripts/test-node-installer.sh     # the installer, in --dry-run
cargo test --manifest-path hidravpn/Cargo.toml --workspace
```

`test-admission-netns.sh` is the suite for this round. Four namespaces — a
client, an entry node, an exit node and "the internet" — with the two nodes
started by `hidravpn-node init --role exit|entry --open-admission` under one
operator. It proves, in 36 checks:

- `init` records the role and the admission mode; both nodes come up with
  their admission service; `hidravpn-node record` prints each one's record;
  `make-node-list.sh` turns the two records into a signed list with a
  sequence and an expiry; `nodes discover` reads a node by address and trusts
  nothing by itself;
- the import makes both nodes known and none connectable; `nodes list` shows
  role and open admission; with known nodes that admit by hand only, `up`
  is refused and says whom to ask;
- `connect rapido` with only known nodes in the pocket joins both through
  open admission and connects, the pocket now holding node-a as exit and
  node-b as entry; each node logged an admission as a count, never a key;
- one hop reaches the internet through the exit; `up --rapido --node` with
  a pocket that only knows the nodes joins the node by itself, connects, and
  puts the network back on SIGTERM; two hops go entry then exit, `status`
  says both are one operator's, and the internet still sees the exit; root
  may still hand the service an invite; a node admits up to `--max-clients`
  and then answers 503;
- an entry-role node does not forward HTTP (the request times out, dropped
  by its policy); a key that is not a key is refused with `400` and does not
  count against the address; the admission service admits a few and then
  rate-limits the address (`200 200 429 429 429`); an unknown path is `404`;
  a node switched to admitting by hand answers `403` with whom to ask and
  still describes itself;
- the prober, first through the service and then holding the circuit
  itself, connects through the node, sees the exit's address, writes
  `status.json` and `status.md`, and puts the network back; the node writes
  our last handshake down when it stops, and restarted with a twelve-second
  idle window it forgets the probes that never shook hands, keeps us, and
  forgets us too once we have been quiet for the window;
- no node or service log names the client's address, a lease or a key.

`test-browser-netns.sh` runs the three namespaces of `test-service-netns.sh`
and drives everything through `hidra-browser/src/main/vpn-manager.js` — the
exact module the page uses — as an unprivileged user in the `hidravpn` group.
It proves, in 28 checks:

- the socket is `root:hidravpn 0660`, the token `root:hidravpn 0640`, the
  directory the group's, and the client key still `root:root 0600`;
- a user outside the group cannot even read the token; a member can;
- `nodes` names the exit without a key; `connect privado` with no entry in
  the pocket is refused by the service, with the reason, and changes nothing;
- `connect rapido` connects through the node the service picked; the internet
  sees the node's address; the kill switch is armed in the kernel and the
  default route goes into the tunnel; a connection to port 25 from the tunnel
  times out, dropped by the node's exit policy, instead of being refused;
- `new_identity` with one exit says the address did not change; `down` lifts
  the kill switch, removes the routes, restores `resolv.conf`, and the client
  is back on its own network;
- no service or node log names the client's address or name.

`test-directory.sh` makes a list key with `hidravpn-sign`, signs a list of
three nodes, and checks that `nodes import` refuses it with no key built in
and none given, makes the three known with the key (and connectable to
none: `up --rapido` is refused with what to do), adds nothing on a second
import, refuses a list changed after signing, one signed with another key,
one with no `.sig`, and a key that is not a key — the pocket knowing exactly
the three throughout, carrying no client address, readable by root only;
then an admission on one of them turns it into an exit, and importing the
list again does not demote it.

In the browser (`hidra-browser/`), `node test/vpn-manager.js` drives the
module against a stand-in service: every command, and every way the service
can be absent — not installed, not running, not this user's to open, a stale
token, an answer that is not an answer, no answer, a flood — comes back as a
state the page shows, never a crash. `node test/vpn-page.js` lints the page
and its wiring; `node test/release-verify.js` signs with `hidravpn-sign` and
verifies here, and the other way round; `xvfb-run -a npx electron --no-sandbox
test/preload-boundary.js` proves a downloaded `.html` and every website get no
`vpn` bridge.

Then the existing suites still pass: unit tests (78 in the workspace),
`test-netns.sh` (24), `test-service-netns.sh` (19), `test-multihop-netns.sh`
(73), `test-browser-netns.sh` (28), `test-directory.sh` (19),
`test-node-installer.sh` (32), and every browser test.

## How to check it on Windows

By hand, on a PC with the service installed from this build, in PowerShell.
Lines 1–5 as a **non-elevated** standard user; 6 as an administrator.

```
# 1. The service runs as SYSTEM in session 0.
Get-Process hidravpn-service | Select-Object Id, SessionId

# 2. A plain user can open the pipe for reading and writing, and the
#    descriptor is the one the service set (generic bits already mapped).
$p=[IO.Pipes.NamedPipeClientStream]::new('.','hidravpn',[IO.Pipes.PipeDirection]::InOut); $p.Connect(2000)
$p.GetAccessControl().GetSecurityDescriptorSddlForm('Access'); $p.Dispose()
#    expected: D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;IU)

# 3. The token is readable by this user and the service answers `status`.
hidravpn status

# 4. The folder and the files carry the rights the installer set: no Users
#    entry on the folder, the key or the pocket; Interactive read on the token.
icacls "$env:ProgramData\HidraVPN"; icacls "$env:ProgramData\HidraVPN\control.token"
icacls "$env:ProgramData\HidraVPN\client.key"

# 5. A plain user can neither plant a file in the folder nor add a pipe
#    instance; both must be refused (Access denied / All pipe instances are busy).
New-Item "$env:ProgramData\HidraVPN\probe.txt" -ItemType File
[IO.Pipes.NamedPipeServerStream]::new('hidravpn',[IO.Pipes.PipeDirection]::InOut,-1)

# 6. (administrator) `hidravpn up invite.json` still works elevated, and
#    phase3-test.ps1 still passes.
```

## What is honest about this phase

- **The keys are real now, and so is what they are worth.** The release
  and list public keys are built into this client. The secret halves live
  offline with the founders, backed up in two places; whoever holds the list
  key can name nodes to every client, so a lost or leaked list key means a
  new key and a client release, not a quiet rotation. A list signed with any
  other key, including a test key, is refused by this build unless the key
  is given explicitly with `--pubkey`.
- **The list is not published yet.** The browser fetches
  `https://hidranet.org/vpn/nodes.json`; nothing is served there until Phase
  0 of the bootstrap plan has nodes to publish. Until then the button says it
  could not fetch, and `nodes import` takes the file wherever it was saved.
  The ten nodes themselves are rented servers at a few euros a month each;
  `docs/running-nodes.md` says where and how.
- **On Windows, nothing of this phase has run; it has only been compiled for
  the Windows target.** The pipe's descriptor, the instance pool, the
  elevation check, the session check and the `icacls`/`takeown` protection of
  the data folder are all untested at run time. The Linux half of the access
  model is proven in namespaces; the Windows half is to be checked on a real
  PC with the checklist below, and `phase3-test.ps1` must still pass. The
  service on Windows is still a scheduled task at boot, not a Windows
  service; the control channel is polled by the page every two seconds, not
  pushed; macOS has no kill switch and no service.
- **Open admission is open.** A node that admits openly admits anyone with
  a client, three per address and 120 per node every ten minutes, up to
  4000 leases. That is the point — a stranger connects on the first try — and
  it is also what every abuse complaint will come from. An exit run with open
  admission needs its operator to have read `docs/operators/abuse-response.md`
  first. The limits are per node and in memory: a restart forgets the
  counters, not the leases.
- **A lease that expired is not rejoined by itself.** When an openly
  admitted client has not handshaken for `--idle-days`, the node forgets it;
  the client still holds the invite and `connect` fails with no answer from
  that node. Today the person runs `nodes remove NAME`, imports or discovers
  the node again and joins; a client that notices the silence and asks again
  on its own is the next step.
- **The pair may still be one operator's.** Privado prefers two operators
  and says when it could not have them; it does not refuse. In Phase 0 every
  node is the maintainers', so Privado's sentence — no node sees both — is
  true of the nodes and not of their operator, and the page says so.
- **A pipe can be squatted while the service is down.** With the service
  running, every instance is the service's. With it stopped there is no pipe,
  and a user could make one: the command line notices (the server is not in
  session 0) and refuses; the browser cannot see the server's session and
  would show whatever that pipe answered. Low value to an attacker on a
  single-person machine; real on a shared one; said here so nobody is
  surprised.
- **Any signed-in user may drive the service on Windows, and any member of
  the group on Linux — and so may any program they run.** Connect,
  disconnect one's own circuit, a new identity, a join, an import of a
  signed list: not the key, and not a list nobody signed. On Linux a circuit
  belongs to the account that opened it and another account's `down` is
  refused; on Windows the service only knows "elevated or not", so every
  interactive account is one owner. The kill switch holds against the
  network dropping, not against local software of the owning account telling
  the service to disconnect.
- **The admission service is reachable by anyone who can reach the node.**
  It is six hundred lines of HTTP/1.1, tests included, with hard limits (8 KiB of headers,
  16 KiB of body, five seconds, thirty-two connections), not a web server;
  it answers two paths and refuses everything else. An error accepting a
  connection is waited out, never fatal: the tunnel outlives the admission
  service, and the node's unit restarts it in any case. It has been read by
  three reviewers and run under the suite above, not fuzzed.
- **A node can be filled, for a while.** With enough addresses, a script can
  take every lease of a node in hours; it cannot keep them, because a lease
  with no handshake lapses within fifteen minutes. A determined attacker who
  runs four thousand real tunnels holds the node until they stop; the answer
  to that is more nodes and Phase 5's accountable admission, not a cleverer
  limit here.
- **Portless entry is not this phase.** Every node, entry or exit, still
  needs one open UDP port and, for open admission, one TCP port; a node
  behind a home router stays on the roadmap (doc 16 §7).
- **Strong privacy, not anonymity**, as in every phase: the page says what
  each node sees in the service's own words, and nowhere says "anonymous".
