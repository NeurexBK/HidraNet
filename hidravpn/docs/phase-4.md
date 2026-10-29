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

> **Changed since, by the anonymity audit (`anonymity.md`).** Some of what
> follows works differently now:
>
> - A node that admits openly is never joined: on every connection it is
>   asked to admit a key made for that one connection, the exit of two hops
>   through the entry. The page has no Join buttons, and the browser sends no
>   `join`. `hidravpn nodes join` stays on the command line, for root's `up`
>   with an invite.
> - Such admissions are paid for with a proof of work instead of being
>   counted per address.
> - A node is used for that only if its record lists `sessions` (and, as an
>   entry for an open exit, `admission-relay`).
> - Two hops under one operator need the person's yes.
>
> The text below is kept as written for phase 4.

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
  the socket, five seconds for a request and five for the answer, two
  mebibytes per request: a member of the group can be a nuisance, not a
  memory leak. On Windows the pipe's name proves nothing: any interactive
  user can make `\\.\pipe\hidravpn` while the service is stopped, and add an
  instance of it while the service runs (the pipe is made with eight as its
  limit, but an idle service holds one, and on a pipe the write right every
  client needs includes the right to add an instance; Node, behind the
  browser, opens a pipe for write that way or for read only, so it cannot be
  withheld). So the clients do not trust the name. The service makes a fresh
  X25519 key at every start, keeps its private half in memory, and writes the
  public half beside the token, with the token's rights (`control.pub`; on
  Linux in `/run/hidravpn`). The command line and the browser seal every
  request to it, a key of their own for each request (`seal.rs`: X25519,
  HKDF-SHA256, AES-256-GCM), and believe an answer only when it opens under
  the key the service derived for that request (each answer sealed under a
  random nonce of its own, so a request passed on twice gives nothing away).
  Both are written only once the service holds its channel, so one that
  could not have it leaves the running service's alone; beside their place
  and moved into it, the key first, so a client never finds the new token
  without the new key. Whatever else answers sees neither the control token
  nor an account token, cannot answer in the service's place, and cannot
  change an answer it passes on: the browser shows "Service unavailable",
  the command line refuses. The command line also refuses a pipe whose
  server is not in session 0 (where services live). A plain request is still answered, so an older browser or command
  line keeps working with a newer service (without that protection); a newer
  browser asks a Windows service that has no key nothing and says "Update
  HidraVPN", and asks an older Linux service in the clear, as before (only
  root can make its socket). **Release order:** a HidraVPN release that
  writes `control.pub` (the version after 0.1.1) must be signed and
  published before, or with, the first browser that seals; a browser out
  first would show every Windows user "Update HidraVPN" with nothing newer
  to install (the page cannot read the installed version from a service it
  does not ask, so it offers the current signed release, which would put
  the same old service back). And the service never runs without its
  channel: it makes the socket or the pipe's first instance before it tells
  the system it is running, and when it cannot (on Windows: someone already
  holds the name; on Linux: a service already running answers on the socket,
  which a second one started by hand would otherwise take from it), or when
  the channel ever ends, it stops with an error.
  The SCM logs it and tries again three times, a minute apart. The data
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
  an address inside the client's own private tunnel subnet; one that names a
  resolver anywhere else is refused. The client routes that address into the
  tunnel by a host route of its own and checks that it goes there, and the
  kill switch lets DNS out only through the tunnel, to that address, so a
  local network that routes the address to itself (a pushed route, a subnet
  on the same range) receives no query. A lease granted openly expires after `--idle-days` (30)
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
  forwards only WireGuard (UDP 51820) onward, and the admission requests a
  client sends an exit through it (TCP 51821, see `anonymity.md`), and nothing
  to the internet; an
  exit forwards the internet and never mail (port 25) or the usual abuse
  ports (135–139, 445, 1433, 3389); both does both. Whatever the role, the
  tunnel reaches the node's outside interface and nothing else: not another
  interface of the host, and on the host itself only the DNS forwarder and a
  ping. The role travels in the record and in the invite, and the pocket's
  slots follow it: a node that admitted this client as an entry is not
  offered as an exit. An entry forwards to UDP 51820 only, so an exit meant
  to be reached through entries listens on that port, the default.
- **Who runs the pair.** Every record and invite names its operator. Privado
  takes an entry and an exit run by different operators. A pair under one
  operator, or whose operators the list does not name, is refused unless the
  person says yes (`allow_same_operator`, `--allow-same-operator`, a box on
  the page, off by default); `status` then says `same_operator`. A new
  identity never moves to such a pair by itself. (Changed by the anonymity
  audit, `anonymity.md`: it used to fall back silently. In Phase 0 every exit
  is the maintainers', so Privado needs that yes until a second operator
  runs nodes.)
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

## Completing the phase: install from the browser, the leak test, the route

The first round of this phase left a person to install the service by hand.
The second closes that, and the three things the original plan asked of the
page that were still missing.

- **Activate HidraVPN, from the page.** When the service is not installed the
  page shows one card and one button. The browser fetches the release
  manifest from `https://hidranet.org/vpn/release/manifest.json` with its
  `.sig`, checks the signature against the release key it carries **before
  parsing a byte of it**, downloads this platform's files into a fresh folder
  only this account can read, checks every file's size and SHA-256 against the
  manifest, and only then asks the system for administrator rights, once —
  UAC on Windows, `pkexec` on Linux. With those rights a fixed script copies
  the files into a folder only an administrator can write (`/var/lib` on
  Linux, Program Files on Windows), checks each copy's SHA-256 against the
  signed manifest again, and only then runs `hidravpn-service install
  --client hidravpn [--user <this account>]` from that copy
  (`src/main/vpn-installer.js`). The second check is what stops another
  program running as this user from swapping a file in the download folder
  after the first one: whatever was swapped in would otherwise run as root or
  Administrator. Names, paths and hashes travel to the elevated script as
  data, never inside it. A refused prompt is reported as cancelled; nothing is
  half-installed.
- **Update and remove, from the same page.** "Check for an update" reads the
  signed manifest and compares its version with the one the service now
  reports in `status` (`version`); "Install the update" runs the same path for
  that manifest, and
  the installer stops the running service before replacing it (a running
  binary cannot be overwritten), keeps the machine's key, and starts it again.
  "Uninstall HidraVPN" disconnects, then runs the installed service's own
  `uninstall`; with the box ticked, `uninstall --purge`, which also removes the
  programs, the pocket and the machine's key (on Windows the program folder
  goes a few seconds after the process exits, since a running executable
  cannot delete itself).
- **The service installs completely on its own.** `install` now validates
  everything first (a `--user` that is not a login name is refused before the
  service is touched), copies the client beside the service with `--client`,
  puts the account in the `hidravpn` group with `--user`, and makes this
  machine's key if there is none. An existing key is never replaced: every
  node this machine was admitted on knows it by that key.
- **The release manifest.** `scripts/make-release-manifest.sh` writes it from
  the release folders; the maintainers sign it offline with `hidravpn-sign
  sign` and publish both. Nothing is served there yet: until it is, the button
  says it could not fetch the release, exactly like the node list.
- **Only forward, unless the person says otherwise.** Every past manifest
  stays validly signed, so, as with the node list, the manifest carries a
  `sequence` that goes up with every manifest published and an `expires`
  (90 days by default), both under the signature. The browser refuses an
  expired manifest, one with a lower sequence than the highest it has accepted
  (kept in `vpn-release.json` in its data folder), and a release below the
  oldest it installs (`MIN_VERSION`). It installs exactly the manifest the
  page was shown: the page passes the version and digest "Check for an
  update" returned, and a manifest fetched again that differs stops the
  install before anything is downloaded. A release older than the service
  the machine has (as the service says, or, when it is stopped or this
  account cannot ask it, as the version written in the installed copy says)
  is installed only after the browser's own dialog asks the person,
  separately; the service then has to be told too: `install` reads
  the version written in the installed copy and refuses to replace a newer one
  without `--allow-downgrade`. The 0.1.0 manifest, from before `sequence` and
  `expires`, counts as sequence 0 with no expiry, so it still installs until
  a later one has been seen, or until `MIN_VERSION` is raised past it
  (code-signing.md says when).
- **A one-click leak test** (`src/main/vpn-leaktest.js`). While connected, it
  asks api.ipify.org and api6.ipify.org which address they see — from a
  session with no proxy, as any other program on the machine would, because
  the browser's own tabs go through Tor whatever the VPN does — and reads the
  kill switch from the service. IPv4: pass when the exit node's address is
  seen, a warning naming both addresses when another is, never a pass when
  the check did not answer. IPv6: a leak if anything answers. DNS: no query
  can leave outside the tunnel while the kill switch is armed. It runs only
  when the button is pressed.
- **Allow the local network**, a box under Connect, off unless ticked; the
  main process passes `allow_lan` to the service only for a strict `true`.
  It opens the private ranges off the tunnels (the physical link, and the
  machine's own bridges), both ways, and never DNS: names go to the node
  through the tunnel, on Linux as on Windows. Through the tunnel itself
  only answers come in, ticked or not, whatever address the node puts on a
  packet: the node cannot open a connection to this machine.
- **The route, with countries.** A signed list may now say where each node is
  (`"country": "FI"`, two letters, ISO 3166-1 alpha-2, validated as such;
  `hidravpn-node init --country FI` puts it in the node's own description). It
  travels into the invite and the pocket — a newer list updates it like the
  operator or the endpoint — and `status` reports it per hop. The page shows
  *This machine → FI · hel-1 → DE · fra-2 → Internet*, as a flag where the
  system draws flags and as the two letters always. The country is what the
  list's signer says, not something measured.

Checked by: `scripts/test-client-installer.sh` (17 checks, run for real as
root with systemd stood in for: install, update, refusal, uninstall, purge,
and the whole chain — a manifest made by the script, signed by
`hidravpn-sign`, accepted by the browser's installer, which installs the
download), `hidra-browser/test/vpn-installer.js` (16),
`hidra-browser/test/vpn-leaktest.js` (8), `hidra-browser/test/vpn-page.js`
(50) and a unit test for the country. On Windows, `scripts/windows/phase4-test.ps1`
is the checklist for the real PC: install and update over the pipe the
browser uses, the data folder's rights, connect with and without the local
network, the leak checks, uninstall and purge. **It has not run on hardware
yet.**

Not done here, on purpose: the `HIDRAVPN_ENABLED` switch the original plan
asked for, which would hide the page by default. The page has been visible
since the first round and installs nothing on its own, so hiding it now would
only remove the way to install; whether to hide it is the maintainers' call.

## What the browser never sees

The browser's module sends six commands — `status`, `connect`, `down`,
`new_identity`, `nodes` (and, before the audit, `join`) — and `import_nodes` with the text of a list
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
sudo hidravpn up --privado                        # two hops; open nodes are asked for a key for this connection

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

After the anonymity audit (`anonymity.md`), add:

```
sudo bash hidravpn/scripts/test-anonymity-netns.sh   # who can see what: captures, counters, the exit's own peer table, logs at DEBUG
```

It proves, in 46 checks (3 more for IPv6 print SKIP on a kernel without
IPv6), that no node that admits openly sees the same key twice, that the
exit of two hops never hears from the client's address, that the entry
learns no destination, that admission is paid in work rather than counted
per address, that a node not yet updated is passed over, that two hops
under one operator need the person's yes, that nothing leaves outside the
tunnel through a rotation, a reconnect or a dead exit, and that no log at
DEBUG names the client. With it the counts are: unit tests 98,
`test-netns.sh` 24, `test-killswitch.sh` 14, `test-service-netns.sh` 19,
`test-multihop-netns.sh` 76, `test-admission-netns.sh` 37,
`test-browser-netns.sh` 28, `test-directory.sh` 23, `test-node-installer.sh`
32, `test-client-installer.sh` 17.

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
#    entry on the folder, the key or the pocket; Interactive read on the
#    token and the service's public key.
icacls "$env:ProgramData\HidraVPN"; icacls "$env:ProgramData\HidraVPN\control.token"
icacls "$env:ProgramData\HidraVPN\control.pub"; icacls "$env:ProgramData\HidraVPN\client.key"

# 5. A plain user cannot plant a file in the folder (Access denied). A plain
#    user can add a pipe instance; while it is open, `hidravpn status` from
#    another window either answers as the service or refuses ("something
#    other than the HidraVPN service"), and the browser's VPN page shows the
#    real state or "Service unavailable", never anything else.
New-Item "$env:ProgramData\HidraVPN\probe.txt" -ItemType File
$s=[IO.Pipes.NamedPipeServerStream]::new('hidravpn',[IO.Pipes.PipeDirection]::InOut,-1); $s.WaitForConnection()

# 6. (administrator) `hidravpn up invite.json` still works elevated, and
#    phase3-test.ps1 still passes.

# 7. (administrator: Stop-Service HidraVPN first; then the pipe as a plain
#    user, in its own window, kept open) With the name taken, the service
#    does not start: Start-Service fails, `sc.exe query HidraVPN` shows
#    STOPPED with a service-specific exit code of 1, and service.log says
#    "another program may already hold that name". Close the plain user's
#    pipe and Start-Service works again.
$s=[IO.Pipes.NamedPipeServerStream]::new('hidravpn',[IO.Pipes.PipeDirection]::InOut,-1)
Start-Service HidraVPN; sc.exe query HidraVPN
Get-Content "$env:ProgramData\HidraVPN\service.log" -Tail 5
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
  PC with the checklist below, and `phase3-test.ps1` must still pass. On
  Windows the service is now registered with the SCM (it was a scheduled
  task); the control channel is still polled by the page every two seconds,
  not pushed; macOS has no kill switch and no service.
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
- **The pair may still be one operator's, if you say so.** Privado refuses
  one operator's pair unless the person ticks the box. In Phase 0 every exit
  is the maintainers', and until an independent entry is listed every entry
  is too, so Privado's sentence — no node sees both — is then true of the
  nodes and not of their operator, and the page says so.
- **A pipe can be squatted, and it costs only the channel.** Any signed-in
  user may make `\\.\pipe\hidravpn` while the service is stopped, or add an
  instance beside the service's while it runs. Made first, it keeps the
  service from starting (the start fails, with an error in `service.log`
  and the system's event log). The SCM tries three more times, a minute
  apart; held past those, the service stays stopped until someone starts it
  (`Start-Service HidraVPN`, or Install or Update on the page) or the
  machine restarts. While the name is held the page shows "Service
  unavailable" (whatever holds it cannot answer as the service), and once
  it is let go, the service as stopped.
  Beside the service, it may be the instance a client reaches. Either way
  the command line and the browser seal their requests and refuse an answer
  that does not open, so that pipe learns no token and cannot show a made-up
  state of the VPN; it can only keep a client from being answered, and the
  page then says "Service unavailable". An older browser, which does not
  seal, would still believe it: update both. The leak test measures the
  address websites see and IPv6; the kill switch and DNS rows repeat the
  service's own report, which can no longer come from anything else.
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
