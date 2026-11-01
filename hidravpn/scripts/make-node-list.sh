#!/usr/bin/env bash
# Make and sign the node list the maintainers publish.
#
#   hidravpn/scripts/make-node-list.sh --key list.key --out nodes.json --sequence N \
#       [--expires 2027-01-01T00:00:00Z] [--note "..."] [--removed KEY]... \
#       [--issuer-url https://... --pass-key key-record.json... \
#        [--pay-wallet ADDR [--pay-mint MINT]]] record.json...
#
# Each record.json is what `hidravpn-node record` prints on a node. The list
# is written to --out and signed beside it (--out.sig) with the LIST key, the
# one whose public half is LIST_PUBLIC_KEY_B64 in the clients. --sequence
# must go up with every list published; a client refuses an older one.
# --expires defaults to 90 days from now. --removed names a node (its public
# key) that clients must forget, admitted or not. --issuer-url and
# --pass-key (what `hidravpn-issuer record` prints; give the current key and
# the next during a rotation) name the pass issuer, for nodes that admit with
# a pass (phase 5). --pay-wallet is the Solana wallet passes are paid to (the
# issuer's own --pay-wallet), and --pay-mint the token, when it is not HNET
# (phase 7): a client buys only from a list that names the wallet, and pays
# no other wallet or token.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SIGN="${HIDRAVPN_SIGN:-$HERE/../target/release/hidravpn-sign}"
KEY=""; OUT=""; SEQ=""; EXPIRES=""; NOTE=""; REMOVED=(); RECORDS=(); ISSUER=""; PASSKEYS=(); WALLET=""; MINT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --sequence) SEQ="${2:?}"; shift 2 ;;
    --expires) EXPIRES="${2:?}"; shift 2 ;;
    --note) NOTE="${2:?}"; shift 2 ;;
    --removed) REMOVED+=("${2:?}"); shift 2 ;;
    --issuer-url) ISSUER="${2:?}"; shift 2 ;;
    --pass-key) PASSKEYS+=("${2:?}"); shift 2 ;;
    --pay-wallet) WALLET="${2:?}"; shift 2 ;;
    --pay-mint) MINT="${2:?}"; shift 2 ;;
    -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) RECORDS+=("$1"); shift ;;
  esac
done
[ -n "$KEY" ] && [ -n "$OUT" ] && [ -n "$SEQ" ] || { echo "--key, --out and --sequence are required" >&2; exit 2; }
[ ${#RECORDS[@]} -gt 0 ] || [ ${#REMOVED[@]} -gt 0 ] || { echo "give at least one record.json (or --removed)" >&2; exit 2; }
{ [ -n "$ISSUER" ] && [ ${#PASSKEYS[@]} -gt 0 ]; } || { [ -z "$ISSUER" ] && [ ${#PASSKEYS[@]} -eq 0 ]; } || { echo "--issuer-url and --pass-key go together" >&2; exit 2; }
[ -z "$WALLET" ] || [ -n "$ISSUER" ] || { echo "--pay-wallet goes with --issuer-url and --pass-key" >&2; exit 2; }
[ -z "$MINT" ] || [ -n "$WALLET" ] || { echo "--pay-mint goes with --pay-wallet" >&2; exit 2; }
[ -x "$SIGN" ] || { echo "hidravpn-sign is not built at $SIGN (set HIDRAVPN_SIGN)" >&2; exit 1; }
[ -n "$EXPIRES" ] || EXPIRES="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 -I - "$OUT" "$SEQ" "$EXPIRES" "$GENERATED" "$NOTE" "$ISSUER" "$WALLET" "$MINT" "${#PASSKEYS[@]}" "${PASSKEYS[@]}" "${#REMOVED[@]}" "${REMOVED[@]}" "${RECORDS[@]}" <<'PY'
import json, sys
out, seq, expires, generated, note, issuer = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
wallet, mint = sys.argv[7].strip(), sys.argv[8].strip()
npk = int(sys.argv[9]); passkeys = sys.argv[10:10 + npk]
rest = sys.argv[10 + npk:]
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HNET_MINT = "Aov3BtQvrGXM5V9oiHu8PKJWeV8a2rFnr24fwWcNpump"  # payment::HNET_MINT
def address(flag, s):
    # payment::check_address: 32 bytes in base58, as clients check it.
    if not s or any(c not in B58 for c in s): sys.exit(f"{flag} {s!r} is not a Solana address")
    n = 0
    for c in s: n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(s) - len(s.lstrip("1")) + len(raw) != 32: sys.exit(f"{flag} {s!r} is not a Solana address (not 32 bytes)")
if wallet: address("--pay-wallet", wallet)
if mint: address("--pay-mint", mint)
if wallet and wallet == (mint or HNET_MINT): sys.exit("--pay-wallet is the mint itself; payments go to a wallet")
nrem = int(rest[0]); removed = rest[1:1 + nrem]
records = rest[1 + nrem:]
nodes = []
seen = set()
for path in records:
    r = json.load(open(path))
    for k in ("node_name", "node_public_key", "endpoint"):
        if not r.get(k): sys.exit(f"{path}: missing {k}")
    if r["node_public_key"] in seen: sys.exit(f"{path}: the key of {r['node_name']} is already in the list")
    seen.add(r["node_public_key"])
    nodes.append({k: v for k, v in r.items() if v is not None})
doc = {"version": 1, "generated": generated, "sequence": seq, "expires": expires}
if note: doc["note"] = note
if removed: doc["removed"] = removed
doc["nodes"] = nodes
if issuer:
    keys = []
    for path in passkeys:
        k = json.load(open(path))
        for f in ("id", "key", "not_after"):
            if not k.get(f): sys.exit(f"{path}: missing {f}")
        keys.append({"id": k["id"], "key": k["key"], "not_after": k["not_after"]})
    doc["pass_issuer"] = {"url": issuer, "keys": keys}
    if wallet: doc["pass_issuer"]["wallet"] = wallet
    if mint: doc["pass_issuer"]["mint"] = mint
open(out, "w").write(json.dumps(doc, indent=2) + "\n")
print(f"{out}: {len(nodes)} node(s), {len(removed)} removed, sequence {seq}, expires {expires}"
      + (f"; passes paid to {wallet}" + (f" in {mint}" if mint else " in HNET") if wallet else ""))
PY
"$SIGN" sign --key "$KEY" "$OUT" >/dev/null
echo "signed: $OUT.sig  (publish both files; clients check the signature against the list key built into them)"
