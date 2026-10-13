#!/usr/bin/env bash
# Make and sign the node list the maintainers publish.
#
#   hidravpn/scripts/make-node-list.sh --key list.key --out nodes.json --sequence N \
#       [--expires 2027-01-01T00:00:00Z] [--note "..."] [--removed KEY]... record.json...
#
# Each record.json is what `hidravpn-node record` prints on a node. The list
# is written to --out and signed beside it (--out.sig) with the LIST key, the
# one whose public half is LIST_PUBLIC_KEY_B64 in the clients. --sequence
# must go up with every list published; a client refuses an older one.
# --expires defaults to 90 days from now. --removed names a node (its public
# key) that clients must forget, admitted or not.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SIGN="${HIDRAVPN_SIGN:-$HERE/../target/release/hidravpn-sign}"
KEY=""; OUT=""; SEQ=""; EXPIRES=""; NOTE=""; REMOVED=(); RECORDS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --sequence) SEQ="${2:?}"; shift 2 ;;
    --expires) EXPIRES="${2:?}"; shift 2 ;;
    --note) NOTE="${2:?}"; shift 2 ;;
    --removed) REMOVED+=("${2:?}"); shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) RECORDS+=("$1"); shift ;;
  esac
done
[ -n "$KEY" ] && [ -n "$OUT" ] && [ -n "$SEQ" ] || { echo "--key, --out and --sequence are required" >&2; exit 2; }
[ ${#RECORDS[@]} -gt 0 ] || [ ${#REMOVED[@]} -gt 0 ] || { echo "give at least one record.json (or --removed)" >&2; exit 2; }
[ -x "$SIGN" ] || { echo "hidravpn-sign is not built at $SIGN (set HIDRAVPN_SIGN)" >&2; exit 1; }
[ -n "$EXPIRES" ] || EXPIRES="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 -I - "$OUT" "$SEQ" "$EXPIRES" "$GENERATED" "$NOTE" "${#REMOVED[@]}" "${REMOVED[@]}" "${RECORDS[@]}" <<'PY'
import json, sys
out, seq, expires, generated, note, nrem = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
removed = sys.argv[7:7 + nrem]
records = sys.argv[7 + nrem:]
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
open(out, "w").write(json.dumps(doc, indent=2) + "\n")
print(f"{out}: {len(nodes)} node(s), {len(removed)} removed, sequence {seq}, expires {expires}")
PY
"$SIGN" sign --key "$KEY" "$OUT" >/dev/null
echo "signed: $OUT.sig  (publish both files; clients check the signature against the list key built into them)"
