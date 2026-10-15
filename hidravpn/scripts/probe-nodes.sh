#!/usr/bin/env bash
# The uptime prober: tries every exit this machine can use — admitted on by
# hand, or known from the signed list as admitting openly (asked for a key
# of its own on each connection) — one at a time, and writes down which ones
# carried traffic. Run it hourly (cron or a
# systemd timer) on a small machine of the maintainers' that is admitted on
# every node; publish the status file. That is the uptime measurement
# docs/business/16 promises, the "a stranger connects" check, and an
# operator's "how do I know my node works".
#
#   sudo hidravpn/scripts/probe-nodes.sh [--out DIR] [--check-url URL] [--direct] [--timeout S] [--pocket FILE]
#
# --check-url must answer with the address it saw (default: Cloudflare's
# trace, "ip=" line). --direct holds the circuit in this process instead of
# the service (a machine with no service installed). Writes DIR/status.json
# and DIR/status.md. Exit code 1 if any node failed.
set -u
OUT="${PROBE_OUT:-/var/lib/hidravpn/probe}"; CHECK="https://1.1.1.1/cdn-cgi/trace"; DIRECT=""; TIMEOUT=25; HV="${HIDRAVPN_BIN:-hidravpn}"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?}"; shift 2 ;;
    --check-url) CHECK="${2:?}"; shift 2 ;;
    --direct) DIRECT="--direct"; shift ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    --pocket) HV="$HV --pocket ${2:?}"; shift 2 ;;
    -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (it brings the tunnel up and down)"; exit 1; }
mkdir -p "$OUT"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mapfile -t EXITS < <($HV nodes list 2>/dev/null | awk '$1=="exit" || ($1=="known" && ($4=="exit" || $4=="both") && / admits openly/) { if (!seen[$2]++) print $2 }')
if [ ${#EXITS[@]} -eq 0 ]; then
  echo "no exits in the pocket; nothing to probe" >&2
  printf '{"checked":"%s","nodes":[]}\n' "$NOW" > "$OUT/status.json"; exit 0
fi
# The check URL answers with the address it saw: an "ip=" line (Cloudflare's
# trace) or the bare address (a whoami page).
seen_ip() {
  local out; out="$(curl -s --max-time 5 "$CHECK" 2>/dev/null)" || return 0
  printf '%s\n' "$out" | sed -n 's/^ip=//p' | head -1 | grep -q . && { printf '%s\n' "$out" | sed -n 's/^ip=//p' | head -1; return 0; }
  printf '%s\n' "$out" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+' | head -1
}
rows=(); failed=0
# This machine's own address, seen before any tunnel: an answer that shows
# it is the check getting out before the circuit is up, not the node.
$HV down $DIRECT >/dev/null 2>&1
OWN_IP="$(seen_ip)"
for name in "${EXITS[@]}"; do
  # A name goes into file names, JSON and markdown: only these characters do.
  name=$(printf '%s' "$name" | tr -cd 'A-Za-z0-9._-' | cut -c1-32)
  [ -n "$name" ] || continue
  t0=$(date +%s)
  $HV down $DIRECT >/dev/null 2>&1
  ip=""
  if [ -n "$DIRECT" ]; then
    # With --direct, `up` holds the circuit in its own process until Ctrl+C:
    # run it aside, look for traffic, then send it Ctrl+C so it puts the
    # network back itself.
    $HV up --rapido --node "$name" --direct >"$OUT/up-$name.log" 2>&1 & UP=$!
    alive=1; deadline=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if ! kill -0 "$UP" 2>/dev/null; then alive=0; break; fi
      ip="$(seen_ip)"; [ -n "$ip" ] && [ "$ip" != "$OWN_IP" ] && break; ip=""; sleep 1
    done
    if [ "$alive" = 1 ]; then
      # A background job of a script has Ctrl+C ignored, so it is told to stop
      # with SIGTERM, which `up` treats the same way: it puts the network back.
      kill -TERM "$UP" 2>/dev/null
      for _ in $(seq 1 15); do kill -0 "$UP" 2>/dev/null || break; sleep 1; done
      kill -0 "$UP" 2>/dev/null && { kill -KILL "$UP" 2>/dev/null; $HV down --direct >/dev/null 2>&1; }
    fi
    wait "$UP" >/dev/null 2>&1
    if [ -z "$ip" ] && [ "$alive" = 0 ]; then
      rows+=("{\"node\":\"$name\",\"up\":false,\"why\":\"connect failed\",\"seconds\":$(( $(date +%s) - t0 ))}"); failed=1; continue
    fi
  else
    if ! $HV up --rapido --node "$name" >"$OUT/up-$name.log" 2>&1; then
      rows+=("{\"node\":\"$name\",\"up\":false,\"why\":\"connect failed\",\"seconds\":$(( $(date +%s) - t0 ))}"); failed=1; continue
    fi
    deadline=$(( $(date +%s) + TIMEOUT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do ip="$(seen_ip)"; [ -n "$ip" ] && [ "$ip" != "$OWN_IP" ] && break; ip=""; sleep 1; done
    $HV down >/dev/null 2>&1
  fi
  if [ -n "$ip" ]; then
    rows+=("{\"node\":\"$name\",\"up\":true,\"exit_ip\":\"$ip\",\"seconds\":$(( $(date +%s) - t0 ))}")
  else
    rows+=("{\"node\":\"$name\",\"up\":false,\"why\":\"connected but no traffic came back within ${TIMEOUT}s\",\"seconds\":$(( $(date +%s) - t0 ))}"); failed=1
  fi
done
{
  echo "{\"checked\":\"$NOW\",\"nodes\":["
  for i in "${!rows[@]}"; do [ "$i" -gt 0 ] && echo ","; printf '%s' "${rows[$i]}"; done
  echo "]}"
} > "$OUT/status.json"
{
  echo "# HidraVPN nodes, checked $NOW"; echo; echo "| node | up | exit address | seconds |"; echo "|---|---|---|---|"
  for r in "${rows[@]}"; do
    n=$(printf '%s' "$r" | sed -n 's/.*"node":"\([^"]*\)".*/\1/p'); u=$(printf '%s' "$r" | sed -n 's/.*"up":\(true\|false\).*/\1/p')
    ip=$(printf '%s' "$r" | sed -n 's/.*"exit_ip":"\([^"]*\)".*/\1/p'); sec=$(printf '%s' "$r" | sed -n 's/.*"seconds":\([0-9]*\).*/\1/p')
    echo "| $n | $u | ${ip:-} | $sec |"
  done
} > "$OUT/status.md"
cat "$OUT/status.md"
exit $failed
