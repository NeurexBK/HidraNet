#!/usr/bin/env bash
# The guard the namespace suites source (test/guard.sh): every suite that
# deletes a client key or a pocket sources it and ends with guard_done, and
# it refuses to let one run over a key, pocket or passes that are not a
# test's own.
#
# Run as root:  sudo bash hidravpn/scripts/test-guard.sh
# Needs: unshare. Nothing in this machine's /etc/hidravpn is read or changed;
# when there is none, an empty one is made as a mount point and removed after.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

# The client installer has a check of its own, and installs the client.
for t in "$HERE"/test-*.sh; do
  name="$(basename "$t")"
  case "$name" in test-client-installer.sh|test-guard.sh) continue ;; esac
  # shellcheck disable=SC2016 # the suites' own text, not expanded here
  grep -qxF '. "$HERE/test/guard.sh"' "$t" && sourced=1 || sourced=0
  grep -qE '/etc/hidravpn/(client\.key|circuit\.json|passes\.json)' "$t" || [ "$sourced" = 1 ] || continue
  if [ "$sourced" = 1 ] && grep -qxF "trap 'cleanup; guard_done' EXIT" "$t"; then
    pass "$name sources the guard and ends with guard_done"
  else
    fail "$name deletes client files without the guard, or does not end with guard_done"
  fi
done

# The guard over an empty /etc/hidravpn of its own: $1 puts there what the
# case needs before the guard, $2 runs after it. It prints "through" and
# what the place then holds when the guard lets the suite go on.
MADE=""; [ -d /etc/hidravpn ] || { mkdir -p /etc/hidravpn; MADE=1; }
guarded() {
  # shellcheck disable=SC2016 # expanded by the inner shell
  unshare --mount bash -c 'mount -t tmpfs none /etc/hidravpn || exit 9; eval "$1"; . "$3"; echo through; eval "$2"; ls -A /etc/hidravpn' _ "$1" "${2:-}" "$HERE/test/guard.sh" 2>&1
}
for f in client.key circuit.json passes.json pass.token order.json; do
  OUT=$(guarded ": > /etc/hidravpn/$f"); RC=$?
  [ "$RC" = 1 ] && echo "$OUT" | grep -qF "(/etc/hidravpn/$f): this test would delete them" && ! echo "$OUT" | grep -q through \
    && pass "$f made by the client alone, with nothing installed: refused" || fail "$f: exit $RC, $OUT"
done
OUT=$(guarded ': > /etc/hidravpn/client.key; : > /etc/hidravpn/circuit.json; : > /etc/hidravpn/.hidravpn-test'); RC=$?
[ "$RC" = 0 ] && echo "$OUT" | grep -q through && pass "what a run cut short left, under its mark: the next run goes on" || fail "interrupted run: exit $RC, $OUT"
OUT=$(guarded 'true'); RC=$?
[ "$RC" = 0 ] && echo "$OUT" | grep -q through && echo "$OUT" | grep -qx ".hidravpn-test" && pass "nothing there: the suite goes on, and marks the place as its own" || fail "empty: exit $RC, $OUT"
OUT=$(guarded true ': > /etc/hidravpn/circuit.json; : > /etc/hidravpn/passes.json; : > /etc/hidravpn/hidravpn.lock; guard_done'); RC=$?
[ "$RC" = 0 ] && [ "$(echo "$OUT" | awk 'f; /^through$/ { f = 1 }')" = hidravpn.lock ] && pass "guard_done takes what the client made during the suite and the mark, so the next suite is not refused" || fail "guard_done: exit $RC, $OUT"
[ -n "$MADE" ] && rmdir /etc/hidravpn

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
