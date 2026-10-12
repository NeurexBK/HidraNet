/**
 * The Linux launcher, start.sh — written once, used by every builder.
 *
 * It used to be written out three times, in patch-zip.js, build-linux.js and
 * pack-portable.js, and the copies had already started to differ. Worse,
 * patch-zip.js only replaced it when the archive's launcher was still called
 * iniciar.sh, so once the published package had been refreshed and carried a
 * start.sh, any change here would have been silently dropped on the next
 * release. All three now read this file.
 *
 * What it does beyond exec'ing the browser is keep Chromium's sandbox working
 * on the systems where it otherwise aborts the browser before a window opens.
 */
'use strict';

/**
 * A string that only this launcher contains, so a release check can prove the
 * package carries this version rather than an older one.
 */
const SANDBOX_MARKER = 'hidra-launcher: sandbox-check v1';

function launcherScript(APP_NAME) {
  const BIN = APP_NAME || 'hidranet';
  return `#!/bin/bash
# Starts HidraNet. Run:  bash start.sh
# ${SANDBOX_MARKER}
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/${BIN}"
SANDBOX="$DIR/chrome-sandbox"

# Some zip tools drop Unix permissions, so set them here rather than assume.
# Without the execute bit on Tor the browser starts and then cannot connect.
chmod +x "$BIN" 2>/dev/null
chmod +x "$DIR/resources/bin/hidra-node" 2>/dev/null
chmod +x "$DIR/resources/bin/tor/tor" 2>/dev/null

if [ ! -f "$DIR/resources/bin/tor/tor" ]; then
  echo "WARNING: no Tor in this package. It provides no anonymity." >&2
fi

# ── The sandbox ─────────────────────────────────────────────────────────────
#
# Chromium sandboxes every page it renders. It does that with unprivileged user
# namespaces where the system allows them, and otherwise with chrome-sandbox, a
# small helper that has to be owned by root and setuid. Ubuntu 23.10 and later
# restrict unprivileged user namespaces through AppArmor, some distributions
# switch them off, and a zip cannot carry a setuid-root file — so on those
# systems Chromium finds neither, and aborts before a window opens with
# "The SUID sandbox helper binary was found, but is not configured correctly".
#
# Running without the sandbox is not offered. It would turn any bug in the page
# renderer into full access to this account, on the browser whose job is to be
# the careful one.

userns_ok() {
  [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ] && return 1
  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = 0 ] && return 1
  [ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)" = 0 ] && return 1
  return 0
}

nosuid_mount() {
  command -v findmnt >/dev/null 2>&1 &&
    findmnt -T "$DIR" -no OPTIONS 2>/dev/null | tr ',' '\\n' | grep -qx nosuid
}

# Owned by root and setuid is what Chromium checks. It also has to sit on a
# filesystem that honours setuid, or the kernel ignores the bit and Chromium
# fails the same way.
suid_ok() {
  [ "$(stat -c '%u %a' "$SANDBOX" 2>/dev/null)" = "0 4755" ] && ! nosuid_mount
}

make_suid() {
  if [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
    printf 'Set it up now? You will be asked for your password. [Y/n] ' >&2
    read -r answer
    case "$answer" in
      [nN]*) return 1 ;;
    esac
    sudo chown root:root "$SANDBOX" && sudo chmod 4755 "$SANDBOX"
  elif command -v pkexec >/dev/null 2>&1; then
    # Started from a file manager, with no terminal to type into: pkexec asks
    # for the password in a window instead.
    pkexec /bin/sh -c 'chown root:root "$1" && chmod 4755 "$1"' sh "$SANDBOX"
  else
    return 1
  fi
}

case " $* " in
  *" --no-sandbox "*) ;;   # asked for explicitly; their call, not ours
  *)
    if ! userns_ok && ! suid_ok; then
      if nosuid_mount; then
        cat >&2 <<EOF

HidraNet is in a folder on a drive mounted "nosuid", where its sandbox cannot
work. Move the HidraNet folder into your home folder and run start.sh again.

EOF
        exit 1
      fi
      cat >&2 <<EOF

This system blocks the way the browser normally sandboxes web pages
(Ubuntu 23.10 and later do). HidraNet keeps the sandbox on by using the helper
that ships beside it, which has to be owned by root. It is one command:

  sudo chown root:root "$SANDBOX" && sudo chmod 4755 "$SANDBOX"

EOF
      make_suid
      if ! suid_ok; then
        echo "HidraNet was not started: its sandbox could not be enabled." >&2
        echo "Run the command above, then start.sh again." >&2
        exit 1
      fi
      echo "Sandbox ready." >&2
    fi
    ;;
esac

exec "$BIN" "$@"
`;
}

module.exports = { launcherScript, SANDBOX_MARKER };
