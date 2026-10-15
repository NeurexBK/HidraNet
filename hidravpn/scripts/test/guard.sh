# Sourced by the test suites that use the machine's own HidraVPN places
# (/etc/hidravpn, /var/lib/hidravpn, /run/hidravpn) and clean them up: such a
# suite deletes a client key, a wallet, a node's leases. On a machine where
# HidraVPN is really installed — a client or a node — it refuses to run.
# Run the suites in a container or a throwaway machine.
for f in /etc/systemd/system/hidravpn.service /etc/systemd/system/hidravpn-node.service \
         /usr/local/bin/hidravpn-service /usr/local/bin/hidravpn-node /etc/hidravpn/node.toml; do
  if [ -e "$f" ]; then
    echo "HidraVPN is installed on this machine ($f): this test would delete its keys, passes or leases."
    echo "Run the tests in a container or a throwaway machine."
    exit 1
  fi
done
unset f
