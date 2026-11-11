# Sourced by the test suites that use the machine's own HidraVPN places
# (/etc/hidravpn, /var/lib/hidravpn, /run/hidravpn) and clean them up: such a
# suite deletes a client key, a wallet, a node's leases. On a machine where
# HidraVPN is really installed — a client or a node — it refuses to run.
# Run the suites in a container or a throwaway machine.
for f in /etc/systemd/system/hidravpn.service /etc/systemd/system/hidravpn-node.service \
         /usr/local/bin/hidravpn /usr/local/bin/hidravpn-service /usr/local/bin/hidravpn-node /etc/hidravpn/node.toml; do
  if [ -e "$f" ]; then
    echo "HidraVPN is installed on this machine ($f): this test would delete its keys, passes or leases."
    echo "Run the tests in a container or a throwaway machine."
    exit 1
  fi
done
# Files the client makes without installing anything. They are a suite's own
# only under TEST_MARK, which guard_done removes with them.
TEST_MARK=/etc/hidravpn/.hidravpn-test
CLIENT_FILES=(/etc/hidravpn/client.key /etc/hidravpn/circuit.json /etc/hidravpn/passes.json
              /etc/hidravpn/pass.token /etc/hidravpn/order.json)
if [ ! -e "$TEST_MARK" ]; then
  for f in "${CLIENT_FILES[@]}"; do
    if [ -e "$f" ]; then
      echo "This machine has a HidraVPN client key, pocket or passes ($f): this test would delete them."
      echo "Run the tests in a container or a throwaway machine."
      exit 1
    fi
  done
fi
unset f
if [ "$(id -u)" = 0 ]; then mkdir -p /etc/hidravpn && : > "$TEST_MARK"; fi
guard_done() { rm -f "${CLIENT_FILES[@]}" "$TEST_MARK"; }
