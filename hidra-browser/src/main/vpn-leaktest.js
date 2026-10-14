// The one-click leak test on the VPN page.
//
// It asks, from outside the browser's own Tor route, what the rest of this
// machine looks like to the internet while HidraVPN is connected:
//
//   - IPv4: which address a website sees. It should be the exit node's.
//   - IPv6: whether anything leaves over IPv6 at all. It should not: the kill
//     switch drops IPv6.
//   - DNS: whether a name can be looked up outside the tunnel. The kill
//     switch forbids it, so the test reads it from the service: armed or not.
//   - The kill switch itself, as the service reports it.
//
// The two network checks go to api.ipify.org / api6.ipify.org, from a session
// with no proxy, exactly as any other program on this machine would — which
// is the point: the browser's own tabs go through Tor whatever the VPN does,
// so a test through them would prove nothing about the machine. ipify sees
// the address it reports back, and nothing else; the test runs only when the
// person presses the button.
//
// Every verdict is one of pass, warn, fail; nothing is assumed green.

'use strict';

const IPV4_URL = 'https://api.ipify.org?format=json';
const IPV6_URL = 'https://api6.ipify.org?format=json';

function hostOf(endpoint) {
  const s = String(endpoint || '');
  const i = s.lastIndexOf(':');
  return i > 0 ? s.slice(0, i) : s;
}

function readIp(body) {
  try {
    const ip = JSON.parse(body).ip;
    return typeof ip === 'string' && /^[0-9a-fA-F.:]{2,45}$/.test(ip) ? ip : null;
  } catch {
    return null;
  }
}

// `status` is VpnManager.status()'s answer; `probe(url)` resolves to the
// response body, or rejects when nothing could be fetched.
async function runLeakTest(status, probe) {
  const r = status && status.report;
  if (!r) return { ran: false, error: 'the HidraVPN service cannot be reached, so there is nothing to test' };
  if (!r.connected) return { ran: false, error: 'connect first: the test checks the connection HidraVPN is holding' };

  const checks = [];
  checks.push(r.killswitch
    ? { id: 'killswitch', label: 'Kill switch', verdict: 'pass', detail: 'Armed: if the tunnel drops, nothing leaves this machine until it is back.' }
    : { id: 'killswitch', label: 'Kill switch', verdict: 'fail', detail: 'Off: if the tunnel drops, traffic would leave in the clear.' });

  const exit = (r.hops_detail || []).find((h) => h.role === 'exit');
  const exitHost = hostOf(exit ? exit.endpoint : r.endpoint);
  let seen = null;
  try {
    seen = readIp(await probe(IPV4_URL));
  } catch {
    seen = null;
  }
  if (!seen) {
    checks.push({ id: 'ipv4', label: 'IPv4 address', verdict: 'warn', detail: 'The address check did not answer, so the address websites see is not known.' });
  } else if (seen === exitHost) {
    checks.push({ id: 'ipv4', label: 'IPv4 address', verdict: 'pass', detail: `Websites see ${seen}, the exit node's address.` });
  } else {
    checks.push({
      id: 'ipv4', label: 'IPv4 address', verdict: 'warn',
      detail: `Websites see ${seen}, not ${exitHost}, the exit node's listed address. A node may leave through another address of its own; if ${seen} is your own address, the tunnel is not carrying your traffic.`,
    });
  }

  let v6 = null;
  try {
    v6 = readIp(await probe(IPV6_URL));
  } catch {
    v6 = null;
  }
  checks.push(v6
    ? { id: 'ipv6', label: 'IPv6', verdict: 'fail', detail: `Traffic left over IPv6 as ${v6}, around the tunnel.` }
    : { id: 'ipv6', label: 'IPv6', verdict: 'pass', detail: 'Nothing leaves over IPv6.' });

  checks.push(r.killswitch
    ? { id: 'dns', label: 'DNS', verdict: 'pass', detail: 'No DNS query can leave outside the tunnel: the kill switch blocks every one that does not go through it.' }
    : { id: 'dns', label: 'DNS', verdict: 'fail', detail: 'With the kill switch off, nothing stops a program from asking a resolver outside the tunnel.' });

  const worst = checks.some((c) => c.verdict === 'fail') ? 'fail' : checks.some((c) => c.verdict === 'warn') ? 'warn' : 'pass';
  return { ran: true, verdict: worst, checks };
}

module.exports = { runLeakTest, IPV4_URL, IPV6_URL, hostOf, readIp };
