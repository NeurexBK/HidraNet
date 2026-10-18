// The one-click leak test on the VPN page.
//
// It asks, from outside the browser's own Tor route, what the rest of this
// machine looks like to the internet while HidraVPN is connected:
//
//   - IPv4: which address a website sees. It should be the exit node's.
//   - IPv6: when the exit carries IPv6 (the service says so), that it goes
//     through the tunnel; otherwise that nothing leaves over IPv6 at all. The
//     kill switch lets IPv6 out through the tunnel only, so with it armed an
//     IPv6 answer can only have come through the exit.
//   - DNS: whether a name can be looked up outside the tunnel. The kill
//     switch forbids it, so the test reads it from the service: armed or not.
//   - The kill switch itself, as the service reports it.
//
// The two network checks go to api.ipify.org / api6.ipify.org, from a session
// with no proxy, exactly as any other program on this machine would — which
// is the point: the browser's own tabs go through Tor whatever the VPN does,
// so a test through them would prove nothing about the machine. ipify sees
// the address it reports back (the exit's), the moment someone asked, and a
// generic user agent; the test runs only when the person presses the button,
// and only while the kill switch is armed and the exit has shaken hands in
// the last three minutes. Otherwise the request could leave from this
// machine's own address, and the test itself would be the leak.
//
// Every verdict is one of pass, warn, fail; nothing is assumed green.

'use strict';

const IPV4_URL = 'https://api.ipify.org?format=json';
const IPV6_URL = 'https://api6.ipify.org?format=json';
// How recent the exit's last handshake must be for the test to run: a live
// WireGuard session shakes hands every two minutes.
const FRESH_SECS = 180;

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
  const exitHop = (r.hops_detail || []).find((h) => h.role === 'exit');
  const age = exitHop && typeof exitHop.last_handshake_secs === 'number' ? exitHop.last_handshake_secs : r.last_handshake_secs;
  if (r.killswitch && !(typeof age === 'number' && age <= FRESH_SECS)) {
    return { ran: false, error: 'the tunnel has not shaken hands with the exit in the last three minutes; the test waits until it has, so the address check cannot leave from this machine\'s own address' };
  }

  const checks = [];
  checks.push(r.killswitch
    ? { id: 'killswitch', label: 'Kill switch', verdict: 'pass', detail: 'Armed: if the tunnel drops, nothing leaves this machine until it is back.' }
    : { id: 'killswitch', label: 'Kill switch', verdict: 'fail', detail: 'Off: if the tunnel drops, traffic would leave in the clear.' });

  if (!r.killswitch) {
    // Asking a website now could show it this machine's own address: the
    // network checks are not run, and say why.
    const why = 'Not run: with the kill switch off, asking a website could show it your own address.';
    checks.push({ id: 'ipv4', label: 'IPv4 address', verdict: 'fail', detail: why });
    checks.push({ id: 'ipv6', label: 'IPv6', verdict: 'fail', detail: why });
    checks.push({ id: 'dns', label: 'DNS', verdict: 'fail', detail: 'With the kill switch off, nothing stops a program from asking a resolver outside the tunnel.' });
    return { ran: true, verdict: 'fail', checks };
  }

  const exitHost = hostOf(exitHop ? exitHop.endpoint : r.endpoint);
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
  if (r.ipv6) {
    checks.push(v6
      ? { id: 'ipv6', label: 'IPv6', verdict: 'pass', detail: `IPv6 goes through the tunnel: websites see ${v6}, from the exit.` }
      : { id: 'ipv6', label: 'IPv6', verdict: 'warn', detail: 'The exit carries IPv6, but the IPv6 check did not answer.' });
  } else {
    checks.push(v6
      ? { id: 'ipv6', label: 'IPv6', verdict: 'fail', detail: `Traffic left over IPv6 as ${v6}, though the exit carries none.` }
      : { id: 'ipv6', label: 'IPv6', verdict: 'pass', detail: 'Nothing leaves over IPv6.' });
  }

  checks.push({ id: 'dns', label: 'DNS', verdict: 'pass', detail: 'No DNS query can leave outside the tunnel: the kill switch blocks every one that does not go through it.' });

  const worst = checks.some((c) => c.verdict === 'fail') ? 'fail' : checks.some((c) => c.verdict === 'warn') ? 'warn' : 'pass';
  return { ran: true, verdict: worst, checks };
}

module.exports = { runLeakTest, IPV4_URL, IPV6_URL, hostOf, readIp };
