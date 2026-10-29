// Drives a REAL hidravpn-service through the browser's own module, exactly as
// the VPN page would. Run by hidravpn/scripts/test-browser-netns.sh inside the
// client namespace, where the service is listening; not meant to be run alone.
//
//   node vpn-live.js <step>        step: before | not-the-service |
//                                        connect-privado-refused | connect-rapido |
//                                        status | identity | down | after
//
// Prints one line of JSON with what it saw, and exits non-zero on anything
// unexpected, so the shell script can judge each step and check the network
// itself (exit address, kill switch, routes) in between.

'use strict';

const path = require('path');
const { VpnManager } = require(path.join(__dirname, '..', 'src', 'main', 'vpn-manager.js'));

const vpn = new VpnManager({ timeoutMs: 20000 });
const step = process.argv[2];

function fail(msg, extra) {
  console.log(JSON.stringify({ ok: false, step, msg, extra }));
  process.exit(1);
}
function done(extra) {
  console.log(JSON.stringify({ ok: true, step, ...extra }));
}

(async () => {
  switch (step) {
    case 'before': {
      const s = await vpn.status();
      if (s.state !== 'disconnected') fail('expected disconnected', s);
      if (s.report.killswitch) fail('kill switch armed before connecting', s);
      const n = await vpn.nodes();
      if (!n.ok) fail('nodes failed', n);
      if (n.nodes.some((x) => 'node_public_key' in x)) fail('a key reached the browser', n);
      done({ state: s.state, nodes: n.nodes.map((x) => `${x.slot}:${x.node_name}`) });
      break;
    }
    case 'not-the-service': {
      // The script has put another key where the service's public key
      // lives: every answer then fails to open, and none may be believed.
      const s = await vpn.status();
      if (s.state !== 'unavailable' || s.report) fail('an answer that did not open was believed', s);
      done({ state: s.state, error: s.error });
      break;
    }
    case 'connect-privado-refused': {
      // Only an exit is in the pocket: two hops must be refused, by the
      // service, with the reason, and nothing must have changed.
      const r = await vpn.connect('privado');
      if (r.ok) fail('privado connected with no entry in the pocket', r);
      if (!/no entry node/.test(r.error || '')) fail('refusal does not say what is missing', r);
      const s = await vpn.status();
      if (s.state !== 'disconnected' || s.report.killswitch) fail('a refused connect changed the machine', s);
      done({ error: r.error });
      break;
    }
    case 'connect-rapido': {
      const r = await vpn.connect('rapido');
      if (!r.ok) fail('connect failed', r);
      if (!r.status || r.status.mode !== 'rapido' || r.status.hops !== 1) fail('wrong mode or hops', r);
      done({ connected: r.status.connected, killswitch: r.status.killswitch, node: r.status.node_name });
      break;
    }
    case 'status': {
      // Give the handshake a moment, as the page would while polling.
      let s;
      for (let i = 0; i < 25; i++) {
        s = await vpn.status();
        if (s.state === 'connected') break;
        await new Promise((r) => setTimeout(r, 400));
      }
      if (s.state !== 'connected') fail('never reached connected', s);
      if (!s.report.killswitch) fail('kill switch not armed while connected', s);
      if (s.report.hops_detail.length !== 1 || s.report.hops_detail[0].role !== 'exit') fail('hops_detail wrong', s);
      done({ state: s.state, killswitch: s.report.killswitch, hops: s.report.hops, mode: s.report.mode, handshake: s.report.last_handshake_secs });
      break;
    }
    case 'identity': {
      const r = await vpn.newIdentity();
      if (!r.ok) fail('new identity failed', r);
      if (!/only one exit node/.test(r.note || '')) fail('with one exit the note must say the address did not change', r);
      done({ note: r.note });
      break;
    }
    case 'down': {
      const r = await vpn.disconnect();
      if (!r.ok) fail('disconnect failed', r);
      const s = await vpn.status();
      if (s.state !== 'disconnected') fail('still not disconnected', s);
      if (s.report.killswitch) fail('kill switch still armed after disconnect', s);
      done({ state: s.state, killswitch: s.report.killswitch });
      break;
    }
    case 'refill-off': {
      const before = await vpn.refill();
      if (!before.ok || !before.refill || before.refill.enabled !== true) fail('automatic passes were not on by default', before);
      const r = await vpn.refill(false);
      if (!r.ok || r.refill.enabled !== false) fail('automatic passes did not switch off', r);
      const again = await vpn.refill(true);
      if (!again.ok || again.refill.enabled !== true) fail('automatic passes did not switch back on', again);
      done({ before: before.refill.enabled, off: r.refill.enabled, on: again.refill.enabled });
      break;
    }
    case 'after': {
      const s = await vpn.status();
      done({ state: s.state, killswitch: s.report ? s.report.killswitch : null });
      break;
    }
    default:
      fail('unknown step');
  }
})().catch((e) => fail('threw', String((e && e.stack) || e)));
