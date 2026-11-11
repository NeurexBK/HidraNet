// The command-line switches main.js gives Chromium, as [name, value] pairs.
//
// main.js is loaded in a process of its own with a stand-in Electron whose
// app never becomes ready, so every switch recorded was appended before
// ready. Anything else main.js touches at load answers with another
// stand-in. Under Electron the child runs as plain Node.
const { execFileSync } = require('child_process');
const path = require('path');

const LOADER = `
  const Module = require('module');
  const switches = [];
  const stand = (name) => new Proxy(function () {}, {
    get: (t, k) => {
      if (k === 'then') return undefined;
      if (name === 'app.commandLine' && k === 'appendSwitch') return (...a) => { switches.push(a); };
      if (name === 'app' && k === 'whenReady') return () => new Promise(() => {});
      if (name === 'app' && k === 'requestSingleInstanceLock') return () => false;
      return stand(name + '.' + String(k));
    },
    apply: () => stand(name + '()'),
    construct: () => stand(name),
  });
  const electron = new Proxy({}, { get: (t, k) => stand(String(k)) });
  const load = Module._load;
  Module._load = function (request) { return request === 'electron' ? electron : load.apply(this, arguments); };
  require(process.argv[1]);
  process.stdout.write('\\nswitches ' + JSON.stringify(switches) + '\\n');
  process.exit(0);`;

function mainSwitches() {
  const out = execFileSync(process.execPath, ['-e', LOADER, path.join(__dirname, '..', '..', 'src', 'main', 'main.js')], {
    encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  });
  return JSON.parse(/^switches (.*)$/m.exec(out)[1]);
}

module.exports = { mainSwitches };
