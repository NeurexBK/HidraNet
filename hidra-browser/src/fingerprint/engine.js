const crypto = require('crypto');

// A fingerprint is only useful if it is internally consistent: a Windows user
// agent with platform "MacIntel" and an Apple GPU is a stronger signal than no
// spoofing at all. Everything that a site can cross-check lives in one profile
// and is picked together.
//
// All profiles are Chrome because the engine underneath is Chromium — claiming
// Firefox while exposing Chromium-only behaviour is the same kind of tell.
const PROFILES = [
  {
    platform: 'Win32',
    userAgents: [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    ],
    gpus: [
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    ],
  },
  {
    platform: 'MacIntel',
    userAgents: [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    ],
    gpus: [
      { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)' },
      { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)' },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics 655, OpenGL 4.1)' },
    ],
  },
  {
    platform: 'Linux x86_64',
    userAgents: [
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    ],
    gpus: [
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)' },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 6600 (radeonsi, navi23), OpenGL 4.6)' },
    ],
  },
];

// Language and timezone are cross-checked against each other by fingerprinters,
// so they are picked as a pair rather than independently.
const LOCALES = [
  { languages: ['en-US', 'en'], timezones: ['America/New_York', 'America/Chicago', 'America/Los_Angeles'] },
  { languages: ['en-GB', 'en'], timezones: ['Europe/London'] },
  { languages: ['pt-BR', 'pt'], timezones: ['America/Sao_Paulo'] },
  { languages: ['es-ES', 'es'], timezones: ['Europe/Madrid'] },
  { languages: ['fr-FR', 'fr'], timezones: ['Europe/Paris'] },
  { languages: ['de-DE', 'de'], timezones: ['Europe/Berlin'] },
];

const SCREEN_RESOLUTIONS = [
  { width: 1920, height: 1080 },
  { width: 1366, height: 768 },
  { width: 1536, height: 864 },
  { width: 1440, height: 900 },
  { width: 2560, height: 1440 },
  { width: 1600, height: 900 },
];

function pick(arr) {
  return arr[crypto.randomInt(arr.length)];
}

class FingerprintEngine {
  static generate() {
    const seed = crypto.randomBytes(32);
    const profile = pick(PROFILES);
    const locale = pick(LOCALES);
    const gpu = pick(profile.gpus);
    const screen = pick(SCREEN_RESOLUTIONS);

    return {
      seed: seed.toString('hex'),
      userAgent: pick(profile.userAgents),
      platform: profile.platform,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: 24,
        pixelRatio: pick([1, 1, 1.25, 1.5, 2]),
      },
      languages: locale.languages,
      timezone: pick(locale.timezones),
      hardwareConcurrency: pick([4, 8, 12, 16]),
      deviceMemory: pick([4, 8]),
      maxTouchPoints: 0,
      gpuVendor: gpu.vendor,
      gpuRenderer: gpu.renderer,
      audioNoise: crypto.randomBytes(4).readFloatBE(0) * 0.0001,
    };
  }

  static buildInjectionScript(fp) {
    return `(function() {
  'use strict';

  const _fp = ${JSON.stringify({
    userAgent: fp.userAgent,
    platform: fp.platform,
    screen: fp.screen,
    languages: fp.languages,
    timezone: fp.timezone,
    hardwareConcurrency: fp.hardwareConcurrency,
    deviceMemory: fp.deviceMemory,
    maxTouchPoints: fp.maxTouchPoints,
    gpuVendor: fp.gpuVendor,
    gpuRenderer: fp.gpuRenderer,
    canvasSeed: fp.seed.substring(0, 32),
    audioNoise: fp.audioNoise,
  })};

  // === NAVIGATOR SPOOFING ===
  // navigator.plugins must stay array-like: Object.create(PluginArray.prototype)
  // throws "Illegal invocation" the moment a page reads .length, which breaks
  // the page's own scripts.
  function emptyList() {
    const list = [];
    list.item = () => null;
    list.namedItem = () => null;
    list.refresh = () => {};
    return list;
  }

  const navProps = {
    userAgent: { get: () => _fp.userAgent },
    platform: { get: () => _fp.platform },
    language: { get: () => _fp.languages[0] },
    languages: { get: () => Object.freeze([..._fp.languages]) },
    hardwareConcurrency: { get: () => _fp.hardwareConcurrency },
    deviceMemory: { get: () => _fp.deviceMemory },
    maxTouchPoints: { get: () => _fp.maxTouchPoints },
    vendor: { get: () => 'Google Inc.' },
    plugins: { get: () => emptyList() },
    mimeTypes: { get: () => emptyList() },
    webdriver: { get: () => false },
    connection: { get: () => undefined },
  };

  for (const [key, desc] of Object.entries(navProps)) {
    try {
      Object.defineProperty(Navigator.prototype, key, {
        ...desc,
        configurable: true,
        enumerable: true,
      });
    } catch(e) {}
  }

  // === SCREEN SPOOFING ===
  // innerWidth/innerHeight are deliberately left alone: reporting the screen
  // size as the viewport size breaks every responsive layout, and a viewport
  // smaller than the screen is what a normal windowed browser looks like.
  const screenProps = {
    width: { get: () => _fp.screen.width },
    height: { get: () => _fp.screen.height },
    availWidth: { get: () => _fp.screen.width },
    availHeight: { get: () => _fp.screen.height - 40 },
    colorDepth: { get: () => _fp.screen.colorDepth },
    pixelDepth: { get: () => _fp.screen.colorDepth },
  };

  for (const [key, desc] of Object.entries(screenProps)) {
    try {
      Object.defineProperty(Screen.prototype, key, {
        ...desc,
        configurable: true,
        enumerable: true,
      });
    } catch(e) {}
  }

  try {
    Object.defineProperty(window, 'devicePixelRatio', {
      get: () => _fp.screen.pixelRatio,
      configurable: true,
    });
  } catch(e) {}

  // === CANVAS FINGERPRINT NOISE ===
  // The noise must be stable for a given pixel so that reading the same canvas
  // twice returns the same bytes — a site that sees two different results knows
  // it is being randomised. A precomputed table keyed by coordinate gives that
  // without hashing a freshly built string per pixel, which froze the tab on
  // any large getImageData call.
  const NOISE_SIZE = 4096;
  const noiseTable = new Uint8Array(NOISE_SIZE);
  (function buildNoise() {
    let state = 0;
    for (let i = 0; i < _fp.canvasSeed.length; i++) {
      state = (Math.imul(state, 31) + _fp.canvasSeed.charCodeAt(i)) | 0;
    }
    state = state || 0x9e3779b9;
    for (let i = 0; i < NOISE_SIZE; i++) {
      state ^= state << 13; state |= 0;
      state ^= state >>> 17;
      state ^= state << 5; state |= 0;
      noiseTable[i] = state & 0xff;
    }
  })();

  function applyNoise(data, width, offsetX, offsetY) {
    for (let i = 0; i < data.length; i += 4) {
      const p = i >> 2;
      const px = (p % width) + offsetX;
      const py = ((p / width) | 0) + offsetY;
      const n = noiseTable[(Math.imul(px, 73856093) ^ Math.imul(py, 19349663)) & (NOISE_SIZE - 1)];
      if (n < 8) {
        const channel = i + (n % 3);
        data[channel] = (data[channel] + (n & 1 ? 1 : 255)) & 0xff;
      }
    }
  }

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
    const imageData = origGetImageData.call(this, sx, sy, sw, sh);
    try { applyNoise(imageData.data, imageData.width, sx, sy); } catch(e) {}
    return imageData;
  };

  // Export paths render a noised copy. The previous version wrote the noise back
  // into the live canvas, so every toDataURL call visibly degraded the drawing.
  function noisyCopy(canvas) {
    const copy = document.createElement('canvas');
    copy.width = canvas.width;
    copy.height = canvas.height;
    const ctx = copy.getContext('2d');
    ctx.drawImage(canvas, 0, 0);
    const img = origGetImageData.call(ctx, 0, 0, copy.width, copy.height);
    applyNoise(img.data, img.width, 0, 0);
    ctx.putImageData(img, 0, 0);
    return copy;
  }

  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    try {
      return origToDataURL.apply(noisyCopy(this), args);
    } catch(e) {
      return origToDataURL.apply(this, args);
    }
  };

  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
    try {
      return origToBlob.call(noisyCopy(this), callback, ...args);
    } catch(e) {
      return origToBlob.call(this, callback, ...args);
    }
  };

  // === WEBGL FINGERPRINT SPOOFING ===
  // 0x9245/0x9246 are UNMASKED_VENDOR_WEBGL and UNMASKED_RENDERER_WEBGL, the
  // pair that actually carries the GPU identity. Spoofing only 0x1F00/0x1F01
  // left the real adapter readable through the debug extension.
  const UNMASKED_VENDOR = 0x9245;
  const UNMASKED_RENDERER = 0x9246;

  function spoofGetParameter(proto) {
    if (typeof proto === 'undefined') return;
    const orig = proto.prototype.getParameter;
    proto.prototype.getParameter = function(param) {
      if (param === UNMASKED_RENDERER || param === 0x1F01) return _fp.gpuRenderer;
      if (param === UNMASKED_VENDOR || param === 0x1F00) return _fp.gpuVendor;
      return orig.call(this, param);
    };
  }

  spoofGetParameter(typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext : undefined);
  spoofGetParameter(typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext : undefined);

  // === TIMEZONE SPOOFING ===
  const origDateTimeFormat = Intl.DateTimeFormat;
  const _tz = _fp.timezone;

  const SpoofedDateTimeFormat = function(locales, options) {
    const opts = Object.assign({}, options);
    if (!opts.timeZone) opts.timeZone = _tz;
    return new origDateTimeFormat(locales, opts);
  };
  SpoofedDateTimeFormat.prototype = origDateTimeFormat.prototype;
  // Dropping the statics broke every site that calls supportedLocalesOf.
  SpoofedDateTimeFormat.supportedLocalesOf = origDateTimeFormat.supportedLocalesOf.bind(origDateTimeFormat);
  Object.defineProperty(SpoofedDateTimeFormat, 'name', { value: 'DateTimeFormat' });
  Intl.DateTimeFormat = SpoofedDateTimeFormat;

  const origResolved = origDateTimeFormat.prototype.resolvedOptions;
  origDateTimeFormat.prototype.resolvedOptions = function() {
    const result = origResolved.call(this);
    result.timeZone = _tz;
    return result;
  };

  // Date.getTimezoneOffset kept returning the real offset, contradicting the
  // timezone reported through Intl — an easy cross-check for a fingerprinter.
  let offsetFormatter = null;
  try {
    offsetFormatter = new origDateTimeFormat('en-US', {
      timeZone: _tz,
      timeZoneName: 'longOffset',
    });
  } catch(e) {}

  function spoofedOffset(date) {
    if (!offsetFormatter) return NaN;
    try {
      const parts = offsetFormatter.formatToParts(date);
      const name = parts.find(p => p.type === 'timeZoneName');
      const m = name && name.value.match(/GMT([+-])(\\d{1,2})(?::(\\d{2}))?/);
      if (!m) return 0;
      const minutes = parseInt(m[2], 10) * 60 + parseInt(m[3] || '0', 10);
      return m[1] === '-' ? minutes : -minutes;
    } catch(e) {
      return 0;
    }
  }

  const origGetTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function() {
    const offset = spoofedOffset(this);
    return Number.isFinite(offset) ? offset : origGetTimezoneOffset.call(this);
  };

  // === AUDIOCTX FINGERPRINT NOISE ===
  if (typeof AudioContext !== 'undefined') {
    const origCreateOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = function() {
      const osc = origCreateOscillator.call(this);
      const origConnect = osc.connect.bind(osc);
      osc.connect = function(dest) {
        if (dest instanceof AnalyserNode) {
          const gain = osc.context.createGain();
          gain.gain.value = 1 + _fp.audioNoise;
          origConnect(gain);
          gain.connect(dest);
          return dest;
        }
        return origConnect(dest);
      };
      return osc;
    };
  }

  // === WEBRTC BLOCK ===
  if (typeof RTCPeerConnection !== 'undefined') {
    window.RTCPeerConnection = undefined;
    window.webkitRTCPeerConnection = undefined;
    window.mozRTCPeerConnection = undefined;
  }

  // === MEDIA DEVICES ===
  if (navigator.mediaDevices) {
    navigator.mediaDevices.enumerateDevices = async () => [];
    navigator.mediaDevices.getUserMedia = async () => { throw new DOMException('NotAllowedError'); };
  }

  // === GEOLOCATION BLOCK ===
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition = (_, err) => {
      if (err) err({ code: 1, message: 'PERMISSION_DENIED' });
    };
    navigator.geolocation.watchPosition = () => 0;
  }

  // Storage is not shimmed here: every tab already runs in its own in-memory
  // session partition that is wiped when the tab closes. The old localStorage
  // Proxy had no set trap, so "localStorage.x = 1" silently bypassed it while
  // setItem/getItem went to a Map — sites that mix both styles broke.

})();`;
  }
}

module.exports = { FingerprintEngine };
