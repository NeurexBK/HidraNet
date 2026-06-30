const crypto = require('crypto');

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0',
];

const PLATFORMS = [
  { platform: 'Win32', oscpu: 'Windows NT 10.0; Win64; x64' },
  { platform: 'MacIntel', oscpu: 'Intel Mac OS X 10.15' },
  { platform: 'Linux x86_64', oscpu: 'Linux x86_64' },
];

const SCREEN_RESOLUTIONS = [
  { width: 1920, height: 1080 },
  { width: 1366, height: 768 },
  { width: 1536, height: 864 },
  { width: 1440, height: 900 },
  { width: 1280, height: 720 },
  { width: 2560, height: 1440 },
  { width: 1600, height: 900 },
];

const LANGUAGES = [
  ['en-US', 'en'],
  ['en-GB', 'en'],
  ['pt-BR', 'pt'],
  ['es-ES', 'es'],
  ['fr-FR', 'fr'],
  ['de-DE', 'de'],
];

const TIMEZONES = [
  'America/New_York',
  'America/Chicago',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Paris',
  'Asia/Tokyo',
];

const GPU_RENDERERS = [
  'ANGLE (NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0)',
  'ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)',
  'ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)',
  'ANGLE (Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)',
  'ANGLE (Apple M1 Metal)',
  'Mesa Intel(R) UHD Graphics 630 (CFL GT2)',
];

function pick(arr) {
  return arr[crypto.randomInt(arr.length)];
}

class FingerprintEngine {
  static generate() {
    const seed = crypto.randomBytes(32);
    const screen = pick(SCREEN_RESOLUTIONS);
    const platformInfo = pick(PLATFORMS);
    const langs = pick(LANGUAGES);

    return {
      seed: seed.toString('hex'),
      userAgent: pick(USER_AGENTS),
      platform: platformInfo.platform,
      oscpu: platformInfo.oscpu,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: pick([24, 32]),
        pixelRatio: pick([1, 1, 1.25, 1.5, 2]),
      },
      languages: langs,
      timezone: pick(TIMEZONES),
      hardwareConcurrency: pick([2, 4, 8, 16]),
      deviceMemory: pick([2, 4, 8]),
      maxTouchPoints: 0,
      gpuRenderer: pick(GPU_RENDERERS),
      canvasNoise: seed.slice(0, 16),
      webglNoise: seed.slice(16, 32),
      audioNoise: crypto.randomBytes(4).readFloatBE(0) * 0.0001,
    };
  }

  static buildInjectionScript(fp) {
    return `(function() {
  'use strict';

  const _fp = ${JSON.stringify({
    userAgent: fp.userAgent,
    platform: fp.platform,
    oscpu: fp.oscpu,
    screen: fp.screen,
    languages: fp.languages,
    timezone: fp.timezone,
    hardwareConcurrency: fp.hardwareConcurrency,
    deviceMemory: fp.deviceMemory,
    maxTouchPoints: fp.maxTouchPoints,
    gpuRenderer: fp.gpuRenderer,
    canvasNoiseSeed: fp.seed.substring(0, 32),
    audioNoise: fp.audioNoise,
  })};

  // === NAVIGATOR SPOOFING ===
  const navProps = {
    userAgent: { get: () => _fp.userAgent },
    platform: { get: () => _fp.platform },
    oscpu: { get: () => _fp.oscpu },
    language: { get: () => _fp.languages[0] },
    languages: { get: () => Object.freeze([..._fp.languages]) },
    hardwareConcurrency: { get: () => _fp.hardwareConcurrency },
    deviceMemory: { get: () => _fp.deviceMemory },
    maxTouchPoints: { get: () => _fp.maxTouchPoints },
    vendor: { get: () => 'Google Inc.' },
    plugins: { get: () => Object.create(PluginArray.prototype) },
    mimeTypes: { get: () => Object.create(MimeTypeArray.prototype) },
    webdriver: { get: () => false },
    connection: { get: () => undefined },
    getBattery: { value: undefined },
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

  Object.defineProperty(window, 'devicePixelRatio', {
    get: () => _fp.screen.pixelRatio,
    configurable: true,
  });

  Object.defineProperty(window, 'innerWidth', {
    get: () => _fp.screen.width,
    configurable: true,
  });

  Object.defineProperty(window, 'innerHeight', {
    get: () => _fp.screen.height - 80,
    configurable: true,
  });

  Object.defineProperty(window, 'outerWidth', {
    get: () => _fp.screen.width,
    configurable: true,
  });

  Object.defineProperty(window, 'outerHeight', {
    get: () => _fp.screen.height,
    configurable: true,
  });

  // === CANVAS FINGERPRINT NOISE ===
  function hashSeed(seed, x, y) {
    let h = 0x811c9dc5;
    const s = seed + x + ',' + y;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0) / 0xffffffff;
  }

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
    const imageData = origGetImageData.call(this, sx, sy, sw, sh);
    const data = imageData.data;
    const seed = _fp.canvasNoiseSeed;
    for (let i = 0; i < data.length; i += 4) {
      const px = (i / 4) % sw;
      const py = Math.floor((i / 4) / sw);
      const noise = hashSeed(seed, px + sx, py + sy);
      if (noise < 0.03) {
        const channel = Math.floor(noise * 100) % 3;
        data[i + channel] = (data[i + channel] + (noise > 0.015 ? 1 : -1) + 256) % 256;
      }
    }
    return imageData;
  };

  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    try {
      const ctx = this.getContext('2d');
      if (ctx) {
        const img = ctx.getImageData(0, 0, this.width, this.height);
        ctx.putImageData(img, 0, 0);
      }
    } catch(e) {}
    return origToDataURL.apply(this, args);
  };

  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
    try {
      const ctx = this.getContext('2d');
      if (ctx) {
        const img = ctx.getImageData(0, 0, this.width, this.height);
        ctx.putImageData(img, 0, 0);
      }
    } catch(e) {}
    return origToBlob.call(this, callback, ...args);
  };

  // === WEBGL FINGERPRINT SPOOFING ===
  const origGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 0x1F01) return _fp.gpuRenderer;  // RENDERER
    if (param === 0x1F00) return 'Google Inc. (HidraNet)';  // VENDOR
    return origGetParameter.call(this, param);
  };

  const origGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
  WebGL2RenderingContext.prototype.getParameter = function(param) {
    if (param === 0x1F01) return _fp.gpuRenderer;
    if (param === 0x1F00) return 'Google Inc. (HidraNet)';
    return origGetParameter2.call(this, param);
  };

  const origGetExtension = WebGLRenderingContext.prototype.getExtension;
  WebGLRenderingContext.prototype.getExtension = function(name) {
    if (name === 'WEBGL_debug_renderer_info') {
      return { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
    }
    return origGetExtension.call(this, name);
  };

  // === TIMEZONE SPOOFING ===
  const origDateTimeFormat = Intl.DateTimeFormat;
  const _tz = _fp.timezone;

  Intl.DateTimeFormat = function(locales, options) {
    const opts = Object.assign({}, options, { timeZone: _tz });
    return new origDateTimeFormat(locales, opts);
  };
  Intl.DateTimeFormat.prototype = origDateTimeFormat.prototype;
  Object.defineProperty(Intl.DateTimeFormat, 'name', { value: 'DateTimeFormat' });

  const origResolved = origDateTimeFormat.prototype.resolvedOptions;
  origDateTimeFormat.prototype.resolvedOptions = function() {
    const result = origResolved.call(this);
    result.timeZone = _tz;
    return result;
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

  // === STORAGE ISOLATION ===
  try {
    const origStorage = window.localStorage;
    const fakeStorage = new Map();
    Object.defineProperty(window, 'localStorage', {
      get: () => new Proxy(origStorage, {
        get: (target, prop) => {
          if (prop === 'getItem') return (key) => fakeStorage.get(key) || null;
          if (prop === 'setItem') return (key, val) => fakeStorage.set(key, String(val));
          if (prop === 'removeItem') return (key) => fakeStorage.delete(key);
          if (prop === 'clear') return () => fakeStorage.clear();
          if (prop === 'length') return fakeStorage.size;
          if (prop === 'key') return (i) => [...fakeStorage.keys()][i] || null;
          return typeof target[prop] === 'function' ? target[prop].bind(target) : target[prop];
        }
      }),
      configurable: true,
    });
  } catch(e) {}

})();`;
  }
}

module.exports = { FingerprintEngine };
