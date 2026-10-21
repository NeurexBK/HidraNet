// The MQTT relays an app talks through: all of them at once.
//
// The chat, mail and forum used to talk through one public broker at a time,
// moving to the next only once the one in use stopped answering. The brokers
// share nothing, and that split people. With the first one down, Mail (which
// had no second broker at all) could not send, and a newcomer to the forum
// found it empty and could register a username that already belonged to
// someone else. Once the first came back, whoever had moved stayed on the
// second while newcomers landed on the first: the same chat room and the same
// forum, in two halves that could not see each other.
//
// Now an app connects to every broker in its list and keeps each connection
// up on its own. What it publishes goes to all of them and what it subscribes
// to is read from all of them, so one broker down costs nothing while another
// is up, and nobody ends up on a different broker from everyone else. The
// same message then arrives once per broker; each app drops the copies (the
// chat by its replay guard, the mail by message id, the forum because a post,
// claim or tombstone applied twice changes nothing).
(function () {
  'use strict';

  // The same pacing the apps used: 3 s after the first failure, growing to 20 s.
  function backoff(fails) { return Math.min(2000 * Math.pow(1.5, Math.min(fails, 8)), 20000); }

  // How long a publish waits for a broker to take it before giving up on it.
  var PUBLISH_WAIT_MS = 10000;

  // urls: the brokers, in order. opts:
  //   options(i)               mqtt.connect options for broker i
  //   onMessage(topic, payload, i)
  //   onUp(i)                  broker i connected; subscriptions are renewed
  //   onChange(up, total, fails)  after every connect and every drop; fails
  //                            is the fewest failed attempts in a row among
  //                            the brokers, so 2 or more with up 0 means all
  //                            of them keep failing
  function Relays(urls, opts) {
    this.opts = opts || {};
    this.subs = {};
    this.closed = false;
    this.total = urls.length;
    this.list = urls.map(function (url, i) {
      return { url: url, index: i, client: null, up: false, fails: 0, timer: null };
    });
  }

  Relays.prototype.start = function () {
    var self = this;
    this.list.forEach(function (r) { self._open(r); });
    return this;
  };

  Relays.prototype._open = function (r) {
    if (this.closed) return;
    var self = this, opts = this.opts, c;
    var options = {};
    var extra = opts.options ? opts.options(r.index) : {};
    for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) options[k] = extra[k];
    if (options.connectTimeout === undefined) options.connectTimeout = 9000;
    if (options.keepalive === undefined) options.keepalive = 30;
    // Reconnecting is done here, per broker, not by the client.
    options.reconnectPeriod = 0;
    try { c = mqtt.connect(r.url, options); }
    catch (e) { r.fails++; this._changed(); this._retry(r); return; }
    r.client = c;
    c.on('connect', function () {
      if (c !== r.client || self.closed) return;
      r.fails = 0;
      r.up = true;
      for (var t in self.subs) {
        if (Object.prototype.hasOwnProperty.call(self.subs, t)) { try { c.subscribe(t, self.subs[t]); } catch (e) {} }
      }
      self._changed();
      if (opts.onUp) opts.onUp(r.index);
    });
    c.on('message', function (topic, payload) {
      if (c === r.client && opts.onMessage) opts.onMessage(topic, payload, r.index);
    });
    c.on('error', function () {});
    c.on('close', function () {
      if (c !== r.client || self.closed) return;
      r.up = false;
      r.fails++;
      self._changed();
      self._retry(r);
    });
  };

  Relays.prototype._retry = function (r) {
    var self = this;
    clearTimeout(r.timer);
    var old = r.client;
    r.client = null;                 // what the old client still emits is ignored
    try { if (old) old.end(true); } catch (e) {}
    r.timer = setTimeout(function () { self._open(r); }, backoff(r.fails));
  };

  Relays.prototype._changed = function () {
    if (this.closed || !this.opts.onChange) return;
    var fails = Math.min.apply(null, this.list.map(function (r) { return r.fails; }));
    this.opts.onChange(this.upCount(), this.total, fails);
  };

  Relays.prototype.upCount = function () {
    return this.list.filter(function (r) { return r.up; }).length;
  };
  Relays.prototype.anyUp = function () { return this.upCount() > 0; };
  Relays.prototype.isUp = function (i) { return !!(this.list[i] && this.list[i].up); };

  // Kept for every connection, now and after each reconnect.
  Relays.prototype.subscribe = function (topic, o) {
    this.subs[topic] = o || { qos: 0 };
    this.list.forEach(function (r) { if (r.up) { try { r.client.subscribe(topic, o || { qos: 0 }); } catch (e) {} } });
  };
  Relays.prototype.unsubscribe = function (topic) {
    delete this.subs[topic];
    this.list.forEach(function (r) { if (r.up) { try { r.client.unsubscribe(topic); } catch (e) {} } });
  };

  // To every broker that is up. Resolves with 1 as soon as one of them has
  // taken it, or with 0 once none can (none up, or each refused or did not
  // answer in time): a message one broker holds has been sent.
  Relays.prototype.publish = function (topic, payload, o) {
    return this._publish(this.list.filter(function (r) { return r.up; }), topic, payload, o);
  };
  // To broker i only, the same way.
  Relays.prototype.publishTo = function (i, topic, payload, o) {
    var r = this.list[i];
    return this._publish(r && r.up ? [r] : [], topic, payload, o);
  };
  Relays.prototype._publish = function (targets, topic, payload, o) {
    return new Promise(function (resolve) {
      var left = targets.length, done = false;
      function finish(v) { if (!done) { done = true; clearTimeout(timer); resolve(v); } }
      if (!left) { resolve(0); return; }
      var timer = setTimeout(function () { finish(0); }, PUBLISH_WAIT_MS);
      targets.forEach(function (r) {
        try {
          r.client.publish(topic, payload, o || {}, function (err) {
            if (!err) finish(1);
            else if (--left === 0) finish(0);
          });
        } catch (e) { if (--left === 0) finish(0); }
      });
    });
  };

  Relays.prototype.stop = function () {
    this.closed = true;
    this.list.forEach(function (r) {
      clearTimeout(r.timer);
      r.up = false;
      try { if (r.client) r.client.end(true); } catch (e) {}
      r.client = null;
    });
  };

  window.hidraRelays = function (urls, opts) { return new Relays(urls, opts); };
})();
