'use strict';
/**
 * One HTTPS download with redirects and a progress line, shared by the
 * packaging scripts. Nothing clever — it exists so the builder and the
 * release refresher do not each carry their own copy.
 */
const fs    = require('fs');
const https = require('https');

function download(url, dest, redirects) {
  redirects = redirects === undefined ? 10 : redirects;
  return new Promise(function(resolve, reject) {
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { headers: { 'User-Agent': 'HidraNet-macOS-Builder/1.0' } }, function(res) {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        file.close();
        try { fs.unlinkSync(dest); } catch(_) {}
        if (redirects <= 0) return reject(new Error('Too many redirects'));
        return download(res.headers.location, dest, redirects - 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        try { fs.unlinkSync(dest); } catch(_) {}
        return reject(new Error('HTTP ' + res.statusCode + ' from ' + url));
      }
      const total = parseInt(res.headers['content-length'] || '0');
      let recv = 0, lastPct = -1;
      res.on('data', function(chunk) {
        recv += chunk.length;
        if (total > 0) {
          const pct = Math.floor(recv / total * 20) * 5;
          if (pct !== lastPct) {
            process.stdout.write('\r    ' + pct + '%  ' +
              (recv / 1048576).toFixed(1) + ' / ' + (total / 1048576).toFixed(1) + ' MB   ');
            lastPct = pct;
          }
        }
      });
      res.pipe(file);
      file.on('finish', function() { file.close(); process.stdout.write('\n'); resolve(); });
    });
    req.on('error', function(err) {
      file.close();
      try { fs.unlinkSync(dest); } catch(_) {}
      reject(err);
    });
  });
}

module.exports = { download };
