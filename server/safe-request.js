const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const { isBlockedIp } = require('./ssrf-guard');

const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 50_000_000;

// Environments with no IPv6 route (this sandbox, some containers) hang or throw
// AggregateError when Node's Happy Eyeballs races an unreachable AAAA record against a
// working A record — curl doesn't hit this because it falls back to IPv4 outright. Putting
// IPv4 first mirrors that fallback without disabling IPv6 anywhere it actually works.
dns.setDefaultResultOrder('ipv4first');

// Passed as the `lookup` option to http(s).request: Node calls this to resolve the
// hostname and then connects to whatever address it returns, so validating here (rather
// than in a separate dns.lookup() call before the request) closes the DNS-rebinding /
// TOCTOU gap where a pre-check and the real connection could resolve to different IPs.
function pinnedLookup(hostname, options, callback) {
  // Must honor the `all` flag Node passes in: http(s).request requests all:true
  // (array of candidates, for Happy Eyeballs) and errors if given a single value instead.
  // No `verbatim` override here (unlike a plain dns.lookup call) so the ipv4first default
  // set above actually takes effect instead of being bypassed by OS-returned order.
  dns.lookup(hostname, { family: options.family, all: true }, (err, records) => {
    if (err) return callback(err);
    const blocked = records.find((r) => isBlockedIp(r.address));
    if (blocked) return callback(new Error(`blocked target address: ${blocked.address} (resolved from ${hostname})`));
    if (options.all) return callback(null, records);
    const first = records[0];
    callback(null, first.address, first.family);
  });
}

// A generic server-side "ThreatFlow-Demo/1.0" UA gets blanket-blocked by several
// providers' bot filters (Reddit, CISA, GitHub, ...) regardless of intent. Presenting as
// an ordinary browser is the standard workaround for polling public feeds/APIs.
const DEFAULT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  Accept: 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
};

function requestOnce(urlStr, { method = 'GET', body, timeoutMs = 15000, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch {
      return reject(new Error('invalid URL'));
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return reject(new Error(`blocked URL scheme: ${parsed.protocol}`));
    }
    // WHATWG URL keeps IPv6 literals bracketed (`[::1]`), which defeats net.isIP()
    // (returns 0) and lets the literal skip this guard. Worse, http.request connects
    // straight to an IP literal WITHOUT calling our pinnedLookup, so for literals this
    // explicit check is the ONLY guard — it must see the bare address and cover IPv6.
    const literalHost = parsed.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(literalHost) && isBlockedIp(literalHost)) {
      return reject(new Error(`blocked target address: ${literalHost}`));
    }

    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(
      parsed,
      { method, lookup: pinnedLookup, timeout: timeoutMs, headers: { ...DEFAULT_HEADERS, ...headers } },
      (res) => {
        let body = '';
        let bytes = 0;
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          bytes += Buffer.byteLength(chunk);
          if (bytes > MAX_BODY_BYTES) {
            req.destroy(new Error('response body too large'));
            return;
          }
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      }
    );
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Fetches a URL with SSRF protection (scheme + resolved-address checks pinned to the
// actual connection) and manual redirect handling, re-validating on every hop.
async function safeRequest(urlStr, opts = {}) {
  let current = urlStr;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const res = await requestOnce(current, opts);
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.location;
      if (!location) throw new Error(`redirect with no Location header (status ${res.status})`);
      current = new URL(location, current).href;
      continue;
    }
    return res;
  }
  throw new Error('too many redirects');
}

module.exports = { safeRequest };
