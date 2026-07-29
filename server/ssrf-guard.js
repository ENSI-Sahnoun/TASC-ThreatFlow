const dns = require('node:dns/promises');
const net = require('node:net');

// Blocks loopback, link-local, private, unspecified, and metadata-service ranges.
function isBlockedIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
    if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT, also used for cloud metadata (e.g. 100.100.100.200)
    if (a === 0) return true; // "this network"
    return false;
  }
  if (type === 6) {
    const norm = ip.toLowerCase();
    if (norm === '::1') return true; // loopback
    if (norm === '::') return true; // unspecified
    if (norm.startsWith('fe80:') || norm.startsWith('fe8') || norm.startsWith('fe9') || norm.startsWith('fea') || norm.startsWith('feb')) return true; // link-local fe80::/10
    if (norm.startsWith('fc') || norm.startsWith('fd')) return true; // unique local fc00::/7
    if (norm.startsWith('::ffff:')) return isBlockedIp(norm.slice(7)); // IPv4-mapped
    if (norm.startsWith('64:ff9b::')) return isBlockedIp(norm.slice(9)); // NAT64 well-known prefix, embeds IPv4
    return false;
  }
  return true; // unknown/unparseable -> block
}

// Throws if the URL's scheme isn't http(s) or its resolved address is in a blocked range.
// Call this immediately before every outbound fetch, since DNS can change between calls (TOCTOU/rebinding).
async function assertSafeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('invalid URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`blocked URL scheme: ${parsed.protocol}`);
  }
  // Strip IPv6 literal brackets so net.isIP()/isBlockedIp() see the bare address;
  // otherwise `[::1]` is treated as a hostname and slips past the literal check.
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) throw new Error(`blocked target address: ${hostname}`);
    return parsed;
  }
  const records = await dns.lookup(hostname, { all: true });
  if (records.length === 0) throw new Error('DNS resolution failed');
  for (const rec of records) {
    if (isBlockedIp(rec.address)) throw new Error(`blocked target address: ${rec.address} (resolved from ${hostname})`);
  }
  return parsed;
}

module.exports = { assertSafeUrl, isBlockedIp };
