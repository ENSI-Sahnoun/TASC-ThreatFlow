const path = require('node:path');
const fs = require('node:fs');
const { domainsForCategory } = require('./normalize');
const { isDomain } = require('./domains');
const { isBlockedIp } = require('./ssrf-guard');
const { scoreFromVector, severityFromScore, canonicalSeverity } = require('./cvss');

const ACTORS = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'threat-actors.json'), 'utf8'));
const FAMILIES = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'malware-families.json'), 'utf8'));

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HASH_RE = /\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>)]+/gi;

function extractCves(text) {
  const found = String(text || '').match(CVE_RE) || [];
  return [...new Set(found.map((c) => c.toUpperCase()))];
}

function extractIocs(text) {
  const s = String(text || '');
  const iocs = [];
  const push = (type, value) => { if (!iocs.some((i) => i.type === type && i.value === value)) iocs.push({ type, value }); };
  for (const h of s.match(HASH_RE) || []) push(h.length === 64 ? 'sha256' : h.length === 40 ? 'sha1' : 'md5', h.toLowerCase());
  // IP_RE also matches 4-part version strings (e.g. "10.15.7.1"). Drop octet-overflow
  // matches and private/reserved addresses — the latter aren't useful public IOCs and
  // catch the most common version-number false positives before they hit enrichment.
  // (Public routable version strings like "1.0.0.0" can't be told apart syntactically.)
  for (const ip of s.match(IP_RE) || []) {
    const parts = ip.split('.').map(Number);
    if (parts.every((n) => n >= 0 && n <= 255) && !isBlockedIp(ip)) push('ip', ip);
  }
  for (const u of s.match(URL_RE) || []) push('url', u);
  return iocs;
}

// Word-boundary matching, not substring. ATT&CK's real catalogue includes living-off-the-land
// tool names (at, cmd, reg, sc, wmic, certutil, netsh) and group/malware names that double as
// ordinary English words (Empire) -- .includes() would substring-match those into unrelated
// text on nearly every item. This is a real fix against today's 10+10 dictionary too, just
// invisible until now because none of those 20 names happen to be substrings of common words.
function nameRegex(name) {
  return new RegExp(`\\b${name.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
}

function matchDictionary(text, list) {
  const s = String(text || '');
  const hits = [];
  for (const entry of list) {
    const names = [entry.name, ...(entry.aliases || [])];
    if (names.some((n) => nameRegex(n).test(s))) hits.push(entry.name);
  }
  return hits;
}

function threatTypeFor(category) {
  switch (category) {
    case 'cve': return 'vulnerability';
    case 'ransomware': return 'ransomware';
    case 'malware': return 'malware';
    case 'ioc': return 'ioc';
    case 'advisory': return 'advisory';
    default: return category || 'other';
  }
}

function enrichItem(item, { kevCveSet } = { kevCveSet: new Set() }) {
  const text = `${item.title || ''} ${item.summary || ''}`;
  const native = item.native || {};

  // Phishing feeds are URL dumps, not vulnerability reports — an incidental "CVE-xxxx" mention
  // in a phishing kit's lure text isn't a real disclosure and must never feed cve_intel
  // consolidation or count as source corroboration for that CVE's score.
  const cves = item.category === 'phishing'
    ? []
    : [...new Set([...(native.cveIds || []).map((c) => c.toUpperCase()), ...extractCves(text)])];
  const iocs = [...(native.iocs || [])];
  for (const io of extractIocs(text)) if (!iocs.some((i) => i.type === io.type && i.value === io.value)) iocs.push(io);
  const actors = [...new Set([...(native.actors || []), ...matchDictionary(text, ACTORS)])];
  const families = [...new Set([...(native.malwareFamilies || []), ...matchDictionary(text, FAMILIES)])];

  // Prefer the feed's number; fall back to scoring its vector. A feed-supplied severity word
  // is honoured only if it maps to the canonical enum — blobs and arrays become 'unknown'.
  const cvssScore = native.cvssScore != null ? Number(native.cvssScore) : scoreFromVector(native.cvssVector);
  const cvssVersion = native.cvssVersion || null;
  const fromLabel = native.severity != null ? canonicalSeverity(native.severity) : null;
  const severity = (fromLabel && fromLabel !== 'unknown')
    ? fromLabel
    : (severityFromScore(cvssScore, cvssVersion) || (native.severity != null ? 'unknown' : null));

  let exploitationStatus = native.exploitation || null;
  if (!exploitationStatus && cves.some((c) => kevCveSet.has(c))) exploitationStatus = 'actively_exploited';

  const domains = new Set(domainsForCategory(item.category));
  if (cves.some((c) => kevCveSet.has(c))) domains.add('zero-day');
  if (families.length) domains.add('malware');
  if (/ransomware/i.test(text)) domains.add('ransomware');
  if (/phish/i.test(text)) domains.add('phishing');
  const domainList = [...domains].filter(isDomain);

  return {
    cves,
    iocs,
    actors,
    families,
    domains: domainList,
    cpes: native.cpes || [],
    severity,
    cvssScore,
    cvssVersion,
    epssScore: native.epssScore != null ? Number(native.epssScore) : null,
    exploitationStatus,
    vendor: native.vendor || null,
    region: native.region || null,
    industry: native.industry || null,
    threatType: threatTypeFor(item.category),
  };
}

module.exports = { enrichItem, extractCves, extractIocs, matchDictionary };
