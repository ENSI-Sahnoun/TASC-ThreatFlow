// Pure presentation rules. No I/O, no DB. Applied at ingest via adapters/shape.js so every
// adapter benefits and none can bypass them. items.raw_json keeps the untouched upstream
// record, so every rule here is re-derivable without a re-sync.

// A title that is nothing but a URL is not a title. An optional short prefix (URLhaus emits
// "sh: http://…", where "sh" is the payload type) is captured separately, not discarded.
// A trailing "(label)" is captured the same way (ransomware.live falls back to the victim's
// bare website as the title when it has no post_title/victim name, then appends " (group)").
// The trailing group requires at least one space before "(" so a URL that legitimately
// contains parentheses (e.g. .../wiki/Stuxnet_(worm)) is never mistaken for a "(label)"
// annotation and truncated mid-URL.
const URL_TITLE_RE = /^\s*(?:([a-z0-9+.-]{1,12}):\s+)?(https?:\/\/\S+?)(?:\s+\(([^)]+)\))?\s*$/i;

const CATEGORY_LABEL = {
  phishing: 'Phishing page',
  malware: 'Malware payload',
  ioc: 'Indicator',
  ransomware: 'Ransomware victim',
  'data-breach': 'Breach record',
};

// Leading lines that carry no information. Feeds prepend these to the body (CISA emits
// "View CSAF\nSummary\n…" on every advisory).
const BOILERPLATE_LEADERS = new Set(['view csaf', 'summary', 'executive summary', 'overview', 'description']);

const ACRONYMS = {
  cc: 'C2', c2: 'C2', rce: 'RCE', rat: 'RAT', apt: 'APT', ics: 'ICS', ot: 'OT',
  cve: 'CVE', url: 'URL', ip: 'IP', dns: 'DNS', md5: 'MD5', sha1: 'SHA1', sha256: 'SHA256',
};

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&apos;': "'", '&nbsp;': ' ' };

const ENUM_TOKEN_RE = /^[a-z0-9]+(?:[_-][a-z0-9]+)+$/i;
const BARE_DOMAIN_RE = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?$/i;
const MAX_SUMMARY = 400;

function extractTitleUrl(title) {
  const m = String(title || '').match(URL_TITLE_RE);
  return m ? m[2] : null;
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

function displayTitle(title, opts = {}) {
  const raw = String(title || '').trim();
  const m = raw.match(URL_TITLE_RE);
  if (!m) return raw;
  const host = hostOf(m[2]);
  if (!host) return raw;
  const label = CATEGORY_LABEL[opts.category] || 'Report';
  const annotation = m[1] || m[3];
  const prefix = annotation ? ` (${annotation})` : '';
  return `${label}${prefix} · ${host}`;
}

function humanizeToken(token) {
  const parts = String(token || '').split(/[_\-\s]+/).filter(Boolean);
  if (!parts.length) return '';
  const mapped = parts.map((p) => ACRONYMS[p.toLowerCase()] || p.toLowerCase());
  // Capitalize the first part unless it resolved to an acronym, which is already correct.
  const first = mapped[0];
  const head = ACRONYMS[parts[0].toLowerCase()] ? first : first.charAt(0).toUpperCase() + first.slice(1);
  return [head, ...mapped.slice(1)].join(' ');
}

function stripHtml(s) {
  let out = s.replace(/<[^>]*>/g, ' ');
  for (const [ent, ch] of Object.entries(ENTITIES)) out = out.split(ent).join(ch);
  return out;
}

function truncateAtSentence(s) {
  if (s.length <= MAX_SUMMARY) return s;
  const window = s.slice(0, MAX_SUMMARY);
  const cut = window.lastIndexOf('. ');
  return `${(cut > 0 ? window.slice(0, cut + 1) : window).trimEnd()}…`;
}

function cleanSummary(text) {
  if (text == null) return null;
  let s = stripHtml(String(text));
  // Drop boilerplate leader lines, then flatten.
  const lines = s.split(/\r?\n/).map((l) => l.trim());
  while (lines.length && (lines[0] === '' || BOILERPLATE_LEADERS.has(lines[0].toLowerCase()))) lines.shift();
  s = lines.join(' ').replace(/\s+/g, ' ').trim();
  if (!s) return null;
  if (ENUM_TOKEN_RE.test(s)) return humanizeToken(s);
  return truncateAtSentence(s);
}

function normalizeLink(link) {
  const s = String(link == null ? '' : link).trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) return s;
  if (BARE_DOMAIN_RE.test(s)) return `https://${s}`;
  return null;
}

module.exports = { extractTitleUrl, displayTitle, cleanSummary, humanizeToken, normalizeLink };
