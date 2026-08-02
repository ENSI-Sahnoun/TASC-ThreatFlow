const { test } = require('node:test');
const assert = require('node:assert');
const { extractTitleUrl, displayTitle, cleanSummary, humanizeToken, normalizeLink } = require('./present');

test('extractTitleUrl finds URL-only titles, ignores real titles', () => {
  assert.strictEqual(extractTitleUrl('https://www.roblox.com.ml/users/1/profile'), 'https://www.roblox.com.ml/users/1/profile');
  assert.strictEqual(extractTitleUrl('sh: http://202.155.8.56/RSW0'), 'http://202.155.8.56/RSW0');
  assert.strictEqual(extractTitleUrl('Cobalt Strike: 47.95.207.79:443'), null);
  assert.strictEqual(extractTitleUrl('CISA adds SharePoint RCE to KEV'), null);
});

test('displayTitle turns URL titles into human phrases by category', () => {
  assert.strictEqual(displayTitle('https://www.roblox.com.ml/users/1/profile', { category: 'phishing' }), 'Phishing page · www.roblox.com.ml');
  assert.strictEqual(displayTitle('sh: http://202.155.8.56/RSW0', { category: 'malware' }), 'Malware payload (sh) · 202.155.8.56');
  assert.strictEqual(displayTitle('  Real headline  ', { category: 'news' }), 'Real headline');
});

// Regression: ransomware.live falls back to the victim's bare website as the title when it
// has no post_title/victim name, then the bespoke adapter appends " (group)". The original
// URL_TITLE_RE only recognised a leading prefix ("sh: http://…"), so a trailing "(group)"
// annotation left the whole string unmatched and the raw URL passed straight through as the
// displayed title.
test('displayTitle also recognises a trailing (label) annotation after the URL', () => {
  assert.strictEqual(extractTitleUrl('https://www.statebankofnauvoo.com/ (incransom)'), 'https://www.statebankofnauvoo.com/');
  assert.strictEqual(
    displayTitle('https://www.statebankofnauvoo.com/ (incransom)', { category: 'ransomware' }),
    'Ransomware victim (incransom) · www.statebankofnauvoo.com'
  );
});

// Regression: the trailing-annotation group above requires a space before "(" so a URL that
// legitimately contains parentheses is never treated as having a "(label)" annotation and
// truncated mid-URL (the greedy optional group would otherwise backtrack the lazy \S+? short
// to make an in-URL "(...)" match).
test('extractTitleUrl does not truncate a URL containing parentheses with no preceding space', () => {
  assert.strictEqual(
    extractTitleUrl('https://en.wikipedia.org/wiki/Stuxnet_(worm)'),
    'https://en.wikipedia.org/wiki/Stuxnet_(worm)'
  );
  assert.strictEqual(extractTitleUrl('http://x.test/a?b=(1)'), 'http://x.test/a?b=(1)');
});

test('cleanSummary strips HTML, boilerplate leaders and collapses whitespace', () => {
  assert.strictEqual(cleanSummary('View CSAF\nSummary\nSuccessful exploitation of these.'), 'Successful exploitation of these.');
  assert.strictEqual(cleanSummary('<p>Hello &amp; welcome</p>'), 'Hello & welcome');
  assert.strictEqual(cleanSummary('botnet_cc'), 'Botnet C2');
  assert.strictEqual(cleanSummary('   '), null);
  assert.strictEqual(cleanSummary(null), null);
});

test('cleanSummary truncates at a sentence boundary', () => {
  const long = `${'A'.repeat(380)}. ${'B'.repeat(200)}.`;
  const out = cleanSummary(long);
  assert.ok(out.length <= 401, `expected <=401, got ${out.length}`);
  assert.ok(out.endsWith('…'));
});

test('humanizeToken expands enums and preserves acronyms', () => {
  assert.strictEqual(humanizeToken('botnet_cc'), 'Botnet C2');
  assert.strictEqual(humanizeToken('malware_download'), 'Malware download');
  assert.strictEqual(humanizeToken('rce-exploit'), 'RCE exploit');
});

test('normalizeLink repairs bare domains and rejects non-URLs', () => {
  assert.strictEqual(normalizeLink('000webhost.com'), 'https://000webhost.com');
  assert.strictEqual(normalizeLink('\n   https://cert.europa.eu/  '), 'https://cert.europa.eu/');
  assert.strictEqual(normalizeLink('not a link'), null);
  assert.strictEqual(normalizeLink(''), null);
  assert.strictEqual(normalizeLink(null), null);
});

const { bulkIocSummary } = require('./present');

test('bulkIocSummary describes a phishing URL from its host and date', () => {
  assert.strictEqual(
    bulkIocSummary({ category: 'phishing', value: 'http://evil.test/login', sourceName: 'OpenPhish', firstSeen: '2026-07-30T10:00:00Z' }),
    'Phishing page on evil.test, first seen 2026-07-30, reported by OpenPhish.');
});

test('bulkIocSummary labels malware payloads distinctly', () => {
  assert.strictEqual(
    bulkIocSummary({ category: 'malware', value: 'http://bad.test/x.exe', sourceName: 'abuse.ch URLhaus', firstSeen: '2026-07-30T10:00:00Z' }),
    'Malware payload on bad.test, first seen 2026-07-30, reported by abuse.ch URLhaus.');
});

test('bulkIocSummary omits the date clause when none is supplied', () => {
  assert.strictEqual(
    bulkIocSummary({ category: 'phishing', value: 'http://evil.test/login', sourceName: 'OpenPhish', firstSeen: null }),
    'Phishing page on evil.test, reported by OpenPhish.');
});

test('bulkIocSummary returns null when it has nothing to describe', () => {
  assert.strictEqual(bulkIocSummary({ category: 'phishing', value: 'not-a-url', sourceName: 'OpenPhish' }), null);
  assert.strictEqual(bulkIocSummary({ category: 'news', value: 'http://x.test/', sourceName: 'S' }), null);
});

// The backfill reads published_at from Postgres as a Date object, not an ISO string.
test('bulkIocSummary accepts a Date object for firstSeen', () => {
  assert.strictEqual(
    bulkIocSummary({ category: 'phishing', value: 'http://evil.test/a', sourceName: 'OpenPhish', firstSeen: new Date('2026-07-30T10:00:00Z') }),
    'Phishing page on evil.test, first seen 2026-07-30, reported by OpenPhish.');
  assert.strictEqual(
    bulkIocSummary({ category: 'phishing', value: 'http://evil.test/a', sourceName: 'OpenPhish', firstSeen: new Date('nope') }),
    'Phishing page on evil.test, reported by OpenPhish.');
});
