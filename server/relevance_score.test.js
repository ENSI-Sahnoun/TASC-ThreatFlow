const test = require('node:test');
const assert = require('node:assert');
const { scoreRelevance, SCORER_RECENT_DAYS, TIERS } = require('./relevance_score');

const NOW = new Date('2026-08-02T00:00:00Z');
const daysAgo = (n) => new Date(NOW.getTime() - n * 24 * 60 * 60 * 1000).toISOString();
const RECENT = daysAgo(3);
const OLD = daysAgo(300);

const PROFILE = {
  vendors: ['fortinet'],
  products: ['fortios'],
  threat_domains: ['ransomware'],
  sector: 'finance',
  severity_floor: 'medium',
};

// Nothing matches: no vendor overlap, no domain overlap, no CVE facts.
function item(over = {}) {
  return {
    severity: null, cvssScore: null, cvssVersion: null,
    publishedAt: RECENT, industry: null,
    domains: [], cpes: [], cve: null,
    ...over,
  };
}

const tierOf = (p, i) => scoreRelevance(p, i, NOW).tier;

test('TIERS is ordered most to least urgent', () => {
  assert.deepStrictEqual(TIERS, ['act_now', 'watch', 'low', 'not_yours']);
});

test('SCORER_RECENT_DAYS is 90 — not the feed age filter', () => {
  assert.strictEqual(SCORER_RECENT_DAYS, 90);
});

// --- Rung 1: asset match + (KEV or high severity) + recent ---

test('rung 1: asset match on a KEV-listed CVE is act_now', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], cve: { kevListed: true, epssScore: null, severity: 'high', cvssScore: 8.1 } });
  assert.strictEqual(tierOf(PROFILE, i), 'act_now');
});

test('rung 1: asset match on a high-severity recent item is act_now without KEV', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high', cvssScore: 8.1, cvssVersion: '3.1' });
  assert.strictEqual(tierOf(PROFILE, i), 'act_now');
});

test('rung 1 requires recency: the same high-severity asset match when old drops to watch', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high', publishedAt: OLD });
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

// --- Rung 2: KEV + domain match + critical ---

test('rung 2: a critical KEV item in a followed domain is act_now without an asset match', () => {
  const i = item({ domains: ['ransomware'], cve: { kevListed: true, epssScore: null, severity: 'critical', cvssScore: 9.8 } });
  assert.strictEqual(tierOf(PROFILE, i), 'act_now');
});

test('rung 2 needs critical: the same item at high severity is watch, not act_now', () => {
  const i = item({ domains: ['ransomware'], cve: { kevListed: true, epssScore: null, severity: 'high', cvssScore: 8.1 } });
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

// --- Rung 3: asset match alone ---

test('rung 3: a vendor-only asset match with no severity is watch at any age', () => {
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }] })), 'watch');
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }], publishedAt: OLD })), 'watch');
});

// --- Rung 4: domain + floor + recent ---

test('rung 4: a followed domain at the severity floor and recent is watch', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'], severity: 'medium' })), 'watch');
});

test('rung 4 respects the floor: below it the item falls to low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'], severity: 'low' })), 'low');
});

// --- Rung 5: sector match ---

test('rung 5: a recent item naming the profile sector is watch', () => {
  assert.strictEqual(tierOf(PROFILE, item({ industry: 'finance' })), 'watch');
});

// --- Rung 6 / 7 ---

test('rung 6: a followed domain with no severity is low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'] })), 'low');
});

test('rung 6: severity at or above the floor with no personal link is low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ severity: 'critical' })), 'low');
});

test('rung 7: nothing matching is not_yours', () => {
  assert.strictEqual(tierOf(PROFILE, item()), 'not_yours');
});

// --- Guards ---

// A profile with no vendors must not asset-match every item.
test('empty profile arrays match nothing', () => {
  const empty = { vendors: [], products: [], threat_domains: [], sector: 'other', severity_floor: 'medium' };
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], domains: ['ransomware'] });
  assert.strictEqual(tierOf(empty, i), 'not_yours');
});

// 'unknown' is an unverifiable severity, not evidence of one.
test('an unknown severity never satisfies the floor', () => {
  assert.strictEqual(tierOf(PROFILE, item({ severity: 'unknown' })), 'not_yours');
});

// v2 has no 'critical' band; a v2 9.3 is 'high'. Comparing it against a v3 band would
// promote it wrongly.
test('a v2 score is judged on v2 bands, never promoted to critical', () => {
  const i = item({ domains: ['ransomware'], cvssScore: 9.3, cvssVersion: '2.0', cve: { kevListed: true, epssScore: null, severity: null, cvssScore: 9.3 } });
  // v2 9.3 is 'high', so rung 2 (which needs critical) must not fire.
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

test('an undated item is never treated as recent', () => {
  const i = item({ publishedAt: null, cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high' });
  assert.strictEqual(tierOf(PROFILE, i), 'watch', 'must not reach act_now without a date');
});

test('consolidated cve_intel severity outranks the per-item value', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'low', cve: { kevListed: false, epssScore: null, severity: 'critical', cvssScore: 9.8 } });
  assert.strictEqual(tierOf(PROFILE, i), 'act_now');
});

// --- matches and score ---

test('matches name the specific reason, product before vendor', () => {
  const r = scoreRelevance(PROFILE, item({
    cpes: [{ vendor: 'fortinet', product: 'fortios' }], domains: ['ransomware'],
    cve: { kevListed: true, epssScore: 0.7, severity: 'critical', cvssScore: 9.8 },
  }), NOW);
  const kinds = r.matches.map((m) => m.kind);
  assert.ok(kinds.includes('product'));
  assert.ok(kinds.includes('domain'));
  assert.ok(kinds.includes('kev'));
  assert.strictEqual(r.matches.find((m) => m.kind === 'product').value, 'fortinet fortios');
});

test('a not_yours verdict carries no matches', () => {
  assert.deepStrictEqual(scoreRelevance(PROFILE, item(), NOW).matches, []);
});

test('score breaks ties within a tier — a product match outranks a vendor-only match', () => {
  const exact = scoreRelevance(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }] }), NOW);
  const vendorOnly = scoreRelevance(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }] }), NOW);
  assert.strictEqual(exact.tier, vendorOnly.tier);
  assert.ok(exact.score > vendorOnly.score, `${exact.score} should exceed ${vendorOnly.score}`);
});

test('score is finite and non-negative for every tier', () => {
  for (const i of [item(), item({ domains: ['ransomware'] }), item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }] })]) {
    const r = scoreRelevance(PROFILE, i, NOW);
    assert.ok(Number.isFinite(r.score) && r.score >= 0, `bad score ${r.score}`);
  }
});
