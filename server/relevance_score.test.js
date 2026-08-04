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
  // Ladder v2: only a profile_assets row can reach act_now, so the rung-1 and rung-2 cases
  // below need one. Exposure is 'unknown' deliberately — the common real state, and the one
  // that must still be allowed to be urgent.
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }],
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

// Ladder v3: severity alone no longer reaches act_now. The verification profile measured
// against ladder v2 produced 310 act_now items, of which 1 carried real exploitation
// evidence — "act now" on 310 items is the vagueness this spec set out to remove, just with
// better sentences underneath it. Only a KEV listing (or, later, a high EPSS score) proves
// someone is actually exploiting it.
test('rung 1: asset match on a high-severity recent item without KEV caps at watch', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high', cvssScore: 8.1, cvssVersion: '3.1' });
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

test('rung 1: asset match on a KEV-listed CVE with only a medium severity is still act_now', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], cve: { kevListed: true, epssScore: null, severity: 'medium', cvssScore: 5.0 } });
  assert.strictEqual(tierOf(PROFILE, i), 'act_now');
});

test('rung 1 requires recency: the same high-severity asset match when old drops to watch', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high', publishedAt: OLD });
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

// --- A critical, KEV-listed item in a followed domain with NO asset match: watch, not act_now ---

test('a critical KEV item in a followed domain with no asset match is watch, not act_now', () => {
  const i = item({ domains: ['ransomware'], cve: { kevListed: true, epssScore: null, severity: 'critical', cvssScore: 9.8 } });
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

test('the same item, when old, drops to low — domain-only urgency still requires recency', () => {
  const i = item({ domains: ['ransomware'], publishedAt: OLD, cve: { kevListed: true, epssScore: null, severity: 'critical', cvssScore: 9.8 } });
  assert.strictEqual(tierOf(PROFILE, i), 'low');
});

// --- Rung 2: asset match alone ---

test('rung 2: an asset match with no severity is watch at any age', () => {
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }] })), 'watch');
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], publishedAt: OLD })), 'watch');
});

// Ladder v2 changed this deliberately. Before, a bare vendor match reached watch; 'microsoft'
// matches 7519 item_cpes rows, so that made the verdict noise. A vendor the profile merely
// lists, with no asset row behind it, is now background information.
test('rung 5: a vendor-only match is low at any age, never watch', () => {
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }] })), 'low');
  assert.strictEqual(tierOf(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }], publishedAt: OLD })), 'low');
});

// --- Rung 3: domain + floor + recent ---

test('rung 3: a followed domain at the severity floor and recent is watch', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'], severity: 'medium' })), 'watch');
});

test('rung 3 respects the floor: below it the item falls to low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'], severity: 'low' })), 'low');
});

// --- Rung 4: sector match ---

test('rung 4: a recent item naming the profile sector is watch', () => {
  assert.strictEqual(tierOf(PROFILE, item({ industry: 'finance' })), 'watch');
});

// --- Rung 5 / 6 ---

test('rung 5: a followed domain with no severity is low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ domains: ['ransomware'] })), 'low');
});

test('rung 5: severity at or above the floor with no personal link is low', () => {
  assert.strictEqual(tierOf(PROFILE, item({ severity: 'critical' })), 'low');
});

test('rung 6: nothing matching is not_yours', () => {
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
  // v2 9.3 is 'high', not 'critical' — irrelevant to act_now now that act_now requires an asset
  // match regardless of severity band; this only proves the item still lands on watch (rung 3).
  assert.strictEqual(tierOf(PROFILE, i), 'watch');
});

test('an undated item is never treated as recent', () => {
  const i = item({ publishedAt: null, cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'high' });
  assert.strictEqual(tierOf(PROFILE, i), 'watch', 'must not reach act_now without a date');
});

test('consolidated cve_intel severity outranks the per-item value in the match list', () => {
  const i = item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }], severity: 'low', cve: { kevListed: false, epssScore: null, severity: 'critical', cvssScore: 9.8 } });
  const r = scoreRelevance(PROFILE, i, NOW);
  // Not act_now: no KEV, and ladder v3 requires exploitation evidence for the top rung.
  assert.strictEqual(r.tier, 'watch');
  assert.ok(r.matches.some((m) => m.kind === 'severity' && m.value === 'critical'),
    'the consolidated (not the per-item) severity is what drives the match list');
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

// The two now land in different tiers, so score is compared across the boundary rather than
// within it: an asset match must still outrank a vendor-only one on the ordering axis too.
test('score ranks an asset match above a vendor-only match', () => {
  const exact = scoreRelevance(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }] }), NOW);
  const vendorOnly = scoreRelevance(PROFILE, item({ cpes: [{ vendor: 'fortinet', product: 'other' }] }), NOW);
  assert.strictEqual(exact.tier, 'watch');
  assert.strictEqual(vendorOnly.tier, 'low');
  assert.ok(exact.score > vendorOnly.score, `${exact.score} should exceed ${vendorOnly.score}`);
});

test('score is finite and non-negative for every tier', () => {
  for (const i of [item(), item({ domains: ['ransomware'] }), item({ cpes: [{ vendor: 'fortinet', product: 'fortios' }] })]) {
    const r = scoreRelevance(PROFILE, i, NOW);
    assert.ok(Number.isFinite(r.score) && r.score >= 0, `bad score ${r.score}`);
  }
});

// --- Ladder v2: assets, exposure, and the demotion of vendor-level matches ---

const ASSET_PROFILE = {
  ...PROFILE,
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
};
const cpe = (vendor, product) => ({ vendor, product });
const kevItem = (over = {}) => item({
  cve: { kevListed: true, severity: 'critical', cvssScore: 9.8, epssScore: null }, ...over });

test('ladder v2: an internet-facing asset on a KEV CVE is act_now', () => {
  const r = scoreRelevance(ASSET_PROFILE, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW);
  assert.strictEqual(r.tier, 'act_now');
  assert.strictEqual(r.exposure, 'internet');
});

test('ladder v2: the same flaw on an internal-only asset is watch, not act_now', () => {
  const profile = { ...PROFILE, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internal' }] };
  assert.strictEqual(scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW).tier, 'watch');
});

// Withholding act_now because the user skipped a survey question fails in the wrong direction.
test('ladder v2: unknown exposure still reaches act_now', () => {
  const profile = { ...PROFILE, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }] };
  assert.strictEqual(scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW).tier, 'act_now');
});

// The whole point of the change: 'microsoft' matches 7519 item_cpes rows, so a vendor-level
// claim must never be urgent.
test('ladder v2: a vendor-only match never exceeds low, even on a KEV CVE', () => {
  const profile = { vendors: ['microsoft'], products: [], threat_domains: [], sector: 'finance',
    severity_floor: 'medium', assets: [] };
  assert.strictEqual(scoreRelevance(profile, kevItem({ cpes: [cpe('microsoft', 'windows')] }), NOW).tier, 'low');
});

test('ladder v2: a legacy products[] match with no asset row never exceeds low', () => {
  const profile = { ...PROFILE, assets: [] };
  assert.strictEqual(scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW).tier, 'low');
});

test('ladder v2: an asset match alone, old and unsevere, is still watch', () => {
  const r = scoreRelevance(ASSET_PROFILE, item({ cpes: [cpe('fortinet', 'fortios')], publishedAt: OLD }), NOW);
  assert.strictEqual(r.tier, 'watch');
});

test('ladder v2: exposure is unknown when no asset matched', () => {
  assert.strictEqual(scoreRelevance(ASSET_PROFILE, item(), NOW).exposure, 'unknown');
});

// An internet-facing instance is the one that matters even if the same product also runs
// internally, so the strongest exposure among matched assets decides the rung.
test('ladder v2: the strongest exposure among matched assets wins', () => {
  const profile = { ...PROFILE, assets: [
    { vendor: 'fortinet', product: 'fortios', exposure: 'internal' },
    { vendor: 'fortinet', product: 'fortiproxy', exposure: 'internet' },
  ] };
  const r = scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios'), cpe('fortinet', 'fortiproxy')] }), NOW);
  assert.strictEqual(r.exposure, 'internet');
  assert.strictEqual(r.tier, 'act_now');
});

test('ladder v2: an asset match emits a product match reason', () => {
  const r = scoreRelevance(ASSET_PROFILE, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW);
  assert.ok(r.matches.some((m) => m.kind === 'product' && m.value === 'fortinet fortios'));
});

test('ladder v2: a profile with no assets key at all does not throw', () => {
  const profile = { vendors: [], products: [], threat_domains: [], sector: 'finance', severity_floor: 'medium' };
  assert.strictEqual(scoreRelevance(profile, item(), NOW).tier, 'not_yours');
});
