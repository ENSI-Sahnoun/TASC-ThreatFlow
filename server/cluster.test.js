const { test } = require('node:test');
const assert = require('node:assert');
const { titleTokens, jaccard, itemsMatch, clusterItems } = require('./cluster');

const T0 = '2026-07-20T10:00:00.000Z';
const T1 = '2026-07-20T14:00:00.000Z';
const FAR = '2026-07-01T10:00:00.000Z';

const item = (o) => ({ cves: [], actors: [], families: [], confidence: 0.6, published_at: T0, ...o });

test('titleTokens drops stopwords and punctuation', () => {
  const t = titleTokens('New Siemens ROX II vulnerability: attackers exploit it!');
  assert.ok(t.has('siemens'));
  assert.ok(t.has('rox'));
  assert.ok(!t.has('new'));
  assert.ok(!t.has('vulnerability'));
  assert.ok(!t.has('attackers'));
});

test('jaccard measures overlap', () => {
  assert.strictEqual(jaccard(new Set(['a', 'b']), new Set(['a', 'b'])), 1);
  assert.strictEqual(jaccard(new Set(['a']), new Set(['b'])), 0);
  assert.strictEqual(jaccard(new Set(), new Set()), 0);
});

test('identical CVE sets cluster across sources', () => {
  const out = clusterItems([
    item({ id: 1, source_id: 10, title: 'Siemens ROX II flaws', cves: ['CVE-2026-3143'] }),
    item({ id: 2, source_id: 11, title: 'Three zero-days in Siemens gear', cves: ['CVE-2026-3143'], published_at: T1 }),
  ]);
  assert.strictEqual(out.length, 1);
  assert.deepStrictEqual(out[0].itemIds.sort(), [1, 2]);
  assert.deepStrictEqual(out[0].sourceIds.sort(), [10, 11]);
});

test('shared actor plus title overlap clusters; unrelated titles do not', () => {
  const out = clusterItems([
    item({ id: 1, source_id: 10, title: 'Lazarus targets defence contractors', actors: ['Lazarus'] }),
    item({ id: 2, source_id: 11, title: 'Lazarus hits defence contractors again', actors: ['Lazarus'] }),
    item({ id: 3, source_id: 12, title: 'Lazarus and cryptocurrency exchange theft', actors: ['Lazarus'] }),
  ]);
  const sizes = out.map((c) => c.itemIds.length).sort();
  assert.deepStrictEqual(sizes, [1, 2]);
});

test('items outside the 72h window never cluster', () => {
  const out = clusterItems([
    item({ id: 1, source_id: 10, title: 'Siemens ROX II flaws', cves: ['CVE-2026-3143'] }),
    item({ id: 2, source_id: 11, title: 'Siemens ROX II flaws', cves: ['CVE-2026-3143'], published_at: FAR }),
  ]);
  assert.strictEqual(out.length, 2);
});

test('primary item is the highest-confidence member', () => {
  const out = clusterItems([
    item({ id: 1, source_id: 10, title: 'Siemens ROX II flaws', cves: ['CVE-2026-3143'], confidence: 0.6 }),
    item({ id: 2, source_id: 11, title: 'Siemens ROX II flaws', cves: ['CVE-2026-3143'], confidence: 0.95 }),
  ]);
  assert.strictEqual(out[0].primaryItemId, 2);
});

test('itemsMatch on raw items with shared actor and high title overlap', () => {
  const a = item({ id: 1, source_id: 10, title: 'Lazarus targets defence contractors', actors: ['Lazarus'], published_at: T0 });
  const b = item({ id: 2, source_id: 11, title: 'Lazarus hits defence contractors again', actors: ['Lazarus'], published_at: T1 });
  // No _tokens field — must compute from title
  assert.strictEqual(itemsMatch(a, b), true);
});

test('itemsMatch on raw items with shared actor and low title overlap', () => {
  const a = item({ id: 1, source_id: 10, title: 'Lazarus targets defence contractors', actors: ['Lazarus'], published_at: T0 });
  const b = item({ id: 2, source_id: 11, title: 'Lazarus and cryptocurrency theft', actors: ['Lazarus'], published_at: T1 });
  // No _tokens field — must compute from title; low overlap should not cluster
  assert.strictEqual(itemsMatch(a, b), false);
});
