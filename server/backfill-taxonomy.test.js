const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfillItem, backfill } = require('./backfill-taxonomy');

test('backfillItem reclassifies a stale category and canonicalizes a stale severity', () => {
  const dirty = backfillItem({
    id: 1, category: 'other', severity: 'important', source_category: 'Data Breaches',
  });
  assert.strictEqual(dirty.category, 'data-breach');
  assert.strictEqual(dirty.severity, 'high');

  assert.strictEqual(backfillItem({
    id: 2, category: 'news', severity: null, source_category: 'News',
  }), null);

  assert.strictEqual(backfillItem({
    id: 3, category: 'cve', severity: 'critical', source_category: 'Vulnerability Intelligence',
  }), null);
});

test('backfillItem never turns a null severity into a value', () => {
  const out = backfillItem({ id: 4, category: 'other', severity: null, source_category: 'Phishing' });
  assert.strictEqual(out.category, 'phishing');
  assert.strictEqual(out.severity, null);
});

test('backfillItem folds a stored JSON blob severity down to unknown', () => {
  const blob = '{"{\\"type\\":\\"CVSS_V3\\",\\"score\\":\\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\\"}"}';
  const out = backfillItem({ id: 5, category: 'cve', severity: blob, source_category: 'Vulnerability Intelligence' });
  assert.strictEqual(out.severity, 'unknown');
});

test('backfill dry run reports changes without writing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind, category) VALUES ('S','text_feed','Data Breaches') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, severity) VALUES ($1, 'other', 'x', 'moderate')`, [s.id]);

    const dry = await backfill(store, { dryRun: true });
    assert.strictEqual(dry.changed, 1);
    const unchanged = await store.get('SELECT category, severity FROM items');
    assert.strictEqual(unchanged.category, 'other');
    assert.strictEqual(unchanged.severity, 'moderate');

    const real = await backfill(store, { dryRun: false });
    assert.strictEqual(real.changed, 1);
    const row = await store.get('SELECT category, severity FROM items');
    assert.strictEqual(row.category, 'data-breach');
    assert.strictEqual(row.severity, 'medium');
  } finally {
    await cleanup();
  }
});

test('backfill is idempotent — a second run changes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind, category) VALUES ('S','text_feed','Phishing') RETURNING id");
    await store.run("INSERT INTO items (source_id, category, title) VALUES ($1,'other','x')", [s.id]);
    await backfill(store, { dryRun: false });
    const second = await backfill(store, { dryRun: false });
    assert.strictEqual(second.changed, 0);
  } finally {
    await cleanup();
  }
});
