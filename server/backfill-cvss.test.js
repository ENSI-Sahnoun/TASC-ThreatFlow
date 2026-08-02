const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfill, backfillRow } = require('./backfill-cvss');

const RAW_V2 = JSON.stringify({
  id: 'CVE-2002-1',
  metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5.0 }, baseSeverity: 'MEDIUM' }] },
  configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:sendmail:sendmail:8.9.3:*:*:*:*:*:*:*' }] }] }],
});

async function seed(store, raw, cols = {}) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('bf','json_api',true) RETURNING id");
  const item = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, raw_json, severity, cvss_score, cvss_version)
     VALUES ($1,'cve','CVE-2002-1','CVE-2002-1',$2,$3,$4,$5) RETURNING id`,
    [src.id, raw, cols.severity || null, cols.cvssScore || null, cols.cvssVersion || null]);
  return item.id;
}

test('backfillRow recovers severity, score, version and cpes from raw_json', () => {
  assert.deepStrictEqual(
    backfillRow({ id: 1, raw_json: RAW_V2, severity: null, cvss_score: null, cvss_version: null }),
    {
      severity: 'medium',
      cvssScore: 5.0,
      cvssVersion: '2.0',
      cpes: [{ part: 'a', vendor: 'sendmail', product: 'sendmail' }],
    });
});

test('backfillRow returns null when nothing would change', () => {
  assert.strictEqual(
    backfillRow({ id: 1, raw_json: JSON.stringify({ id: 'X' }), severity: null, cvss_score: null, cvss_version: null }),
    null);
});

test('backfillRow tolerates unparseable raw_json', () => {
  assert.strictEqual(
    backfillRow({ id: 1, raw_json: '{not json', severity: null, cvss_score: null, cvss_version: null }),
    null);
});

test('backfill writes recovered values and cpe rows', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, RAW_V2);
    const result = await backfill(store, { dryRun: false });
    assert.strictEqual(result.changed, 1);
    const row = await store.get('SELECT severity, cvss_score, cvss_version FROM items WHERE id=$1', [id]);
    assert.deepStrictEqual(row, { severity: 'medium', cvss_score: 5, cvss_version: '2.0' });
    const cpes = await store.all('SELECT vendor, product FROM item_cpes WHERE item_id=$1', [id]);
    assert.deepStrictEqual(cpes, [{ vendor: 'sendmail', product: 'sendmail' }]);
  } finally { await cleanup(); }
});

test('backfill is idempotent — a second run changes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store, RAW_V2);
    await backfill(store, { dryRun: false });
    const second = await backfill(store, { dryRun: false });
    assert.strictEqual(second.changed, 0);
    const cpes = await store.all('SELECT vendor FROM item_cpes');
    assert.strictEqual(cpes.length, 1, 'cpe rows must not accumulate');
  } finally { await cleanup(); }
});

test('backfill --dry-run writes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, RAW_V2);
    const result = await backfill(store, { dryRun: true });
    assert.strictEqual(result.changed, 1, 'dry run still reports what it would change');
    const row = await store.get('SELECT severity FROM items WHERE id=$1', [id]);
    assert.strictEqual(row.severity, null);
    assert.strictEqual((await store.all('SELECT 1 FROM item_cpes')).length, 0);
  } finally { await cleanup(); }
});

// Never destroys a value a vendor actually supplied.
test('backfill leaves an existing severity untouched', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, RAW_V2, { severity: 'critical', cvssScore: 9.8, cvssVersion: '3.1' });
    await backfill(store, { dryRun: false });
    const row = await store.get('SELECT severity, cvss_score, cvss_version FROM items WHERE id=$1', [id]);
    assert.deepStrictEqual(row, { severity: 'critical', cvss_score: 9.8, cvss_version: '3.1' });
  } finally { await cleanup(); }
});
