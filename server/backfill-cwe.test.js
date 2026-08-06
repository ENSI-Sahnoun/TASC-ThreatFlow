const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfill, backfillRow } = require('./backfill-cwe');

const RAW_WITH_CWES = JSON.stringify({
  id: 'CVE-2026-1',
  weaknesses: [{ type: 'Primary', description: [{ lang: 'en', value: 'CWE-79' }] }],
});
const RAW_NOINFO_ONLY = JSON.stringify({
  id: 'CVE-2026-2',
  weaknesses: [{ type: 'Primary', description: [{ lang: 'en', value: 'CWE-noinfo' }] }],
});
const RAW_NO_WEAKNESSES = JSON.stringify({ id: 'CVE-2026-3' });

async function seed(store, extId, raw) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('bf-cwe','json_api',true) RETURNING id");
  const item = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, raw_json)
     VALUES ($1,'cve',$2,$2,$3) RETURNING id`, [src.id, extId, raw]);
  return item.id;
}

test('backfillRow extracts CWE ids from raw_json', () => {
  assert.deepStrictEqual(backfillRow({ raw_json: RAW_WITH_CWES }), ['CWE-79']);
});

test('backfillRow returns [] when raw_json carries only CWE-noinfo', () => {
  assert.deepStrictEqual(backfillRow({ raw_json: RAW_NOINFO_ONLY }), []);
});

test('backfillRow returns [] for a raw_json with no weaknesses key', () => {
  assert.deepStrictEqual(backfillRow({ raw_json: RAW_NO_WEAKNESSES }), []);
});

test('backfillRow tolerates unparseable raw_json', () => {
  assert.deepStrictEqual(backfillRow({ raw_json: '{not json' }), []);
});

test('backfill writes item_cwes rows for items with weaknesses data', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, 'CVE-2026-1', RAW_WITH_CWES);
    const result = await backfill(store, { dryRun: false });
    assert.strictEqual(result.changed, 1);
    const rows = await store.all('SELECT cwe_id FROM item_cwes WHERE item_id = $1', [id]);
    assert.deepStrictEqual(rows.map((r) => r.cwe_id), ['CWE-79']);
  } finally { await cleanup(); }
});

test('backfill writes no rows for CWE-noinfo-only or weaknesses-free items, without error', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id1 = await seed(store, 'CVE-2026-2', RAW_NOINFO_ONLY);
    const id2 = await seed(store, 'CVE-2026-3', RAW_NO_WEAKNESSES);
    await backfill(store, { dryRun: false });
    assert.deepStrictEqual(await store.all('SELECT 1 FROM item_cwes WHERE item_id = $1', [id1]), []);
    assert.deepStrictEqual(await store.all('SELECT 1 FROM item_cwes WHERE item_id = $1', [id2]), []);
  } finally { await cleanup(); }
});

test('backfill is idempotent -- a second run changes nothing and does not duplicate rows', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, 'CVE-2026-1', RAW_WITH_CWES);
    await backfill(store, { dryRun: false });
    const second = await backfill(store, { dryRun: false });
    assert.strictEqual(second.changed, 0);
    const rows = await store.all('SELECT cwe_id FROM item_cwes WHERE item_id = $1', [id]);
    assert.strictEqual(rows.length, 1, 'cwe rows must not accumulate');
  } finally { await cleanup(); }
});

test('backfill --dry-run writes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seed(store, 'CVE-2026-1', RAW_WITH_CWES);
    const result = await backfill(store, { dryRun: true });
    assert.strictEqual(result.changed, 1, 'dry run still reports what it would change');
    assert.deepStrictEqual(await store.all('SELECT 1 FROM item_cwes WHERE item_id = $1', [id]), []);
  } finally { await cleanup(); }
});
