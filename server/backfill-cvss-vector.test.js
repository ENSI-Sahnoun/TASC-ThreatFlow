const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfill, vectorFromRaw } = require('./backfill-cvss-vector');

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V30 = 'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L';

test('vectorFromRaw prefers v3.1 over v3.0', () => {
  const raw = {
    metrics: {
      cvssMetricV30: [{ cvssData: { vectorString: V30 } }],
      cvssMetricV31: [{ cvssData: { vectorString: V31 } }],
    },
  };
  assert.strictEqual(vectorFromRaw(raw), V31);
});

test('vectorFromRaw falls back to v3.0 when there is no v3.1', () => {
  assert.strictEqual(
    vectorFromRaw({ metrics: { cvssMetricV30: [{ cvssData: { vectorString: V30 } }] } }), V30);
});

// v2 carries no PR/UI/S metrics, so consequence.js cannot read it. Recognising it here would
// store a value the consumer has to special-case.
test('vectorFromRaw ignores v2-only records', () => {
  assert.strictEqual(
    vectorFromRaw({ metrics: { cvssMetricV2: [{ cvssData: { vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' } }] } }),
    null);
});

test('vectorFromRaw returns null for a malformed vector', () => {
  assert.strictEqual(
    vectorFromRaw({ metrics: { cvssMetricV31: [{ cvssData: { vectorString: 'nonsense' } }] } }), null);
});

test('vectorFromRaw tolerates missing or non-object input', () => {
  assert.strictEqual(vectorFromRaw(null), null);
  assert.strictEqual(vectorFromRaw({}), null);
  assert.strictEqual(vectorFromRaw({ metrics: { cvssMetricV31: 'not-an-array' } }), null);
});

async function seed(store, raw = { metrics: { cvssMetricV31: [{ cvssData: { vectorString: V31 } }] } }) {
  const s = await store.get(
    "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
  return store.get(
    `INSERT INTO items (source_id, external_id, title, category, raw_json)
     VALUES ($1,'e1','t','cve',$2) RETURNING id`,
    [s.id, JSON.stringify(raw)]);
}

test('backfill --dry-run reports the change but writes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const r = await backfill(store, { dryRun: true });
    assert.strictEqual(r.changed, 1);
    assert.strictEqual((await store.get('SELECT cvss_vector FROM items LIMIT 1')).cvss_vector, null);
  } finally { await cleanup(); }
});

test('backfill writes the vector and a second run is a no-op', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    assert.strictEqual((await backfill(store)).changed, 1);
    assert.strictEqual((await store.get('SELECT cvss_vector FROM items LIMIT 1')).cvss_vector, V31);
    assert.strictEqual((await backfill(store)).changed, 0);
  } finally { await cleanup(); }
});

test('an item with no readable vector is skipped, not blanked', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store, { metrics: {} });
    const r = await backfill(store);
    assert.strictEqual(r.changed, 0);
    assert.strictEqual(r.skipped, 1);
  } finally { await cleanup(); }
});

test('unparseable raw_json is skipped rather than throwing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, external_id, title, category, raw_json)
       VALUES ($1,'e1','t','cve','{not json')`, [s.id]);
    const r = await backfill(store);
    assert.strictEqual(r.skipped, 1);
    assert.strictEqual(r.changed, 0);
  } finally { await cleanup(); }
});

// The corpus is larger than one batch, so paging has to actually advance.
test('backfill pages through more rows than one batch', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
    const raw = JSON.stringify({ metrics: { cvssMetricV31: [{ cvssData: { vectorString: V31 } }] } });
    for (let i = 0; i < 7; i += 1) {
      await store.run(
        `INSERT INTO items (source_id, external_id, title, category, raw_json)
         VALUES ($1,$2,'t','cve',$3)`, [s.id, `e${i}`, raw]);
    }
    const r = await backfill(store, { batchSize: 2 });
    assert.strictEqual(r.scanned, 7);
    assert.strictEqual(r.changed, 7);
  } finally { await cleanup(); }
});
