// server/schema.test.js
const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');

test('items has enrichment columns', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const cols = (await store.all("SELECT column_name FROM information_schema.columns WHERE table_name = 'items'")).map((c) => c.column_name);
    for (const c of ['severity', 'cvss_score', 'exploitation_status', 'vendor', 'region', 'industry', 'confidence', 'threat_type', 'canonical_id']) {
      assert.ok(cols.includes(c), `items.${c} exists`);
    }
  } finally { await cleanup(); }
});

test('child tables exist', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const tables = (await store.all("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).map((r) => r.tablename);
    for (const t of ['item_cves', 'item_iocs', 'item_actors', 'item_malware_families', 'item_domains']) {
      assert.ok(tables.includes(t), `${t} exists`);
    }
  } finally { await cleanup(); }
});

test('applySchema creates the derived and history tables', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const rows = await store.all(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' AND table_name = ANY($1)`,
      [['cve_intel', 'cve_sources', 'clusters', 'cluster_items', 'source_syncs']]);
    assert.strictEqual(rows.length, 5);
  } finally {
    await cleanup();
  }
});

test('applySchema adds items.epss_score to an existing table', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const col = await store.get(
      `SELECT data_type FROM information_schema.columns
        WHERE table_name='items' AND column_name='epss_score'`);
    assert.ok(col, 'items.epss_score is missing');
    assert.strictEqual(col.data_type, 'double precision');
  } finally {
    await cleanup();
  }
});

test('applySchema adds items.epss_score to a table that lacks it', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await store.run('ALTER TABLE items DROP COLUMN epss_score');
    const { applySchema } = require('./db');
    await applySchema(store);
    const col = await store.get(
      `SELECT data_type FROM information_schema.columns
        WHERE table_name='items' AND column_name='epss_score'`);
    assert.ok(col, 'ALTER path did not re-add the column');
    assert.strictEqual(col.data_type, 'double precision');
  } finally {
    await cleanup();
  }
});

test('applySchema is idempotent', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { applySchema } = require('./db');
    await applySchema(store);
    await applySchema(store);
  } finally {
    await cleanup();
  }
});
