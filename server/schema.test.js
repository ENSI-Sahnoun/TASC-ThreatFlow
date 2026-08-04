// server/schema.test.js
const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { applySchema } = require('./db');

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

// --- Impact indicator (Spec A) ---

test('profile_assets exists with an exposure check constraint', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      "INSERT INTO profiles (name, sector) VALUES ('t','finance') RETURNING id");
    await store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortios','internet')`, [p.id]);
    await assert.rejects(() => store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortiproxy','sometimes')`, [p.id]));
  } finally { await cleanup(); }
});

test('profile_assets cascades when its profile is deleted', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      "INSERT INTO profiles (name, sector) VALUES ('t','finance') RETURNING id");
    await store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortios','internet')`, [p.id]);
    await store.run('DELETE FROM profiles WHERE id = $1', [p.id]);
    assert.strictEqual((await store.all('SELECT * FROM profile_assets')).length, 0);
  } finally { await cleanup(); }
});

test('exposure defaults to unknown rather than assuming internal', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      "INSERT INTO profiles (name, sector) VALUES ('t','finance') RETURNING id");
    await store.run(
      "INSERT INTO profile_assets (profile_id, vendor, product) VALUES ($1,'fortinet','fortios')",
      [p.id]);
    const row = await store.get('SELECT exposure FROM profile_assets');
    assert.strictEqual(row.exposure, 'unknown');
  } finally { await cleanup(); }
});

test('items.cvss_vector and item_relevance.consequence exist', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const cols = await store.all(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE (table_name='items' AND column_name='cvss_vector')
           OR (table_name='item_relevance' AND column_name='consequence')`);
    assert.strictEqual(cols.length, 2);
  } finally { await cleanup(); }
});

test('applySchema seeds profile_assets from legacy products[] at unknown exposure', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
    const i = await store.get(
      "INSERT INTO items (source_id, external_id, title, category) VALUES ($1,'e1','t','cve') RETURNING id", [s.id]);
    await store.run(
      "INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')",
      [i.id]);
    await store.run(
      "INSERT INTO profiles (name, sector, products) VALUES ('legacy','finance','{fortios,ghost}')");

    await applySchema(store);   // idempotent re-apply performs the seed

    const rows = await store.all('SELECT vendor, product, exposure FROM profile_assets');
    // 'ghost' matches no item_cpes row and is skipped — storing it would store a value that
    // can never match anything.
    assert.deepStrictEqual(rows, [
      { vendor: 'fortinet', product: 'fortios', exposure: 'unknown' },
    ]);
  } finally { await cleanup(); }
});

test('a product slug under several vendors seeds one row per vendor', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
    const i = await store.get(
      "INSERT INTO items (source_id, external_id, title, category) VALUES ($1,'e1','t','cve') RETURNING id", [s.id]);
    for (const v of ['acme', 'globex']) {
      await store.run(
        "INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a',$2,'router_os')",
        [i.id, v]);
    }
    await store.run(
      "INSERT INTO profiles (name, sector, products) VALUES ('multi','finance','{router_os}')");

    await applySchema(store);

    const rows = await store.all('SELECT vendor FROM profile_assets ORDER BY vendor');
    assert.deepStrictEqual(rows.map((r) => r.vendor), ['acme', 'globex']);
  } finally { await cleanup(); }
});

test('the seed is idempotent and never resurrects a removed asset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
    const i = await store.get(
      "INSERT INTO items (source_id, external_id, title, category) VALUES ($1,'e1','t','cve') RETURNING id", [s.id]);
    await store.run(
      "INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')",
      [i.id]);
    const p = await store.get(
      "INSERT INTO profiles (name, sector, products) VALUES ('legacy','finance','{fortios}') RETURNING id");

    await applySchema(store);
    // A user deliberately removing an asset must not have it reinstated on the next boot.
    await store.run('UPDATE profiles SET products = $1 WHERE id = $2', [[], p.id]);
    await store.run('DELETE FROM profile_assets WHERE profile_id = $1', [p.id]);
    await applySchema(store);

    assert.deepStrictEqual(await store.all('SELECT * FROM profile_assets'), []);
  } finally { await cleanup(); }
});
