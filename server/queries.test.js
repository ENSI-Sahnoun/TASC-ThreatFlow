const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { sourceStats, listCves, cveDetail, entityProfile, feed, search, iocRows } = require('./queries');
const { consolidate } = require('./consolidate');

async function withTestStore(fn) {
  const { store, cleanup } = await makeTempDb();
  try { await fn(store); } finally { await cleanup(); }
}

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, category, fetch_kind, active, last_status) VALUES ('NVD CVE API','Vulnerability Intelligence','nvd_cve',true,'ok') RETURNING id");
  const item = await store.get(
    `INSERT INTO items (source_id, category, title, summary, link, severity, cvss_score, published_at)
     VALUES ($1,'cve','CVE-2024-3400','A long authoritative description of the flaw in question.','https://x.test/a','critical',9.8, now())
     RETURNING id`, [src.id]);
  await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [item.id, 'CVE-2024-3400']);
  await store.run('INSERT INTO item_actors (item_id, actor) VALUES ($1,$2)', [item.id, 'Lazarus']);
  await store.run('INSERT INTO item_malware_families (item_id, family) VALUES ($1,$2)', [item.id, 'Cobalt Strike']);
  await store.run('INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1,$2,$3)', [item.id, 'ip', '1.2.3.4']);
  await store.run("INSERT INTO source_syncs (source_id, status, items_new, items_total) VALUES ($1,'ok',1,1)", [src.id]);
  await consolidate(store);
  return { src, item };
}

test('sourceStats returns the dossier payload including field coverage', async () => {
  await withTestStore(async (store) => {
    const { src } = await seed(store);
    const s = await sourceStats(store, src.id);
    assert.strictEqual(s.source.name, 'NVD CVE API');
    assert.strictEqual(s.counts.items, 1);
    assert.strictEqual(s.counts.cves, 1);
    assert.strictEqual(s.counts.iocs, 1);
    assert.strictEqual(s.fieldCoverage.summary, 100);
    assert.strictEqual(s.fieldCoverage.region, 0);
    assert.strictEqual(s.syncHistory.length, 1);
    assert.strictEqual(await sourceStats(store, 999999), null);
  });
});

test('listCves filters and paginates', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const all = await listCves(store, { limit: 10, offset: 0 });
    assert.strictEqual(all.total, 1);
    assert.strictEqual(all.rows[0].cve_id, 'CVE-2024-3400');
    const filtered = await listCves(store, { minCvss: 10, limit: 10, offset: 0 });
    assert.strictEqual(filtered.total, 0);
    const bySeverity = await listCves(store, { severity: 'critical', limit: 10, offset: 0 });
    assert.strictEqual(bySeverity.total, 1);
  });
});

test('listCves treats malformed/empty numeric filters and pagination as absent, not NaN', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    // Empty string min_cvss (an unfilled frontend input) must not silently exclude every row.
    const emptyMin = await listCves(store, { minCvss: '', limit: 10, offset: 0 });
    assert.strictEqual(emptyMin.total, 1);
    // A non-numeric value must not throw or reach SQL as NaN.
    const garbage = await listCves(store, { minCvss: 'abc', minEpss: 'nope', limit: 10, offset: 0 });
    assert.strictEqual(garbage.total, 1);
    // Negative limit/offset must clamp rather than error at Postgres.
    const negative = await listCves(store, { limit: -5, offset: -5 });
    assert.strictEqual(negative.rows.length, 1);
  });
});

test('cveDetail returns per-source evidence', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const d = await cveDetail(store, 'CVE-2024-3400');
    assert.strictEqual(d.cve.cvss_score, 9.8);
    assert.strictEqual(d.sources.length, 1);
    assert.strictEqual(d.sources[0].source_name, 'NVD CVE API');
    assert.strictEqual(await cveDetail(store, 'CVE-0000-0000'), null);
  });
});

test('entityProfile works for actors and families, null for unknown', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const actor = await entityProfile(store, 'actor', 'Lazarus');
    assert.strictEqual(actor.name, 'Lazarus');
    assert.strictEqual(actor.itemCount, 1);
    assert.deepStrictEqual(actor.cves, ['CVE-2024-3400']);
    // The seed's one item links both 'Lazarus' and 'Cobalt Strike' — related must cross the
    // item_actors/item_malware_families join, not just echo the entity's own name back.
    assert.deepStrictEqual(actor.related, ['Cobalt Strike']);
    // sources must carry last_status directly (not derived from the truncated `items` list),
    // since `items` is capped at 100 and can omit a source's most-recent item entirely.
    assert.strictEqual(actor.sources.length, 1);
    assert.strictEqual(actor.sources[0].name, 'NVD CVE API');
    assert.strictEqual(actor.sources[0].last_status, 'ok');
    const fam = await entityProfile(store, 'family', 'Cobalt Strike');
    assert.strictEqual(fam.itemCount, 1);
    assert.deepStrictEqual(fam.related, ['Lazarus']);
    assert.strictEqual(await entityProfile(store, 'actor', 'Nobody'), null);
    assert.strictEqual(await entityProfile(store, 'bogus', 'Lazarus'), null);
  });
});

test('feed returns clustered rows and search finds across types', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const rows = await feed(store, { limit: 10 });
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].source_count, 1);

    const r = await search(store, 'Lazarus', 5);
    assert.strictEqual(r.actors.length, 1);

    const iocs = await iocRows(store, {});
    assert.deepStrictEqual(iocs.map((i) => i.value), ['1.2.3.4']);
  });
});

test('feed excludes raw malware/ioc dumps — narrative categories only', async () => {
  await withTestStore(async (store) => {
    const { src } = await seed(store);
    const iocItem = await store.get(
      `INSERT INTO items (source_id, category, title, published_at) VALUES ($1,'ioc','Attacking IP: 1.2.3.4', now()) RETURNING id`,
      [src.id]);
    await consolidate(store);
    const rows = await feed(store, { limit: 10 });
    assert.ok(rows.every((r) => r.category !== 'ioc'));
    assert.ok(!rows.some((r) => r.item_id === iocItem.id));
  });
});

test('iocRows severity=unknown matches NULL rows, not just the literal string', async () => {
  await withTestStore(async (store) => {
    const { src } = await seed(store);   // one 'critical' item with IOC 1.2.3.4
    const unscored = await store.get(
      `INSERT INTO items (source_id, category, title, severity) VALUES ($1,'cve','no severity set',NULL) RETURNING id`,
      [src.id]);
    await store.run('INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1,$2,$3)', [unscored.id, 'ip', '5.6.7.8']);

    const iocs = await iocRows(store, { severity: 'unknown' });
    assert.deepStrictEqual(iocs.map((i) => i.value), ['5.6.7.8']);
  });
});

test('feed/search/iocRows treat malformed limit and source_id as absent, not a DB error', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const rows = await feed(store, { limit: -5, since: 'not-a-date' });
    assert.strictEqual(rows.length, 1);
    const r = await search(store, 'Lazarus', -5);
    assert.strictEqual(r.actors.length, 1);
    const iocs = await iocRows(store, { source_id: 'abc' });
    assert.deepStrictEqual(iocs.map((i) => i.value), ['1.2.3.4']);
  });
});

const { DEFAULT_MAX_AGE_DAYS, maxAgeClause } = require('./queries');

test('DEFAULT_MAX_AGE_DAYS is one year', () => {
  assert.strictEqual(DEFAULT_MAX_AGE_DAYS, 365);
});

test('maxAgeClause tolerates NULL published_at so undated rows survive', () => {
  const params = [];
  const ph = (v) => { params.push(v); return `$${params.length}`; };
  const sql = maxAgeClause(365, ph);
  assert.match(sql, /items\.published_at IS NULL/);
  assert.deepStrictEqual(params, [365]);
});

test('maxAgeClause returns null for 0 and for malformed input', () => {
  const ph = () => '$1';
  for (const v of [0, '0', -5, 'abc', NaN]) assert.strictEqual(maxAgeClause(v, ph), null);
});

test('maxAgeClause defaults a missing value to DEFAULT_MAX_AGE_DAYS', () => {
  const params = [];
  const ph = (v) => { params.push(v); return `$${params.length}`; };
  assert.ok(maxAgeClause(undefined, ph));
  assert.deepStrictEqual(params, [365]);
});

const { cpeFacets } = require('./queries');

async function seedCpes(store, rows) {
  const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('S','json_api') RETURNING id");
  for (const [i, r] of rows.entries()) {
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'cve',$2,$2, now()) RETURNING id`, [s.id, `CVE-2026-${i}`]);
    await store.run('INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,$2,$3,$4)',
      [item.id, r.part || 'a', r.vendor, r.product]);
  }
}

test('cpeFacets ranks vendors by reference count', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpes(store, [
      { vendor: 'microsoft', product: 'windows' },
      { vendor: 'microsoft', product: 'office' },
      { vendor: 'fortinet', product: 'fortios' },
    ]);
    assert.deepStrictEqual(await cpeFacets(store, { kind: 'vendor' }),
      [{ value: 'microsoft', refs: 2 }, { value: 'fortinet', refs: 1 }]);
  } finally { await cleanup(); }
});

test('cpeFacets filters case-insensitively by substring', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpes(store, [
      { vendor: 'microsoft', product: 'windows' },
      { vendor: 'fortinet', product: 'fortios' },
    ]);
    assert.deepStrictEqual(await cpeFacets(store, { kind: 'vendor', q: 'FORT' }),
      [{ value: 'fortinet', refs: 1 }]);
  } finally { await cleanup(); }
});

test('cpeFacets returns products when asked', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpes(store, [{ vendor: 'fortinet', product: 'fortios' }]);
    assert.deepStrictEqual(await cpeFacets(store, { kind: 'product' }), [{ value: 'fortios', refs: 1 }]);
  } finally { await cleanup(); }
});

// kind selects a column name, so it must never reach SQL uninspected.
test('cpeFacets defaults an unknown kind to vendor', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpes(store, [{ vendor: 'fortinet', product: 'fortios' }]);
    assert.deepStrictEqual(await cpeFacets(store, { kind: 'vendor; DROP TABLE items' }),
      [{ value: 'fortinet', refs: 1 }]);
    assert.strictEqual((await store.all('SELECT 1 FROM items')).length, 1, 'items table survived');
  } finally { await cleanup(); }
});

test('cpeFacets clamps limit', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpes(store, [
      { vendor: 'a1', product: 'p' }, { vendor: 'b2', product: 'p' }, { vendor: 'c3', product: 'p' },
    ]);
    assert.strictEqual((await cpeFacets(store, { kind: 'vendor', limit: 2 })).length, 2);
    assert.ok((await cpeFacets(store, { kind: 'vendor', limit: 99999 })).length <= 3);
  } finally { await cleanup(); }
});
