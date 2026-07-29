const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { consolidate, rebuildCveIntel } = require('./consolidate');

async function withTestStore(fn) {
  const { store, cleanup } = await makeTempDb();
  try { await fn(store); } finally { await cleanup(); }
}

async function mkSource(store, name, category) {
  return store.get("INSERT INTO sources (name, category, fetch_kind, active) VALUES ($1,$2,'rss',true) RETURNING id", [name, category]);
}
async function mkItem(store, sourceId, o = {}) {
  return store.get(
    `INSERT INTO items (source_id, category, title, summary, severity, cvss_score, epss_score, exploitation_status, published_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
    [sourceId, o.category || 'cve', o.title || 't', o.summary || null, o.severity || null,
     o.cvss ?? null, o.epss ?? null, o.exploit || null, o.published_at || '2026-07-20T10:00:00Z']);
}

test('rebuildCveIntel consolidates one CVE across four sources with NVD winning', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const rh = await mkSource(store, 'Red Hat Security Data', 'Vendor Advisory');
    const kev = await mkSource(store, 'CISA Known Exploited Vulnerabilities', 'Vulnerability Intelligence');
    const epss = await mkSource(store, 'FIRST EPSS', 'Vulnerability Intelligence');

    const a = await mkItem(store, nvd.id, { cvss: 9.8, summary: 'A long authoritative NVD description of the flaw.' });
    const b = await mkItem(store, rh.id, { cvss: 7.5, summary: 'short' });
    const c = await mkItem(store, kev.id, { exploit: 'actively_exploited', published_at: '2026-07-21T10:00:00Z' });
    const d = await mkItem(store, epss.id, { epss: 0.97 });
    for (const id of [a.id, b.id, c.id, d.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2024-3400']);
    }

    const written = await rebuildCveIntel(store);
    assert.strictEqual(written, 1);

    const row = await store.get('SELECT * FROM cve_intel WHERE cve_id=$1', ['CVE-2024-3400']);
    assert.strictEqual(row.cvss_score, 9.8);          // NVD beats Red Hat
    assert.strictEqual(row.cvss_source, 'NVD CVE API');
    assert.strictEqual(row.severity, 'critical');
    assert.strictEqual(row.kev_listed, true);
    assert.strictEqual(row.epss_score, 0.97);         // read from items.epss_score, not cvss_score
    assert.strictEqual(row.source_count, 4);
    assert.match(row.description, /authoritative NVD/);

    // per-source disagreement is retained, not averaged away
    const evidence = await store.all('SELECT cvss_score FROM cve_sources WHERE cve_id=$1 ORDER BY cvss_score DESC NULLS LAST', ['CVE-2024-3400']);
    assert.deepStrictEqual(evidence.map((e) => e.cvss_score), [9.8, 7.5, null, null]);
  });
});

test('rebuildCveIntel backfills severity onto item rows that never carried their own', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const kev = await mkSource(store, 'CISA Known Exploited Vulnerabilities', 'Vulnerability Intelligence');

    const scored = await mkItem(store, nvd.id, { cvss: 9.8 });
    // KEV never carries a native CVSS/severity of its own — this is the row that stays
    // severity IS NULL forever without the backfill.
    const unscored = await mkItem(store, kev.id, { exploit: 'actively_exploited' });
    // Already has its own (wrong-looking but legitimate) value — must not be overwritten.
    const preset = await mkItem(store, kev.id, { severity: 'low' });
    for (const id of [scored.id, unscored.id, preset.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2024-9999']);
    }

    await rebuildCveIntel(store);

    const rows = await store.all('SELECT id, severity FROM items ORDER BY id');
    const byId = Object.fromEntries(rows.map((r) => [r.id, r.severity]));
    assert.strictEqual(byId[scored.id], 'critical');
    assert.strictEqual(byId[unscored.id], 'critical');   // backfilled from the consolidated CVE
    assert.strictEqual(byId[preset.id], 'low');          // pre-existing value untouched
  });
});

test('rebuildCveIntel kev_added_at reflects the CISA KEV item, not any exploited item', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const kev = await mkSource(store, 'CISA Known Exploited Vulnerabilities', 'Vulnerability Intelligence');

    // enrich.js sets exploitation_status = 'actively_exploited' on ANY item whose extracted
    // CVE is in the KEV set at ingest time — not only the actual CISA KEV item. An older,
    // unrelated NVD record can carry the same flag; kev_added_at must still come from the
    // real CISA row, not whichever exploited row Postgres returns first.
    const a = await mkItem(store, nvd.id, { cvss: 8.8, exploit: 'actively_exploited', published_at: '2020-01-01T00:00:00Z' });
    const b = await mkItem(store, kev.id, { published_at: '2026-06-15T00:00:00Z' });
    for (const id of [a.id, b.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2025-9001']);
    }

    await rebuildCveIntel(store);
    const row = await store.get('SELECT * FROM cve_intel WHERE cve_id=$1', ['CVE-2025-9001']);
    assert.strictEqual(row.kev_listed, true);
    assert.strictEqual(row.kev_added_at.toISOString(), '2026-06-15T00:00:00.000Z');
  });
});

test('rebuildCveIntel picks description by source authority, not raw summary length', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const news = await mkSource(store, 'The Hacker News', 'Cybersecurity News'); // unranked source

    const nvdSummary = 'A concise but authoritative NVD technical description of this flaw.';
    const newsSummary = 'A much longer and more verbose write-up from an unranked news outlet '
      + 'that goes on at considerable length about the same vulnerability without any '
      + 'particular technical authority behind it.';
    assert.ok(nvdSummary.length >= 40 && newsSummary.length > nvdSummary.length);

    const a = await mkItem(store, nvd.id, { cvss: 7.2, summary: nvdSummary });
    const b = await mkItem(store, news.id, { summary: newsSummary });
    for (const id of [a.id, b.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2025-9002']);
    }

    await rebuildCveIntel(store);
    const row = await store.get('SELECT description FROM cve_intel WHERE cve_id=$1', ['CVE-2025-9002']);
    assert.strictEqual(row.description, nvdSummary);
  });
});

test('rebuildCveIntel is idempotent — values and evidence rows are stable across reruns', async () => {
  await withTestStore(async (store) => {
    const nvd = await mkSource(store, 'NVD CVE API', 'Vulnerability Intelligence');
    const rh = await mkSource(store, 'Red Hat Security Data', 'Vendor Advisory');
    const a = await mkItem(store, nvd.id, { cvss: 8.1, summary: 'An authoritative NVD description of this particular flaw in detail.' });
    const b = await mkItem(store, rh.id, { cvss: 6.5, summary: 'short' });
    for (const id of [a.id, b.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2026-1']);
    }

    await rebuildCveIntel(store);
    const first = await store.get('SELECT * FROM cve_intel WHERE cve_id=$1', ['CVE-2026-1']);
    const firstSources = await store.all('SELECT * FROM cve_sources WHERE cve_id=$1 ORDER BY item_id', ['CVE-2026-1']);

    await rebuildCveIntel(store);
    const rows = await store.all('SELECT cve_id FROM cve_intel');
    assert.strictEqual(rows.length, 1);

    const second = await store.get('SELECT * FROM cve_intel WHERE cve_id=$1', ['CVE-2026-1']);
    const secondSources = await store.all('SELECT * FROM cve_sources WHERE cve_id=$1 ORDER BY item_id', ['CVE-2026-1']);

    for (const key of ['cvss_score', 'cvss_source', 'severity', 'description', 'kev_listed', 'kev_added_at', 'source_count']) {
      assert.deepStrictEqual(second[key], first[key], `${key} changed across reruns`);
    }
    assert.strictEqual(secondSources.length, firstSources.length);
  });
});

test('consolidate clusters duplicate coverage and raises corroborated confidence', async () => {
  await withTestStore(async (store) => {
    const s1 = await mkSource(store, 'The Hacker News', 'Cybersecurity News');
    const s2 = await mkSource(store, 'BleepingComputer', 'Cybersecurity News');
    const a = await mkItem(store, s1.id, { category: 'news', title: 'Siemens ROX II zero-day chain' });
    const b = await mkItem(store, s2.id, { category: 'news', title: 'Siemens ROX II chain exploited' });
    for (const id of [a.id, b.id]) {
      await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [id, 'CVE-2026-3143']);
    }

    const res = await consolidate(store);
    assert.strictEqual(res.clusters, 1);

    const members = await store.all('SELECT item_id FROM cluster_items');
    assert.strictEqual(members.length, 2);

    // news tier 0.60, corroborated by a second source → 0.65
    const conf = await store.all('SELECT confidence FROM items ORDER BY id');
    assert.deepStrictEqual(conf.map((c) => c.confidence), [0.65, 0.65]);
  });
});

test('pruneSyncHistory removes rows older than the retention window', async () => {
  await withTestStore(async (store) => {
    const s = await mkSource(store, 'S', 'OSINT');
    await store.run("INSERT INTO source_syncs (source_id, started_at, status) VALUES ($1, now() - interval '100 days', 'ok')", [s.id]);
    await store.run("INSERT INTO source_syncs (source_id, started_at, status) VALUES ($1, now(), 'ok')", [s.id]);
    const { pruneSyncHistory } = require('./consolidate');
    const deleted = await pruneSyncHistory(store, 90);
    assert.strictEqual(deleted, 1);
    const left = await store.all('SELECT id FROM source_syncs');
    assert.strictEqual(left.length, 1);
  });
});
