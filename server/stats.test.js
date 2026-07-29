const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { dashboardStats } = require('./stats');

// test-helpers exports makeTempDb (creates an isolated DB + schema, returns { store, cleanup }).
// Wrap it as withTestStore so the test body just gets a clean, isolated store and the DB is
// always dropped afterwards.
async function withTestStore(fn) {
  const { store, cleanup } = await makeTempDb();
  try {
    await fn(store);
  } finally {
    await cleanup();
  }
}

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S1','rss',true) RETURNING id");
  const mkItem = (cat, extra = {}) => store.get(
    `INSERT INTO items (source_id, category, title, severity, cvss_score, exploitation_status, region, published_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7, now()) RETURNING id`,
    [src.id, cat, extra.title || cat, extra.severity ?? null, extra.cvss ?? null,
     extra.exploit ?? null, extra.region ?? null]);
  // A news article mentioning the CVE, inserted first so it gets the lowest id - the
  // drill-down must still prefer the canonical 'cve' record inserted after it.
  const mention = await mkItem('news', { title: 'Exploit chatter for CVE-2025-0001' });
  const cve = await mkItem('cve', { title: 'CVE-2025-0001', severity: 'critical', cvss: 9.8 });
  await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [cve.id, 'CVE-2025-0001']);
  await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [mention.id, 'CVE-2025-0001']);
  const rw = await mkItem('ransomware', { severity: 'unknown', region: 'US' });
  await store.run('INSERT INTO item_actors (item_id, actor) VALUES ($1,$2)', [rw.id, 'thegentlemen']);
  const mw = await mkItem('malware', { region: 'GB' });
  await store.run('INSERT INTO item_malware_families (item_id, family) VALUES ($1,$2)', [mw.id, 'Cobalt Strike']);
  await store.run('INSERT INTO item_domains (item_id, domain) VALUES ($1,$2)', [cve.id, 'vulnerability']);
  return { cve, mention };
}

test('dashboardStats aggregates and cleans data', async () => {
  await withTestStore(async (store) => {
    const { cve } = await seed(store);
    const s = await dashboardStats(store);
    assert.strictEqual(s.total, 4);
    assert.deepStrictEqual(s.topMalware.map((m) => m.family), ['Cobalt Strike']);
    const sev = Object.fromEntries(s.bySeverity.map((r) => [r.severity, r.count]));
    assert.strictEqual(sev.critical, 1);
    // every severity value present must be canonical — nothing to coerce at read time
    const { SEVERITIES } = require('./cvss');
    for (const row of s.bySeverity) assert.ok(SEVERITIES.includes(row.severity), `non-canonical: ${row.severity}`);
    // actors
    assert.deepStrictEqual(s.topActors, [{ actor: 'thegentlemen', count: 1 }]);
    // top cve drill-down prefers the canonical 'cve' record over the lower-id news mention
    assert.strictEqual(s.topCves[0].cve, 'CVE-2025-0001');
    assert.strictEqual(s.topCves[0].itemId, cve.id);
    // countries from region
    const codes = s.targetedCountries.map((c) => c.code).sort();
    assert.deepStrictEqual(codes, ['GB', 'US']);
    // domain label joined
    assert.strictEqual(s.byDomain[0].label, 'Vulnerability Intelligence');
  });
});

test('dashboardStats filters malware-family noise (arch strings, raw IPs) from topMalware', async () => {
  await withTestStore(async (store) => {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','rss',true) RETURNING id");
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, published_at) VALUES ($1,'malware','noisy', now()) RETURNING id`,
      [src.id]);
    for (const family of ['Cobalt Strike', 'elf', 'mips', 'arm', '32-bit', '62-60-159-184']) {
      await store.run('INSERT INTO item_malware_families (item_id, family) VALUES ($1,$2)', [item.id, family]);
    }
    const s = await dashboardStats(store);
    assert.deepStrictEqual(s.topMalware.map((m) => m.family), ['Cobalt Strike']);
  });
});

test('dashboardStats exposes KPI tiles with deltas and source health', async () => {
  await withTestStore(async (store) => {
    await seed(store);
    const s = await dashboardStats(store);

    for (const key of ['activelyExploited', 'newIocs24h', 'criticalAdvisories7d', 'sourcesHealthy']) {
      const kpi = s.kpis[key];
      assert.ok(kpi, `missing kpi ${key}`);
      assert.strictEqual(typeof kpi.value, 'number');
      assert.strictEqual(typeof kpi.delta, 'number');
      assert.ok(Array.isArray(kpi.series));
    }

    assert.strictEqual(typeof s.sourceHealth.total, 'number');
    assert.strictEqual(s.sourceHealth.ok + s.sourceHealth.error + s.sourceHealth.unsupported + s.sourceHealth.neverSynced, s.sourceHealth.total);
  });
});
