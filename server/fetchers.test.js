const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { syncSource, writeItem } = require('./fetchers');
const { enrichItem } = require('./enrich');

async function insertSource(store, s) {
  const row = await store.get(
    `INSERT INTO sources (name, category, conn_type, fetch_kind, url, tier, active, is_custom)
     VALUES ($1, $2, $3, $4, $5, $6, true, false) RETURNING id`,
    [s.name, s.category, s.kind, s.kind, s.url, 'test']
  );
  return row.id;
}

test('syncSource writes item + enrichment child rows', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await insertSource(store, { name: 'KEV Test', category: 'Vulnerability Intelligence', kind: 'kev', url: 'https://kev' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.requestBody = '10';
    source.kind = 'kev';
    const body = JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2024-9', vendorProject: 'Acme', shortDescription: 'bad', dateAdded: '2024-05-05' }] });
    const ctx = { request: async () => ({ status: 200, headers: {}, body }), now: () => new Date('2025-01-01T00:00:00Z') };
    const res = await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: { 'KEV Test': { domains: ['vulnerability', 'zero-day'] } } });
    assert.strictEqual(res.status, 'ok');
    assert.strictEqual(res.itemsFetched, 1);
    const item = await store.get('SELECT * FROM items WHERE source_id = $1', [id]);
    assert.strictEqual(item.exploitation_status, 'actively_exploited');
    assert.strictEqual(item.vendor, 'Acme');
    const cves = (await store.all('SELECT cve_id FROM item_cves WHERE item_id = $1', [item.id])).map((r) => r.cve_id);
    assert.deepStrictEqual(cves, ['CVE-2024-9']);
    const domains = (await store.all('SELECT domain FROM item_domains WHERE item_id = $1', [item.id])).map((r) => r.domain).sort();
    assert.ok(domains.includes('vulnerability') && domains.includes('zero-day'));
  } finally { await cleanup(); }
});

test('syncSource enriches IP IOCs via Shodan, using the DB-stored key over env', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await store.run(
      `INSERT INTO sources (name, category, conn_type, fetch_kind, url, tier, active, is_custom, api_key)
       VALUES ($1, $2, $3, $4, $5, $6, false, false, $7)`,
      ['Shodan (IP enrichment)', 'Threat Intelligence', 'unsupported', 'unsupported', 'https://internetdb.shodan.io', 'optional-key', 'db-key']
    );
    const id = await insertSource(store, { name: 'URLhaus Test', category: 'Malware / C2', kind: 'abuse_ch', url: 'https://urlhaus' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.kind = 'abuse_ch';
    source.enrichHints = { iocField: 'url', iocType: 'ip', familyField: 'tags' };
    const body = JSON.stringify({ '1': [{ url: '203.0.113.5', tags: ['cobaltstrike'], first_seen: '2025-01-01' }] });
    let hostKeyUsed = null;
    const request = async (url) => {
      if (url.includes('urlhaus')) return { status: 200, headers: {}, body };
      if (url.includes('internetdb.shodan.io')) return { status: 200, headers: {}, body: JSON.stringify({ ports: [8080], vulns: [], tags: [], cpes: [], hostnames: [] }) };
      if (url.includes('api.shodan.io/shodan/host/')) {
        hostKeyUsed = new URL(url).searchParams.get('key');
        return { status: 200, headers: {}, body: JSON.stringify({ org: 'Test Org', isp: 'Test ISP', city: 'Nowhere', country_code: 'US' }) };
      }
      return { status: 404, headers: {}, body: '' };
    };
    const res = await syncSource(source, { store, request, now: () => new Date('2025-01-01T00:00:00Z'), kevCveSet: new Set(), configByName: {} });
    assert.strictEqual(res.status, 'ok');
    assert.strictEqual(hostKeyUsed, 'db-key');
    const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', ['203.0.113.5']);
    assert.strictEqual(row.org, 'Test Org');
  } finally { await cleanup(); }
});

test('syncSource records adapter errors as status', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await insertSource(store, { name: 'Bad', category: 'x', kind: 'kev', url: 'https://kev' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.kind = 'kev';
    const ctx = { request: async () => ({ status: 500, headers: {}, body: '' }), now: () => new Date() };
    const res = await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: {} });
    assert.match(res.status, /error:/);
  } finally { await cleanup(); }
});

test('syncSource records a source_syncs row on success and on error', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, category, fetch_kind, url, active) VALUES ('S','OSINT','rss','https://x.test/f',true) RETURNING id");

    const ok = { id: src.id, name: 'S', fetch_kind: 'rss', url: 'https://x.test/f' };
    await syncSource(ok, {
      store,
      request: async () => ({ status: 200, headers: {}, body: '<rss version="2.0"><channel><item><title>A</title><guid>g1</guid></item></channel></rss>' }),
    });

    await syncSource({ ...ok }, { store, request: async () => { throw new Error('boom'); } });

    const rows = await store.all('SELECT status, items_total, error FROM source_syncs ORDER BY id');
    assert.strictEqual(rows.length, 2);
    assert.strictEqual(rows[0].status, 'ok');
    assert.strictEqual(rows[1].status.startsWith('error'), true);
    assert.match(rows[1].error, /boom/);
  } finally {
    await cleanup();
  }
});

test('syncSource counts items_new only for genuinely new rows, not re-synced ones', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await insertSource(store, { name: 'KEV Repeat Test', category: 'Vulnerability Intelligence', kind: 'kev', url: 'https://kev' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.kind = 'kev';
    const body = JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2024-9', vendorProject: 'Acme', shortDescription: 'bad', dateAdded: '2024-05-05' }] });
    const ctx = { request: async () => ({ status: 200, headers: {}, body }), now: () => new Date('2025-01-01T00:00:00Z') };

    // Same external_id (the CVE) both times, so the second sync upserts the existing row
    // instead of inserting a new one.
    await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: {} });
    await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: {} });

    const rows = await store.all('SELECT items_new, items_total FROM source_syncs WHERE source_id = $1 ORDER BY id', [id]);
    assert.strictEqual(rows.length, 2);
    assert.strictEqual(rows[0].items_new, 1);
    assert.strictEqual(rows[0].items_total, 1);
    assert.strictEqual(rows[1].items_new, 0);
    assert.strictEqual(rows[1].items_total, 1);
  } finally { await cleanup(); }
});

test('syncSource persists epss_score onto the item row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await insertSource(store, { name: 'EPSS Test', category: 'Vulnerability Intelligence', kind: 'epss', url: 'https://epss' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.kind = 'epss';
    const body = JSON.stringify({ data: [{ cve: 'CVE-2024-77', epss: '0.7', date: '2024-01-01' }] });
    const ctx = { request: async () => ({ status: 200, headers: {}, body }), now: () => new Date('2025-01-01T00:00:00Z') };

    const res = await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: {} });
    assert.strictEqual(res.status, 'ok');

    const item = await store.get('SELECT epss_score FROM items WHERE source_id = $1', [id]);
    assert.strictEqual(item.epss_score, 0.7);
  } finally { await cleanup(); }
});

// Regression: the upsert used to omit `category` from its ON CONFLICT DO UPDATE SET clause,
// so a real re-sync (which always hits the ON CONFLICT branch for previously-seen external_ids)
// never corrected a stale category — a row categorized 'other' before the taxonomy fix in
// normalize.js stayed 'other' forever, even though every other field refreshed normally.
test('syncSource corrects a stale category on an existing row when re-synced', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await insertSource(store, { name: 'Breach Test', category: 'Data Breaches', kind: 'json_api', url: 'https://breaches' });
    const source = await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    source.kind = 'json_api';
    source.mapping = { title: 'Name', summary: 'Description', link: 'Domain', date: 'BreachDate', id: 'Name' };
    await store.run(
      "INSERT INTO items (source_id, category, title, external_id) VALUES ($1, 'other', 'Stale Co', 'Stale Co')",
      [id]
    );

    const body = JSON.stringify([{ Name: 'Stale Co', Description: 'desc', Domain: 'stale.test', BreachDate: '2024-01-01' }]);
    const ctx = { request: async () => ({ status: 200, headers: {}, body }), now: () => new Date('2025-01-01T00:00:00Z') };
    const res = await syncSource(source, { store, request: ctx.request, now: ctx.now, kevCveSet: new Set(), configByName: {} });
    assert.strictEqual(res.status, 'ok');

    const item = await store.get('SELECT category FROM items WHERE source_id = $1', [id]);
    assert.strictEqual(item.category, 'data-breach');
  } finally { await cleanup(); }
});

test('writeItem persists item_cpes and re-writing replaces them', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('cpe-src','json_api',true) RETURNING id");
    const item = { external_id: 'CVE-2026-1', category: 'cve', title: 'CVE-2026-1', raw: null, native: {} };
    const enr = {
      cves: [], iocs: [], actors: [], families: [], domains: [],
      severity: null, cvssScore: null, cvssVersion: null, epssScore: null,
      exploitationStatus: null, vendor: null, region: null, industry: null, threatType: null,
      cpes: [{ part: 'a', vendor: 'fortinet', product: 'fortios' }],
    };
    await store.tx(async (t) => { await writeItem(t, src.id, item, enr); });
    let rows = await store.all('SELECT part, vendor, product FROM item_cpes ORDER BY product');
    assert.deepStrictEqual(rows, [{ part: 'a', vendor: 'fortinet', product: 'fortios' }]);

    // A later sync of the same external_id must replace, not accumulate.
    enr.cpes = [{ part: 'o', vendor: 'ibm', product: 'aix' }];
    await store.tx(async (t) => { await writeItem(t, src.id, item, enr); });
    rows = await store.all('SELECT part, vendor, product FROM item_cpes ORDER BY product');
    assert.deepStrictEqual(rows, [{ part: 'o', vendor: 'ibm', product: 'aix' }]);
  } finally { await cleanup(); }
});

test('enrichItem passes native.cpes through', () => {
  const enr = enrichItem({
    category: 'cve', title: 'x', summary: '',
    native: { cpes: [{ part: 'a', vendor: 'fortinet', product: 'fortios' }] },
  });
  assert.deepStrictEqual(enr.cpes, [{ part: 'a', vendor: 'fortinet', product: 'fortios' }]);
});

test('enrichItem defaults cpes to an empty array', () => {
  const enr = enrichItem({ category: 'news', title: 'x', summary: '', native: {} });
  assert.deepStrictEqual(enr.cpes, []);
});
