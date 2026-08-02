const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { createApp } = require('./index');

async function seedItem(store, overrides = {}) {
  const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
  const item = await store.get(
    `INSERT INTO items (source_id, category, title, exploitation_status, vendor) VALUES ($1, 'cve', $2, $3, $4) RETURNING id`,
    [sid, overrides.title || 'CVE-2024-1', overrides.exploitation || null, overrides.vendor || null]
  );
  const id = item.id;
  if (overrides.domain) await store.run('INSERT INTO item_domains (item_id, domain) VALUES ($1, $2)', [id, overrides.domain]);
  if (overrides.cve) await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1, $2)', [id, overrides.cve]);
  return id;
}

async function get(app, path) {
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}${path}`);
    const headers = Object.fromEntries(res.headers.entries());
    let body = null;
    try {
      body = await res.json();
    } catch {
      // Not JSON (e.g., 404 without a route handler)
    }
    return { status: res.status, headers, body };
  } finally { server.close(); }
}

async function makeTestApp() {
  const { store, cleanup } = await makeTempDb();
  const app = createApp(store);
  return { app, store, cleanup };
}

test('GET /api/items?domain= filters by domain', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedItem(store, { title: 'ransom item', domain: 'ransomware' });
    await seedItem(store, { title: 'vuln item', domain: 'vulnerability' });
    const app = createApp(store);
    const { body } = await get(app, '/api/items?domain=ransomware');
    assert.strictEqual(body.length, 1);
    assert.strictEqual(body[0].title, 'ransom item');
  } finally { await cleanup(); }
});

test('GET /api/items?severity=unknown matches NULL rows, not just the literal string', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    // Never scored — this is the common case (dashboard's 'unknown' bucket is
    // COALESCE(severity,'unknown'), which folds NULL rows like this one in).
    await store.run("INSERT INTO items (source_id, category, title, severity) VALUES ($1,'cve','no severity set',NULL)", [sid]);
    // The rare literal string, e.g. CIRCL's feed-supplied but unmapped severity.
    await store.run("INSERT INTO items (source_id, category, title, severity) VALUES ($1,'cve','literal unknown','unknown')", [sid]);
    await store.run("INSERT INTO items (source_id, category, title, severity) VALUES ($1,'cve','scored','critical')", [sid]);
    const app = createApp(store);
    const { body } = await get(app, '/api/items?severity=unknown');
    assert.strictEqual(body.length, 2);
    assert.deepStrictEqual(body.map((r) => r.title).sort(), ['literal unknown', 'no severity set']);
  } finally { await cleanup(); }
});

test('GET /api/items excludes phishing category, even when explicitly requested', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedItem(store, { title: 'ransom item', domain: 'ransomware' });
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','text_feed',true) RETURNING id")).id;
    await store.run("INSERT INTO items (source_id, category, title) VALUES ($1, 'phishing', 'bad url')", [sid]);
    const app = createApp(store);

    const all = await get(app, '/api/items');
    assert.ok(!all.body.some((r) => r.category === 'phishing'));

    const filtered = await get(app, '/api/items?category=phishing');
    assert.strictEqual(filtered.body.length, 0);
  } finally { await cleanup(); }
});

test('GET /api/ioc-check?url= finds an exact match across categories', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seedItem(store, { title: 'bad phish' });
    await store.run("UPDATE items SET category = 'phishing', published_at = now() WHERE id = $1", [id]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'url', 'http://evil.example/login')", [id]);
    const app = createApp(store);
    const hit = await get(app, '/api/ioc-check?url=' + encodeURIComponent('http://evil.example/login'));
    assert.strictEqual(hit.body.found, true);
    assert.strictEqual(hit.body.matches.length, 1);
    assert.strictEqual(hit.body.matches[0].title, 'bad phish');
    assert.strictEqual(hit.body.matches[0].category, 'phishing');

    const miss = await get(app, '/api/ioc-check?url=' + encodeURIComponent('http://safe.example/'));
    assert.strictEqual(miss.body.found, false);
    assert.deepStrictEqual(miss.body.matches, []);
  } finally { await cleanup(); }
});

test('GET /api/ioc-check?url= ignores scheme and trailing-slash differences', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const id = await seedItem(store, { title: 'example phish' });
    await store.run("UPDATE items SET category = 'phishing', published_at = now() WHERE id = $1", [id]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'url', 'http://phish.example.test/')", [id]);
    const app = createApp(store);
    const hit = await get(app, '/api/ioc-check?url=' + encodeURIComponent('https://phish.example.test'));
    assert.strictEqual(hit.body.found, true);
    assert.strictEqual(hit.body.matches[0].title, 'example phish');
  } finally { await cleanup(); }
});

test('GET /api/ioc-check without url returns 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { status } = await get(app, '/api/ioc-check');
    assert.strictEqual(status, 400);
  } finally { await cleanup(); }
});

test('GET /api/domains returns 16 with counts', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedItem(store, { domain: 'ransomware' });
    const app = createApp(store);
    const { body } = await get(app, '/api/domains');
    assert.strictEqual(body.length, 16);
    const rw = body.find((d) => d.slug === 'ransomware');
    assert.strictEqual(rw.count, 1);
  } finally { await cleanup(); }
});

test('new v4 endpoints respond', async () => {
  const { app, store, cleanup } = await makeTestApp();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, category, fetch_kind, active) VALUES ('NVD CVE API','Vulnerability Intelligence','nvd_cve',true) RETURNING id");
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, summary, severity, cvss_score, published_at)
       VALUES ($1,'cve','CVE-2024-3400','A long authoritative description of the flaw.','critical',9.8, now()) RETURNING id`, [src.id]);
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [item.id, 'CVE-2024-3400']);
    await require('./consolidate').consolidate(store);

    assert.strictEqual((await get(app, `/api/sources/${src.id}/stats`)).status, 200);
    assert.strictEqual((await get(app, '/api/sources/999999/stats')).status, 404);
    assert.strictEqual((await get(app, '/api/sources/abc/stats')).status, 404);

    const cves = await get(app, '/api/cves');
    assert.strictEqual(cves.status, 200);
    assert.strictEqual(cves.headers['x-total-count'], '1');

    assert.strictEqual((await get(app, '/api/cves/CVE-2024-3400')).status, 200);
    assert.strictEqual((await get(app, '/api/cves/CVE-0000-0000')).status, 404);
    assert.strictEqual((await get(app, '/api/actors/Nobody')).status, 404);
    assert.strictEqual((await get(app, '/api/feed')).status, 200);
    assert.strictEqual((await get(app, '/api/search?q=CVE')).status, 200);

    const csv = await get(app, '/api/export/iocs');
    assert.strictEqual(csv.status, 200);
    assert.match(csv.headers['content-type'], /text\/csv/);
  } finally {
    await cleanup();
  }
});

test('GET /api/items hides items older than a year by default', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const src = await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('age','rss',true) RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, external_id, published_at) VALUES
        ($1,'cve','old CVE','o', now() - interval '10 years'),
        ($1,'cve','new CVE','n', now() - interval '2 days'),
        ($1,'cve','undated CVE','u', NULL)`, [src.id]);

    const def = await get(app, '/api/items');
    assert.deepStrictEqual(def.body.map((r) => r.title).sort(), ['new CVE', 'undated CVE'],
      'undated rows must survive the age filter');

    const all = await get(app, '/api/items?maxAgeDays=0');
    assert.strictEqual(all.body.length, 3);
  } finally { await cleanup(); }
});
