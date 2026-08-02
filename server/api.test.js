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

async function send(app, method, path, body, headers = {}) {
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json', ...headers } : headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    let out = null;
    try { out = await res.json(); } catch { /* not JSON */ }
    return { status: res.status, body: out };
  } finally { server.close(); }
}

const NEW_PROFILE = {
  name: 'Acme Bank', sector: 'finance', vendors: ['microsoft'],
  threatDomains: ['financial'], severityFloor: 'medium',
};

test('GET /api/sectors returns sectors with their recommendations', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/sectors');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.length, 10);
    const finance = res.body.find((s) => s.slug === 'finance');
    assert.ok(finance.recommendation.threatDomains.includes('financial'));
    assert.ok(Array.isArray(finance.recommendation.vendors));
  } finally { await cleanup(); }
});

test('POST /api/profiles creates and GET lists it', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const created = await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    assert.strictEqual(created.status, 201);
    assert.ok(created.body.id > 0);

    const listed = await get(app, '/api/profiles');
    assert.strictEqual(listed.body.length, 1);
    assert.strictEqual(listed.body[0].name, 'Acme Bank');
  } finally { await cleanup(); }
});

test('POST /api/profiles rejects an invalid payload with 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await send(createApp(store), 'POST', '/api/profiles', { ...NEW_PROFILE, sector: 'space-mining' });
    assert.strictEqual(res.status, 400);
    assert.match(res.body.error, /sector/);
  } finally { await cleanup(); }
});

test('POST /api/profiles rejects a duplicate name with 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    const dup = await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    assert.strictEqual(dup.status, 400);
    assert.match(dup.body.error, /already exists/);
  } finally { await cleanup(); }
});

test('PUT /api/profiles/:id bumps the version and returns 202', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const created = await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    const updated = await send(app, 'PUT', `/api/profiles/${created.body.id}`,
      { ...NEW_PROFILE, vendors: ['microsoft', 'oracle'] });
    assert.strictEqual(updated.status, 202);
    assert.strictEqual(updated.body.profile_version, 2);
  } finally { await cleanup(); }
});

test('profile routes return 404 for unknown and non-integer ids', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    assert.strictEqual((await get(app, '/api/profiles/999')).status, 404);
    assert.strictEqual((await get(app, '/api/profiles/abc')).status, 404);
    assert.strictEqual((await send(app, 'DELETE', '/api/profiles/999')).status, 404);
  } finally { await cleanup(); }
});

test('DELETE /api/profiles/:id removes the profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const created = await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    assert.strictEqual((await send(app, 'DELETE', `/api/profiles/${created.body.id}`)).status, 204);
    assert.strictEqual((await get(app, '/api/profiles')).body.length, 0);
  } finally { await cleanup(); }
});

test('GET /api/cpe-facets returns ranked vendors', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('S','json_api') RETURNING id");
    const it = await store.get(
      "INSERT INTO items (source_id, category, title, external_id) VALUES ($1,'cve','C','C') RETURNING id", [s.id]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [it.id]);
    const res = await get(createApp(store), '/api/cpe-facets?kind=vendor&q=fort');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, [{ value: 'fortinet', refs: 1 }]);
  } finally { await cleanup(); }
});

// Phase 2 reads the active profile from this header; a bad value must not become a 500.
test('an unknown or malformed X-Profile-Id returns 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    for (const bad of ['999', 'abc', '-1']) {
      const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': bad });
      assert.strictEqual(res.status, 400, `expected 400 for X-Profile-Id: ${bad}`);
    }
  } finally { await cleanup(); }
});

test('a valid X-Profile-Id is accepted on /api/items', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const created = await send(app, 'POST', '/api/profiles', NEW_PROFILE);
    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(created.body.id) });
    assert.strictEqual(res.status, 200);
  } finally { await cleanup(); }
});
