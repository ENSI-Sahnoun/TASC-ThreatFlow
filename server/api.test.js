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

async function seedRelevanceFixture(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('RS','json_api',true) RETURNING id");
  const hit = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
     VALUES ($1,'cve','FortiOS RCE','CVE-2026-1','high', now() - interval '2 days') RETURNING id`, [src.id]);
  await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [hit.id]);
  // Ladder v3: act_now requires exploitation evidence, not just severity — this fixture is used
  // by several tests that need a genuine act_now row to sort/filter against, so it earns act_now
  // the same way a real item would: a KEV listing.
  await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-1')", [hit.id]);
  await store.run(
    "INSERT INTO cve_intel (cve_id, severity, kev_listed, source_count) VALUES ('CVE-2026-1','high',true,1)");
  const miss = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, published_at)
     VALUES ($1,'news','Unrelated','N-2', now() - interval '1 day') RETURNING id`, [src.id]);
  return { hitId: hit.id, missId: miss.id };
}

const REL_PROFILE = {
  name: 'Rel', sector: 'finance', vendors: ['fortinet'], products: ['fortios'],
  threatDomains: [], severityFloor: 'medium',
  // Ladder v2: only a profile_assets row can reach act_now or watch. This fixture represents a
  // profile that actually runs FortiOS, so it carries the asset alongside the legacy arrays.
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }],
};

test('GET /api/items omits relevance when no profile header is sent', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const res = await get(app, '/api/items');
    assert.ok(res.body.length > 0);
    assert.strictEqual(res.body[0].relevance, null);
  } finally { await cleanup(); }
});

test('GET /api/items returns a tier and matches for the active profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    const hit = res.body.find((r) => r.id === hitId);
    assert.strictEqual(hit.relevance.tier, 'act_now');
    assert.ok(hit.relevance.matches.some((m) => m.kind === 'product'));
  } finally { await cleanup(); }
});

// Rank, don't hide: the most relevant item leads, the rest stay reachable below it.
test('GET /api/items sorts act_now ahead of not_yours when a profile is active', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    assert.strictEqual(res.body[0].id, hitId, 'act_now must lead even though it is not the newest');
  } finally { await cleanup(); }
});

test('?relevantOnly=1 filters to act_now and watch, and is off by default', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    const hdr = { 'X-Profile-Id': String(p.body.id) };

    assert.strictEqual((await send(app, 'GET', '/api/items', null, hdr)).body.length, 2, 'nothing hidden by default');
    const only = await send(app, 'GET', '/api/items?relevantOnly=1', null, hdr);
    assert.strictEqual(only.body.length, 1);
    assert.strictEqual(only.body[0].id, hitId);
  } finally { await cleanup(); }
});

// An item inserted between recomputes has no row yet; it must sort last, not vanish and not
// force the frontend to handle a null.
test('an item with no relevance row is served as not_yours, not null', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const src = await store.get("SELECT id FROM sources WHERE name='RS'");
    const late = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Arrived late','N-3', now()) RETURNING id`, [src.id]);

    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    const row = res.body.find((r) => r.id === late.id);
    assert.ok(row, 'the unscored item must still appear');
    assert.strictEqual(row.relevance.tier, 'not_yours');
    assert.deepStrictEqual(row.relevance.matches, []);
  } finally { await cleanup(); }
});

test('POST /api/profiles/:id/relevance/recompute returns 202 and 404 for unknown ids', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    assert.strictEqual((await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`)).status, 202);
    assert.strictEqual((await send(app, 'POST', '/api/profiles/999/relevance/recompute')).status, 404);
  } finally { await cleanup(); }
});

test('GET /api/items includes a model-written sentence when one exists', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    await store.run(
      `INSERT INTO item_relevance_prose (profile_id, item_id, profile_version, sentence, model)
       VALUES ($1,$2,1,'You run FortiOS, so this critical flaw is directly exposed.','test-model')`,
      [p.body.id, hitId]);

    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    const hit = res.body.find((r) => r.id === hitId);
    assert.match(hit.relevance.sentence, /directly exposed/);
  } finally { await cleanup(); }
});

// Ollama being unreachable must cost nothing but nicer phrasing.
test('relevance sentence is null when no prose was written, and the tier is unaffected', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    const hit = res.body.find((r) => r.id === hitId);
    assert.strictEqual(hit.relevance.sentence, null);
    assert.strictEqual(hit.relevance.tier, 'act_now');
    assert.ok(hit.relevance.matches.length > 0, 'the templated reasons are still there');
  } finally { await cleanup(); }
});

test('POST /api/profiles/:id/relevance/prose returns 202 and 404 for unknown ids', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    assert.strictEqual((await send(app, 'POST', '/api/profiles/999/relevance/prose')).status, 404);
  } finally { await cleanup(); }
});

test('GET /api/items exposes the quality verdict when one exists', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run("INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,'promotion','test-model')", [hitId]);
    const res = await get(app, '/api/items');
    const hit = res.body.find((r) => r.id === hitId);
    assert.strictEqual(hit.quality.verdict, 'promotion');
  } finally { await cleanup(); }
});

test('quality is null for an unclassified item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const res = await get(app, '/api/items');
    assert.ok(res.body.every((r) => r.quality === null));
  } finally { await cleanup(); }
});

// Demoted, never removed — a misclassification must cost ranking, not visibility.
test('non-intel items sort below intel but remain in the results', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('Q','rss',true) RETURNING id");
    // The junk item is NEWER, so recency alone would put it first.
    const junk = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Vendor Raises $50 Million','J-1', now()) RETURNING id`, [src.id]);
    const real = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Actor breaches hospital network','R-1', now() - interval '2 days') RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,'promotion','m')", [junk.id]);
    await store.run("INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,'intel','m')", [real.id]);

    const res = await get(app, '/api/items');
    const ids = res.body.map((r) => r.id);
    assert.ok(ids.includes(junk.id), 'the demoted item is still present');
    assert.ok(ids.indexOf(real.id) < ids.indexOf(junk.id), 'intel outranks newer promotion');
  } finally { await cleanup(); }
});

// Personal relevance is the primary axis; quality only breaks ties beneath it.
test('quality demotion never outranks a relevance tier', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('Q2','rss',true) RETURNING id");
    const urgent = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
       VALUES ($1,'cve','FortiOS RCE','U-1','high', now() - interval '1 day') RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [urgent.id]);
    // Flag the urgent item as junk; its act_now tier must still win.
    await store.run("INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,'promotion','m')", [urgent.id]);
    const boring = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Unrelated story','B-1', now()) RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_quality (item_id, verdict, model) VALUES ($1,'intel','m')", [boring.id]);

    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    const res = await send(app, 'GET', '/api/items', null, { 'X-Profile-Id': String(p.body.id) });
    assert.strictEqual(res.body[0].id, urgent.id, 'act_now leads despite the promotion verdict');
  } finally { await cleanup(); }
});

// --- story links ------------------------------------------------------------

async function seedLinkedClusters(store) {
  const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
  const mk = async (title) => {
    const item = await store.get(
      "INSERT INTO items (source_id, category, title) VALUES ($1,'news',$2) RETURNING id", [sid, title]);
    const cluster = await store.get(
      'INSERT INTO clusters (primary_item_id, title, first_seen, source_count) VALUES ($1,$2,now(),1) RETURNING id',
      [item.id, title]);
    return { itemId: item.id, clusterId: cluster.id };
  };
  const a = await mk('Minnesota water systems attacked');
  const b = await mk('CISA warns on water system attacks');
  const [lo, hi] = [Math.min(a.clusterId, b.clusterId), Math.max(a.clusterId, b.clusterId)];
  await store.run(
    "INSERT INTO story_links (cluster_a_id, cluster_b_id, similarity, model) VALUES ($1,$2,0.93,'m')", [lo, hi]);
  return { a, b };
}

test('GET /api/clusters/:id/related returns the pair from either direction', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { a, b } = await seedLinkedClusters(store);
    const app = createApp(store);

    const fromA = await get(app, `/api/clusters/${a.clusterId}/related`);
    assert.strictEqual(fromA.status, 200);
    assert.strictEqual(fromA.body.length, 1);
    assert.strictEqual(fromA.body[0].clusterId, b.clusterId);
    assert.strictEqual(fromA.body[0].primaryItemId, b.itemId);
    assert.strictEqual(fromA.body[0].label, 'Likely related');

    // The canonical row is stored once with a < b; the other side must still resolve.
    const fromB = await get(app, `/api/clusters/${b.clusterId}/related`);
    assert.strictEqual(fromB.body.length, 1);
    assert.strictEqual(fromB.body[0].clusterId, a.clusterId);
  } finally { await cleanup(); }
});

test('GET /api/clusters/:id/related is an empty array when nothing is linked', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    const item = await store.get("INSERT INTO items (source_id, category, title) VALUES ($1,'news','lonely') RETURNING id", [sid]);
    const cluster = await store.get(
      'INSERT INTO clusters (primary_item_id, title, first_seen, source_count) VALUES ($1,$2,now(),1) RETURNING id',
      [item.id, 'lonely']);
    const res = await get(createApp(store), `/api/clusters/${cluster.id}/related`);
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, []);
  } finally { await cleanup(); }
});

test('GET /api/clusters/:id/related 404s for unknown and non-integer ids', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    assert.strictEqual((await get(app, '/api/clusters/999999/related')).status, 404);
    assert.strictEqual((await get(app, '/api/clusters/abc/related')).status, 404);
  } finally { await cleanup(); }
});

// The detail page decides between a record-card and a browser-window preview based on
// fetch_kind, and shows a source-health dot based on last_status. Both must arrive on the
// initial response — a second request for them lands after first paint and flips the branch,
// visible as a flash between the two layouts.
test('GET /api/items/:id includes the source fetch_kind and status inline', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get(
      "INSERT INTO sources (name, fetch_kind, active, last_status) VALUES ('NVD','nvd',true,'ok') RETURNING id")).id;
    const item = await store.get(
      "INSERT INTO items (source_id, category, title) VALUES ($1,'cve','CVE-2026-1') RETURNING id", [sid]);
    const res = await get(createApp(store), `/api/items/${item.id}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.source_fetch_kind, 'nvd');
    assert.strictEqual(res.body.source_status, 'ok');
  } finally { await cleanup(); }
});

test('GET /api/items/:id omits relevance and quality when no profile header is sent', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const res = await get(app, `/api/items/${hitId}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.relevance, null);
    assert.strictEqual(res.body.quality, null);
  } finally { await cleanup(); }
});

test('GET /api/items/:id returns tier, matches and sentence for the active profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    await store.run(
      `INSERT INTO item_relevance_prose (profile_id, item_id, profile_version, sentence, model)
       VALUES ($1, $2, $3, 'Matches your Fortinet stack.', 'test-model')`,
      [p.body.id, hitId, p.body.profile_version]);

    const res = await send(app, 'GET', `/api/items/${hitId}`, null, { 'X-Profile-Id': String(p.body.id) });
    assert.strictEqual(res.body.relevance.tier, 'act_now');
    assert.ok(res.body.relevance.matches.some((m) => m.kind === 'product'));
    assert.strictEqual(res.body.relevance.sentence, 'Matches your Fortinet stack.');
  } finally { await cleanup(); }
});

test('GET /api/items/:id serves not_yours with no prose sentence when the item has no relevance row yet', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { missId } = await seedRelevanceFixture(store);
    const p = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', `/api/items/${missId}`, null, { 'X-Profile-Id': String(p.body.id) });
    assert.strictEqual(res.body.relevance.tier, 'not_yours');
    assert.deepStrictEqual(res.body.relevance.matches, []);
    assert.strictEqual(res.body.relevance.sentence, null);
  } finally { await cleanup(); }
});

test('GET /api/items/:id includes the quality verdict when one has been classified', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      "INSERT INTO item_quality (item_id, verdict, model) VALUES ($1, 'roundup', 'test-model')", [hitId]);
    const res = await get(createApp(store), `/api/items/${hitId}`);
    assert.deepStrictEqual(res.body.quality, { verdict: 'roundup' });
  } finally { await cleanup(); }
});

test('GET /api/items/:id carries relatedStoryCount for a cluster primary', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { a } = await seedLinkedClusters(store);
    const app = createApp(store);
    const res = await get(app, `/api/items/${a.itemId}`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.relatedStoryCount, 1);
  } finally { await cleanup(); }
});

// Only a cluster primary can carry related stories — a non-primary member is a duplicate of
// its primary, not a story of its own.
test('GET /api/items/:id reports relatedStoryCount 0 for a non-primary item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedLinkedClusters(store);
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','rss',true) RETURNING id")).id;
    const other = await store.get("INSERT INTO items (source_id, category, title) VALUES ($1,'news','a member') RETURNING id", [sid]);
    const res = await get(createApp(store), `/api/items/${other.id}`);
    assert.strictEqual(res.body.relatedStoryCount, 0);
  } finally { await cleanup(); }
});

test('GET /api/health responds ok', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/health');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.body, { ok: true });
  } finally { await cleanup(); }
});

// --- Impact indicator (Spec A) ---

const IMPACT_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

test('GET /api/items/:id includes consequence slots for the active profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    // The fixture item has no vector; add one so reach and impact are derivable.
    await store.run('UPDATE items SET cvss_vector = $1 WHERE id = $2', [IMPACT_VECTOR, hitId]);

    const created = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'Consequence',
      assets: [{ product: 'fortios', exposure: 'internet' }],
    });
    assert.strictEqual(created.status, 201);
    // The create route recomputes in the background; run it synchronously so the read below
    // is deterministic rather than racing the background job.
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.match(res.body.relevance.consequence.reach.text, /anyone on the internet/);
    assert.strictEqual(res.body.relevance.consequence.impact.text, 'read, change and shut down');
    assert.strictEqual(res.body.relevance.exposure, 'internet');
  } finally { await cleanup(); }
});

test('GET /api/items carries consequence on each row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run('UPDATE items SET cvss_vector = $1 WHERE id = $2', [IMPACT_VECTOR, hitId]);
    const created = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'RowLevel',
      assets: [{ product: 'fortios', exposure: 'internet' }],
    });
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items?profileId=${created.body.id}`);
    const row = res.body.find((r) => r.id === hitId);
    assert.match(row.relevance.consequence.reach.text, /anyone on the internet/);
    assert.strictEqual(row.relevance.exposure, 'internet');
  } finally { await cleanup(); }
});

test('POST /api/profiles accepts assets and returns them resolved', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const res = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'assets-ok',
      assets: [{ product: 'fortios', exposure: 'internet' }],
    });
    assert.strictEqual(res.status, 201);
    assert.deepStrictEqual(res.body.assets,
      [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' }]);
  } finally { await cleanup(); }
});

test('POST /api/profiles rejects an unknown exposure with 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await send(createApp(store), 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'assets-bad',
      assets: [{ product: 'fortios', exposure: 'sometimes' }],
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.body.error, /exposure/);
  } finally { await cleanup(); }
});

test('PUT /api/profiles/:id replaces the asset set', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const created = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'replace-me',
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });
    const updated = await send(app, 'PUT', `/api/profiles/${created.body.id}`, {
      ...REL_PROFILE, name: 'replace-me',
      assets: [{ vendor: 'fortinet', product: 'fortiproxy', exposure: 'internal' }],
    });
    assert.strictEqual(updated.status, 202);
    assert.deepStrictEqual(updated.body.assets,
      [{ vendor: 'fortinet', product: 'fortiproxy', exposure: 'internal', version: null, versionState: 'unset' }]);
  } finally { await cleanup(); }
});

test('relevance is null when no profile is active', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId } = await seedRelevanceFixture(store);
    const res = await get(createApp(store), `/api/items/${hitId}`);
    assert.strictEqual(res.body.relevance, null);
  } finally { await cleanup(); }
});

// --- Playbooks ---

async function seedPlaybookItem(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
  const item = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
     VALUES ($1,'cve','FortiOS RCE','CVE-2026-40','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', now() - interval '1 days')
     RETURNING id`, [src.id]);
  await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [item.id]);
  await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-40')", [item.id]);
  await store.run(`INSERT INTO cve_intel (cve_id, severity, kev_listed) VALUES ('CVE-2026-40','critical',true)`);
  return item.id;
}

const PLAYBOOK_PROFILE = {
  name: 'p', sector: 'finance', vendors: [], products: [], threatDomains: [], severityFloor: 'medium',
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
};

test('GET /api/items/:id includes a playbook once a matching profile is active', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const itemId = await seedPlaybookItem(store);
    const p = await send(app, 'POST', '/api/profiles', PLAYBOOK_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', `/api/items/${itemId}`, null, { 'X-Profile-Id': String(p.body.id) });
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.playbook.steps));
    assert.ok(res.body.playbook.steps.some((s) => s.key === 'confirm'));
    assert.deepStrictEqual(res.body.playbook.done, []);
  } finally { await cleanup(); }
});

test('GET /api/items/:id returns playbook: null with no active profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const itemId = await seedPlaybookItem(store);
    const res = await get(createApp(store), `/api/items/${itemId}`);
    assert.strictEqual(res.body.playbook, null);
  } finally { await cleanup(); }
});

test('POST then DELETE a playbook step round-trips through done[]', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const itemId = await seedPlaybookItem(store);
    const p = await send(app, 'POST', '/api/profiles', PLAYBOOK_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    const hdr = { 'X-Profile-Id': String(p.body.id) };

    const tick = await send(app, 'POST', `/api/items/${itemId}/playbook/steps/confirm`, {}, hdr);
    assert.strictEqual(tick.status, 204);

    const afterTick = await send(app, 'GET', `/api/items/${itemId}`, null, hdr);
    assert.deepStrictEqual(afterTick.body.playbook.done, ['confirm']);

    const untick = await send(app, 'DELETE', `/api/items/${itemId}/playbook/steps/confirm`, null, hdr);
    assert.strictEqual(untick.status, 204);

    const afterUntick = await send(app, 'GET', `/api/items/${itemId}`, null, hdr);
    assert.deepStrictEqual(afterUntick.body.playbook.done, []);
  } finally { await cleanup(); }
});

test('POST an unknown step_key returns 404 and stores nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const itemId = await seedPlaybookItem(store);
    const p = await send(app, 'POST', '/api/profiles', PLAYBOOK_PROFILE);
    await send(app, 'POST', `/api/profiles/${p.body.id}/relevance/recompute`);
    const hdr = { 'X-Profile-Id': String(p.body.id) };

    const res = await send(app, 'POST', `/api/items/${itemId}/playbook/steps/not-a-real-step`, {}, hdr);
    assert.strictEqual(res.status, 404);
    assert.strictEqual((await store.all('SELECT 1 FROM playbook_step_state')).length, 0);
  } finally { await cleanup(); }
});

test('POST a playbook step with no active profile returns 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const itemId = await seedPlaybookItem(store);
    const res = await send(app, 'POST', `/api/items/${itemId}/playbook/steps/confirm`, {});
    assert.strictEqual(res.status, 400);
  } finally { await cleanup(); }
});

test('POST /api/profiles/:id/playbooks/word returns 202 and 404 for unknown ids', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const p = await send(app, 'POST', '/api/profiles', {
      name: 'p', sector: 'finance', vendors: [], products: [], threatDomains: [], severityFloor: 'medium',
    });
    assert.strictEqual((await send(app, 'POST', `/api/profiles/${p.body.id}/playbooks/word`)).status, 202);
    assert.strictEqual((await send(app, 'POST', '/api/profiles/999/playbooks/word')).status, 404);
  } finally { await cleanup(); }
});

// playbook_step_state is deliberately not keyed by profile_version — a tick is a statement
// about the real world, and PUT /api/profiles/:id bumps profile_version on every edit.
test('a ticked step survives a PUT /api/profiles/:id that bumps profile_version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const itemId = await seedPlaybookItem(store);
    const created = await send(app, 'POST', '/api/profiles', PLAYBOOK_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`);
    const hdr = { 'X-Profile-Id': String(created.body.id) };
    await send(app, 'POST', `/api/items/${itemId}/playbook/steps/confirm`, {}, hdr);

    // Bump profile_version by editing an unrelated field.
    await send(app, 'PUT', `/api/profiles/${created.body.id}`, {
      ...PLAYBOOK_PROFILE, sector: 'healthcare',
    });
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`);

    const res = await send(app, 'GET', `/api/items/${itemId}`, null, hdr);
    assert.deepStrictEqual(res.body.playbook.done, ['confirm']);
  } finally { await cleanup(); }
});

// --- Remediation foundation (Spec A): queue route ---

test('GET /api/profiles/:id/remediation groups open threats by asset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    await store.run(
      `UPDATE cve_intel SET affected_versions = $1 WHERE cve_id = 'CVE-2026-1'`,
      [JSON.stringify([{
        vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5',
        startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: '7.4.5', pinned: null,
      }])]);
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.length, 1);
    assert.strictEqual(res.body[0].vendor, 'fortinet');
    assert.strictEqual(res.body[0].product, 'fortios');
    assert.strictEqual(res.body[0].versionState, 'unset');
    assert.strictEqual(res.body[0].items.length, 1);
    assert.strictEqual(res.body[0].items[0].itemId, hitId);
    assert.strictEqual(res.body[0].items[0].fix.kind, 'version');
    assert.strictEqual(res.body[0].items[0].fix.value, '7.4.5');
    // No version recorded yet — unset must never read as affected or not_covered.
    assert.strictEqual(res.body[0].items[0].status, 'unknown');
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation excludes low/not_yours items', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store); // seeds one act_now item and one unrelated news item
    const created = await send(app, 'POST', '/api/profiles', REL_PROFILE);
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/profiles/${created.body.id}/remediation`);
    const itemIds = res.body.flatMap((g) => g.items.map((i) => i.itemId));
    // Only the fortios/act_now item can appear; the unrelated news item has no matching asset
    // and is not_yours, so it must not show up in any group.
    assert.strictEqual(itemIds.length, res.body.reduce((n, g) => n + g.items.length, 0));
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation returns 404 for a non-integer id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/profiles/abc/remediation');
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});

test('GET /api/profiles/:id/remediation returns 404 for an unknown profile id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await get(createApp(store), '/api/profiles/999/remediation');
    assert.strictEqual(res.status, 404);
  } finally { await cleanup(); }
});
