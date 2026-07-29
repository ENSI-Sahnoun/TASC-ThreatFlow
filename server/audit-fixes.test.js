const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { makeTempDb } = require('./test-helpers');
const { createApp } = require('./index');
const { safeRequest } = require('./safe-request');
const { assertSafeUrl } = require('./ssrf-guard');

async function req(app, path, opts = {}) {
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, opts);
    const total = res.headers.get('x-total-count');
    let body = null;
    if (res.status !== 204) { try { body = await res.json(); } catch { body = null; } }
    return { status: res.status, body, total };
  } finally { server.close(); }
}

// --- Critical: SSRF guard must block IPv6 literal hosts (bracketed hostnames) ---
test('safeRequest blocks IPv6 loopback literal [::1]', async () => {
  const server = http.createServer((_q, s) => s.end('LOOPBACK'));
  await new Promise((r) => server.listen(0, '::1', r));
  try {
    const port = server.address().port;
    await assert.rejects(() => safeRequest(`http://[::1]:${port}/`), /blocked target address/);
  } finally { server.close(); }
});

test('assertSafeUrl blocks bracketed IPv6 loopback and link-local literals', async () => {
  await assert.rejects(() => assertSafeUrl('http://[::1]/'), /blocked target address/);
  await assert.rejects(() => assertSafeUrl('http://[fe80::1]/'), /blocked target address/);
  await assert.rejects(() => assertSafeUrl('http://[::ffff:169.254.169.254]/'), /blocked target address/);
});

// --- Data integrity: deleting a source cascades item + child rows (FK ON DELETE CASCADE) ---
test('DELETE /api/sources/:id cascades items and their child rows', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    const iid = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'T') RETURNING id", [sid])).id;
    await store.run('INSERT INTO item_actors (item_id, actor) VALUES ($1, $2)', [iid, 'APT1']);
    await store.run('INSERT INTO item_domains (item_id, domain) VALUES ($1, $2)', [iid, 'malware']);
    const app = createApp(store);
    const { status } = await req(app, `/api/sources/${sid}`, { method: 'DELETE' });
    assert.strictEqual(status, 204);
    assert.strictEqual((await store.get('SELECT COUNT(*)::int AS c FROM items')).c, 0);
    assert.strictEqual((await store.get('SELECT COUNT(*)::int AS c FROM item_actors')).c, 0);
    assert.strictEqual((await store.get('SELECT COUNT(*)::int AS c FROM item_domains')).c, 0);
  } finally { await cleanup(); }
});

// --- Secret hygiene: api_key never serialized to clients ---
test('GET /api/sources hides api_key, exposes has_api_key', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await store.run("INSERT INTO sources (name, fetch_kind, active, api_key) VALUES ('K','rss',true,'secret-token')");
    await store.run("INSERT INTO sources (name, fetch_kind, active) VALUES ('NoKey','rss',true)");
    const app = createApp(store);
    const { body } = await req(app, '/api/sources');
    for (const s of body) assert.ok(!('api_key' in s), 'api_key must not be present');
    assert.strictEqual(body.find((s) => s.name === 'K').has_api_key, true);
    assert.strictEqual(body.find((s) => s.name === 'NoKey').has_api_key, false);
  } finally { await cleanup(); }
});

// --- Pagination: total count header + offset ---
test('GET /api/items returns X-Total-Count and honors offset', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    for (let i = 0; i < 5; i += 1) await store.run("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', $2)", [sid, `t${i}`]);
    const app = createApp(store);
    const page1 = await req(app, '/api/items?limit=2&offset=0');
    assert.strictEqual(page1.total, '5');
    assert.strictEqual(page1.body.length, 2);
    const page2 = await req(app, '/api/items?limit=2&offset=2');
    assert.strictEqual(page2.body.length, 2);
    assert.notStrictEqual(page1.body[0].id, page2.body[0].id);
  } finally { await cleanup(); }
});

// --- Dead filter fixed: min_confidence tolerates NULL confidence ---
test('GET /api/items?min_confidence keeps rows with NULL confidence', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    await store.run("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'null-conf')", [sid]);
    await store.run("INSERT INTO items (source_id, category, title, confidence) VALUES ($1, 'cve', 'low', 0.1)", [sid]);
    const app = createApp(store);
    const { body } = await req(app, '/api/items?min_confidence=0.5');
    const titles = body.map((r) => r.title);
    assert.ok(titles.includes('null-conf'), 'NULL-confidence row retained');
    assert.ok(!titles.includes('low'), 'below-threshold row excluded');
  } finally { await cleanup(); }
});

// --- Drill-down: item detail embeds child collections ---
test('GET /api/items/:id embeds cves/actors/domains and parses raw', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    const iid = (await store.get("INSERT INTO items (source_id, category, title, raw_json) VALUES ($1, 'cve', 'T', $2) RETURNING id", [sid, JSON.stringify({ a: 1 })])).id;
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1, $2)', [iid, 'CVE-2024-1']);
    await store.run('INSERT INTO item_actors (item_id, actor) VALUES ($1, $2)', [iid, 'APT1']);
    const app = createApp(store);
    const { body } = await req(app, `/api/items/${iid}`);
    assert.deepStrictEqual(body.cves, ['CVE-2024-1']);
    assert.deepStrictEqual(body.actors, ['APT1']);
    assert.deepStrictEqual(body.raw, { a: 1 });
  } finally { await cleanup(); }
});

// --- Clustering: /api/items collapses non-primary members, exposes cluster metadata ---
test('GET /api/items collapses clustered duplicates to their primary row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s1 = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S1','rss',true) RETURNING id")).id;
    const s2 = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','rss',true) RETURNING id")).id;
    const primary = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Shared story') RETURNING id", [s1])).id;
    const member = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Shared story') RETURNING id", [s2])).id;
    const solo = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Unrelated') RETURNING id", [s1])).id;
    const clusterId = (await store.get(
      "INSERT INTO clusters (primary_item_id, title, source_count) VALUES ($1, 'Shared story', 2) RETURNING id", [primary])).id;
    await store.run('INSERT INTO cluster_items (cluster_id, item_id) VALUES ($1, $2), ($1, $3)', [clusterId, primary, member]);

    const app = createApp(store);
    const { body, total } = await req(app, '/api/items?limit=50');
    assert.strictEqual(total, '2', 'member row excluded from the total, only primary + solo count');
    const ids = body.map((r) => r.id);
    assert.ok(ids.includes(primary), 'primary row present');
    assert.ok(ids.includes(solo), 'unclustered row present');
    assert.ok(!ids.includes(member), 'non-primary member row collapsed out');
    const primaryRow = body.find((r) => r.id === primary);
    assert.strictEqual(primaryRow.cluster_id, clusterId);
    assert.strictEqual(primaryRow.source_count, 2);
    const soloRow = body.find((r) => r.id === solo);
    assert.strictEqual(soloRow.cluster_id, null);
    assert.strictEqual(soloRow.source_count, 1);

    const { body: members } = await req(app, `/api/clusters/${clusterId}/items`);
    assert.strictEqual(members.length, 2);
    assert.deepStrictEqual(new Set(members.map((m) => m.item_id)), new Set([primary, member]));

    assert.strictEqual((await req(app, '/api/clusters/999999/items')).status, 404);
    assert.strictEqual((await req(app, '/api/clusters/abc/items')).status, 404);
  } finally { await cleanup(); }
});

// --- Export filters: /api/export/iocs now honors the full /api/items filter set, not just
// source_id/category/type — verify a newly-added filter (severity) actually narrows the export.
test('GET /api/export/iocs narrows by severity, actor and min_confidence like /api/items does', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const sid = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id")).id;
    const critical = (await store.get(
      "INSERT INTO items (source_id, category, title, severity, confidence) VALUES ($1, 'cve', 'Critical one', 'critical', 0.9) RETURNING id", [sid])).id;
    const low = (await store.get(
      "INSERT INTO items (source_id, category, title, severity, confidence) VALUES ($1, 'cve', 'Low one', 'low', 0.9) RETURNING id", [sid])).id;
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'ip', '1.2.3.4')", [critical]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'ip', '5.6.7.8')", [low]);
    await store.run('INSERT INTO item_actors (item_id, actor) VALUES ($1, $2)', [critical, 'APT1']);

    const app = createApp(store);

    const bySeverity = await req(app, '/api/export/iocs?severity=critical&format=json');
    assert.strictEqual(bySeverity.body.length, 1);
    assert.strictEqual(bySeverity.body[0].value, '1.2.3.4');

    const byActor = await req(app, '/api/export/iocs?actor=APT1&format=json');
    assert.strictEqual(byActor.body.length, 1);
    assert.strictEqual(byActor.body[0].value, '1.2.3.4');

    const unfiltered = await req(app, '/api/export/iocs?format=json');
    assert.strictEqual(unfiltered.body.length, 2, 'no filter still returns every IOC row');

    // CSV variant stays the default and still quotes/escapes correctly for the same filter.
    const csvRes = await req(app, '/api/export/iocs?severity=critical');
    assert.strictEqual(csvRes.status, 200);
  } finally { await cleanup(); }
});

// --- Export/cluster parity: iocRows() must exclude non-primary cluster members the same way
// GET /api/items does, so "Export CSV" / "Copy all IOCs" never include IOCs from rows the
// explorer's collapsed table doesn't show (previously iocRows() had no cluster-dedup clause).
test('GET /api/export/iocs excludes IOCs belonging to non-primary cluster members', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s1 = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S1','rss',true) RETURNING id")).id;
    const s2 = (await store.get("INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','rss',true) RETURNING id")).id;
    const primary = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Shared story') RETURNING id", [s1])).id;
    const member = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Shared story') RETURNING id", [s2])).id;
    const solo = (await store.get("INSERT INTO items (source_id, category, title) VALUES ($1, 'cve', 'Unrelated') RETURNING id", [s1])).id;
    const clusterId = (await store.get(
      "INSERT INTO clusters (primary_item_id, title, source_count) VALUES ($1, 'Shared story', 2) RETURNING id", [primary])).id;
    await store.run('INSERT INTO cluster_items (cluster_id, item_id) VALUES ($1, $2), ($1, $3)', [clusterId, primary, member]);

    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'ip', '9.9.9.9')", [primary]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'ip', '8.8.8.8')", [member]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1, 'domain', 'evil.example')", [solo]);

    const app = createApp(store);

    const { body } = await req(app, '/api/export/iocs?format=json');
    const values = body.map((r) => r.value);
    assert.ok(values.includes('9.9.9.9'), "primary cluster member's IOC included");
    assert.ok(values.includes('evil.example'), "unclustered item's IOC included");
    assert.ok(!values.includes('8.8.8.8'), 'non-primary cluster member IOC excluded');
    assert.strictEqual(body.length, 2, 'only primary + solo IOCs counted, matching the explorer\'s collapsed row count');

    // CSV variant (the actual "Export CSV" response) must match the same row count.
    const server = app.listen(0);
    let csvText;
    try {
      const port = server.address().port;
      const res = await fetch(`http://127.0.0.1:${port}/api/export/iocs`);
      assert.strictEqual(res.status, 200);
      csvText = await res.text();
    } finally { server.close(); }
    const csvDataLines = csvText.trim().split('\n').slice(1); // drop header row
    assert.strictEqual(csvDataLines.length, 2, 'CSV export row count matches the JSON variant');
  } finally { await cleanup(); }
});
