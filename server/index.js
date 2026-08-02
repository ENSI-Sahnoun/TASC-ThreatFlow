const express = require('express');
const { seedFromConfig, configByName } = require('./seed');
const { syncSource, loadKevCveSet } = require('./fetchers');
const { deriveFetchKind } = require('./normalize');
const { assertSafeUrl } = require('./ssrf-guard');
const { safeRequest } = require('./safe-request');
const { frameVerdict } = require('./frame-policy');
const { DOMAINS } = require('./domains');
const { dashboardStats } = require('./stats');
const { normalizeUrl } = require('./urlnorm');
const { consolidate } = require('./consolidate');
const { startScheduler } = require('./scheduler');
const { sourceStats, listCves, cveDetail, entityProfile, feed, search, iocRows, cpeFacets, maxAgeClause } = require('./queries');
const { SECTORS, recommendationFor } = require('./sector_profiles');
const profiles = require('./profiles');
const { recomputeProfile } = require('./relevance');

const CONFIG_BY_NAME = configByName();

// Sequential sync-all over 80+ sources at 15-20s timeout each could take minutes;
// bounded concurrency keeps it fast without hammering every host in parallel.
const SYNC_CONCURRENCY = 8;

// Angular's `ng serve` runs the SPA cross-origin (localhost:4200) from the API (4173);
// without CORS the browser blocks every XHR. Allowlist is env-configurable for prod.
const CORS_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:4200')
  .split(',').map((s) => s.trim()).filter(Boolean);

// api_key is a stored secret (Shodan key, custom-source tokens). Never serialize it to
// clients — expose only whether one is set. The whole API feeds a browser frontend.
function publicSource(row) {
  if (!row) return row;
  const { api_key, ...rest } = row;
  return { ...rest, has_api_key: !!api_key };
}

// ip_intel stores its list fields as JSON strings; decode them for API consumers.
function decodeIpIntel(row) {
  if (!row) return null;
  const parse = (v) => { try { return v ? JSON.parse(v) : null; } catch { return null; } };
  return {
    ip: row.ip,
    ports: parse(row.ports_json),
    vulns: parse(row.vulns_json),
    tags: parse(row.tags_json),
    cpes: parse(row.cpes_json),
    hostnames: parse(row.hostnames_json),
    org: row.org, isp: row.isp, city: row.city, country_code: row.country_code,
    source: row.source, fetched_at: row.fetched_at,
  };
}

// :id path params address an INT column; reject non-integers as not-found rather than
// letting Postgres raise "invalid input syntax for integer" (a 500).
function parseId(raw) {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function createApp(store) {
  const app = express();
  app.use(express.json());

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && CORS_ORIGINS.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  // Wrap async handlers so a rejected promise becomes a 500 instead of an unhandled
  // rejection that crashes the process.
  // An error carrying a numeric `status` is a caller error (e.g. an unknown X-Profile-Id) and
  // keeps that code; everything else is a server fault and becomes a 500.
  const h = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((err) => {
    const status = Number.isInteger(err && err.status) ? err.status : 500;
    if (!res.headersSent) res.status(status).json({ error: String(err.message || err) });
  });

  // Profiles are personas, not accounts — no password, no session, no boundary between them.
  // Anyone reaching the API can select any profile; the loopback bind is what keeps that safe.
  // Phase 2's relevance scoring reads the active profile from here.
  async function resolveProfile(req) {
    const raw = req.get('X-Profile-Id') || req.query.profileId;
    if (raw == null || raw === '') return null;
    const profile = await profiles.getProfile(store, raw);
    if (!profile) { const e = new Error('unknown profile'); e.status = 400; throw e; }
    return profile;
  }

  app.get('/api/sectors', h(async (req, res) => {
    res.json(SECTORS.map((s) => ({ ...s, recommendation: recommendationFor(s.slug) })));
  }));

  app.get('/api/cpe-facets', h(async (req, res) => {
    res.json(await cpeFacets(store, { q: req.query.q, kind: req.query.kind, limit: req.query.limit }));
  }));

  app.get('/api/profiles', h(async (req, res) => {
    res.json(await profiles.listProfiles(store));
  }));

  // Verdicts are recomputed in the background: a recompute over the whole corpus takes about a
  // second, which is worth not blocking a form submit on. A failure here leaves items at
  // 'not_yours' until the next trigger rather than failing the write the user actually asked for.
  const recomputeInBackground = (id) => { recomputeProfile(store, id).catch(() => {}); };

  app.post('/api/profiles', h(async (req, res) => {
    let created;
    try {
      created = await profiles.createProfile(store, req.body || {});
    } catch (e) {
      // Validation and duplicate-name failures are caller errors, not server faults.
      return res.status(400).json({ error: e.message });
    }
    recomputeInBackground(created.id);
    res.status(201).json(created);
  }));

  app.get('/api/profiles/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });
    res.json(profile);
  }));

  app.put('/api/profiles/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(404).json({ error: 'not found' });
    let updated;
    try {
      updated = await profiles.updateProfile(store, id, req.body || {});
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    if (!updated) return res.status(404).json({ error: 'not found' });
    // 202: the row is saved, but the relevance recompute for the new profile_version runs in
    // the background. Until it finishes, items read as 'not_yours' at the new version.
    recomputeInBackground(updated.id);
    res.status(202).json(updated);
  }));

  app.delete('/api/profiles/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id || !(await profiles.deleteProfile(store, id))) return res.status(404).json({ error: 'not found' });
    res.status(204).end();
  }));

  app.post('/api/profiles/:id/relevance/recompute', h(async (req, res) => {
    const id = parseId(req.params.id);
    const result = id && await recomputeProfile(store, id);
    if (!result) return res.status(404).json({ error: 'not found' });
    res.status(202).json(result);
  }));

  app.get('/api/sources', h(async (req, res) => {
    // item_count backs the Arsenal index card grid — one aggregate query for all 43 sources
    // rather than a per-source stats call each.
    const sources = await store.all(`
      SELECT s.*, COUNT(i.id)::int AS item_count
      FROM sources s
      LEFT JOIN items i ON i.source_id = s.id
      GROUP BY s.id
      ORDER BY s.name
    `);
    res.json(sources.map(publicSource));
  }));

  app.post('/api/sources', h(async (req, res) => {
    const { name, category, conn_type, url, notes, auth_required, api_key, request_method, request_body, api_key_header } = req.body;
    if (!name || !url) return res.status(400).json({ error: 'name and url are required' });
    try {
      await assertSafeUrl(url);
    } catch (err) {
      return res.status(400).json({ error: `rejected URL: ${err.message}` });
    }
    const fetchKind = req.body.fetch_kind || deriveFetchKind(conn_type || request_method);
    const created = await store.get(
      `INSERT INTO sources (name, category, conn_type, fetch_kind, url, tier, notes, auth_required, api_key, request_method, request_body, api_key_header, active, is_custom)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true, true)
       RETURNING *`,
      [
        name,
        category || 'Custom',
        conn_type || fetchKind,
        fetchKind,
        url,
        'Custom',
        notes || null,
        auth_required || null,
        api_key || null,
        request_method || 'GET',
        request_body || null,
        api_key_header || 'Authorization',
      ]
    );
    res.status(201).json(publicSource(created));
  }));

  app.patch('/api/sources/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    const source = id && await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    if (!source) return res.status(404).json({ error: 'not found' });
    if (req.body.active !== undefined) {
      await store.run('UPDATE sources SET active = $1 WHERE id = $2', [!!req.body.active, id]);
    }
    for (const field of ['api_key', 'request_method', 'request_body', 'api_key_header']) {
      if (req.body[field] !== undefined) {
        await store.run(`UPDATE sources SET ${field} = $1 WHERE id = $2`, [req.body[field] || null, id]);
      }
    }
    if (req.body.url !== undefined) {
      try {
        await assertSafeUrl(req.body.url);
      } catch (err) {
        return res.status(400).json({ error: `rejected URL: ${err.message}` });
      }
      await store.run('UPDATE sources SET url = $1 WHERE id = $2', [req.body.url, id]);
    }
    for (const field of ['name', 'category', 'notes', 'auth_required', 'cve_field', 'cvss_field', 'severity_field', 'vendor_field']) {
      if (req.body[field] !== undefined) {
        await store.run(`UPDATE sources SET ${field} = $1 WHERE id = $2`, [req.body[field] || null, id]);
      }
    }
    res.json(publicSource(await store.get('SELECT * FROM sources WHERE id = $1', [id])));
  }));

  app.delete('/api/sources/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    // items + all item_* children cascade via ON DELETE CASCADE.
    const result = id && await store.run('DELETE FROM sources WHERE id = $1', [id]);
    if (!result || result.rowCount === 0) return res.status(404).json({ error: 'not found' });
    res.status(204).end();
  }));

  app.post('/api/sources/:id/sync', h(async (req, res) => {
    const id = parseId(req.params.id);
    const source = id && await store.get('SELECT * FROM sources WHERE id = $1', [id]);
    if (!source) return res.status(404).json({ error: 'not found' });
    const result = await syncSource(source, { store, kevCveSet: await loadKevCveSet(store), configByName: CONFIG_BY_NAME });
    res.json(result);
  }));

  async function syncAllConcurrent(sources) {
    const kevCveSet = await loadKevCveSet(store);
    const results = new Array(sources.length);
    let next = 0;
    async function worker() {
      while (next < sources.length) {
        const i = next;
        next += 1;
        const source = sources[i];
        const result = await syncSource(source, { store, kevCveSet, configByName: CONFIG_BY_NAME });
        results[i] = { id: source.id, name: source.name, ...result };
      }
    }
    await Promise.all(Array.from({ length: Math.min(SYNC_CONCURRENCY, sources.length) }, worker));
    return results;
  }

  app.post('/api/sources/sync-all', h(async (req, res) => {
    const sources = await store.all('SELECT * FROM sources WHERE active = true');
    const results = await syncAllConcurrent(sources);
    // Each source's items are already committed by its own transaction inside syncSource;
    // a consolidation failure must not erase that work from the response. Without this,
    // the h() wrapper turns a thrown consolidate() into a bare 500 and the caller loses the
    // per-source results, unable to tell which sources succeeded without re-querying.
    let consolidation = null;
    let consolidationError = null;
    try {
      consolidation = await consolidate(store);
    } catch (e) {
      consolidationError = e.message;
    }
    // Newly ingested items have no verdict yet. Rescore every profile after consolidation, so
    // the tiers reflect the cve_intel facts this sync just rebuilt rather than the previous ones.
    for (const p of await profiles.listProfiles(store)) recomputeInBackground(p.id);
    res.json({ results, consolidation, consolidationError });
  }));

  app.get('/api/items', h(async (req, res) => {
    // Validate the header before any query runs, so a bad profile id fails fast as a 400.
    const profile = await resolveProfile(req);
    const { category, source_id, q, limit } = req.query;
    const params = [];
    const ph = (v) => { params.push(v); return `$${params.length}`; };
    const where = ['1=1'];
    // Phishing feeds are individual URLs, not intel to browse — 500+ of them would otherwise
    // dominate any unfiltered or cross-category list. They're reachable only through the URL
    // checker (GET /api/ioc-check), which queries item_iocs directly and isn't affected by this.
    where.push("items.category <> 'phishing'");
    // Stale rows stay in the database and remain reachable via ?maxAgeDays=0 and search;
    // they just do not lead the default listing. Undated rows pass through.
    const ageSql = maxAgeClause(req.query.maxAgeDays, ph);
    if (ageSql) where.push(ageSql);
    if (category) where.push(`items.category = ${ph(category)}`);
    if (source_id) where.push(`items.source_id = ${ph(source_id)}`);
    if (q) {
      // ILIKE keeps the search case-insensitive (Postgres LIKE is case-sensitive).
      const like = `%${q}%`;
      where.push(`(items.title ILIKE ${ph(like)} OR items.summary ILIKE ${ph(like)} OR items.author ILIKE ${ph(like)} OR sources.name ILIKE ${ph(like)})`);
    }
    const joinFilters = [
      ['domain', 'item_domains', 'domain'],
      ['actor', 'item_actors', 'actor'],
      ['malware_family', 'item_malware_families', 'family'],
      ['cve', 'item_cves', 'cve_id'],
    ];
    for (const [param, tbl, col] of joinFilters) {
      if (req.query[param]) where.push(`items.id IN (SELECT item_id FROM ${tbl} WHERE ${col} = ${ph(req.query[param])})`);
    }
    // The dashboard/stats 'unknown' bucket is COALESCE(severity,'unknown') — it covers both the
    // literal string AND rows where severity was never set at all. A plain equality filter would
    // match only the literal string and silently drop every NULL row from that same bucket.
    if (req.query.severity) {
      where.push(req.query.severity === 'unknown'
        ? `(items.severity IS NULL OR items.severity = ${ph(req.query.severity)})`
        : `items.severity = ${ph(req.query.severity)}`);
    }
    for (const col of ['exploitation_status', 'vendor', 'region', 'industry']) {
      if (req.query[col]) where.push(`items.${col} = ${ph(req.query[col])}`);
    }
    // confidence is nullable and often unset; NULL >= x is never true, so a naive filter
    // would drop every un-scored row. Tolerate NULL so the filter only excludes low scores.
    if (req.query.min_confidence) where.push(`(items.confidence IS NULL OR items.confidence >= ${ph(Number(req.query.min_confidence))})`);

    // A cluster's non-primary members are duplicates of the same story from other sources
    // (see clusters/cluster_items — the same join /api/feed uses). Exclude them from the
    // explorer's row list so "N sources" collapses to one row instead of N; the primary row
    // carries cluster_id + source_count so the UI can expand to the other members on demand.
    where.push(`items.id NOT IN (
      SELECT ci.item_id FROM cluster_items ci JOIN clusters cl ON cl.id = ci.cluster_id
      WHERE cl.primary_item_id <> ci.item_id
    )`);

    // With a profile active, relevance drives the order. An item with no row yet (inserted
    // between recomputes) is treated as not_yours: it sorts last but is never dropped, and the
    // caller never has to handle a null tier.
    let relJoin = '';
    let relSelect = 'NULL::text AS rel_tier, NULL::jsonb AS rel_matches';
    let orderBy = 'ORDER BY COALESCE(items.published_at, items.fetched_at) DESC';
    if (profile) {
      const pid = ph(profile.id);
      const pver = ph(profile.profile_version);
      relJoin = `LEFT JOIN item_relevance ir
                   ON ir.item_id = items.id AND ir.profile_id = ${pid} AND ir.profile_version = ${pver}`;
      relSelect = "COALESCE(ir.tier, 'not_yours') AS rel_tier, COALESCE(ir.matches, '[]'::jsonb) AS rel_matches";
      // Rank, don't hide — opt-in only.
      if (req.query.relevantOnly === '1') where.push("COALESCE(ir.tier, 'not_yours') IN ('act_now','watch')");
      orderBy = `ORDER BY CASE COALESCE(ir.tier, 'not_yours')
                   WHEN 'act_now' THEN 0 WHEN 'watch' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                 COALESCE(ir.score, 0) DESC,
                 COALESCE(items.published_at, items.fetched_at) DESC`;
    }

    const whereSql = where.join(' AND ');
    const total = (await store.get(
      `SELECT COUNT(*)::int AS c FROM items JOIN sources ON sources.id = items.source_id ${relJoin} WHERE ${whereSql}`,
      params)).c;
    const lim = Math.min(Number(limit) || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const rows = await store.all(`
      SELECT items.*, sources.name AS source_name, sources.tier AS source_tier,
             cl.id AS cluster_id, COALESCE(cl.source_count, 1) AS source_count,
             ${relSelect}
      FROM items
      JOIN sources ON sources.id = items.source_id
      LEFT JOIN clusters cl ON cl.primary_item_id = items.id
      ${relJoin}
      WHERE ${whereSql}
      ${orderBy}
      LIMIT ${ph(lim)} OFFSET ${ph(offset)}
    `, params);

    for (const row of rows) {
      row.relevance = profile ? { tier: row.rel_tier, matches: row.rel_matches } : null;
      delete row.rel_tier;
      delete row.rel_matches;
    }
    // Total lives in a header so the body stays a bare array (stable contract); the
    // CORS layer exposes X-Total-Count so a cross-origin Angular grid can read it.
    res.setHeader('X-Total-Count', total);
    res.json(rows);
  }));

  app.get('/api/clusters/:id/items', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (id === null) return res.status(404).json({ error: 'not found' });
    const cluster = await store.get('SELECT id FROM clusters WHERE id = $1', [id]);
    if (!cluster) return res.status(404).json({ error: 'not found' });
    const rows = await store.all(`
      SELECT items.id AS item_id, items.title, items.published_at,
             sources.id AS source_id, sources.name AS source_name, sources.last_status AS source_status
      FROM cluster_items ci
      JOIN items ON items.id = ci.item_id
      JOIN sources ON sources.id = items.source_id
      WHERE ci.cluster_id = $1
      ORDER BY items.published_at DESC NULLS LAST
    `, [id]);
    res.json(rows);
  }));

  app.get('/api/items/:id', h(async (req, res) => {
    const id = parseId(req.params.id);
    const item = id && await store.get(`
      SELECT items.*, sources.name AS source_name, sources.tier AS source_tier, sources.url AS source_url
      FROM items JOIN sources ON sources.id = items.source_id
      WHERE items.id = $1
    `, [id]);
    if (!item) return res.status(404).json({ error: 'not found' });
    // Drill-down (the demo's headline feature) needs the associated entities, not just
    // the flat row. Embed each child collection so a detail view has one source of truth.
    const cves = (await store.all('SELECT cve_id FROM item_cves WHERE item_id = $1', [id])).map((r) => r.cve_id);
    const iocs = await store.all('SELECT ioc_type AS type, ioc_value AS value FROM item_iocs WHERE item_id = $1', [id]);
    const actors = (await store.all('SELECT actor FROM item_actors WHERE item_id = $1', [id])).map((r) => r.actor);
    const families = (await store.all('SELECT family FROM item_malware_families WHERE item_id = $1', [id])).map((r) => r.family);
    const domains = (await store.all('SELECT domain FROM item_domains WHERE item_id = $1', [id])).map((r) => r.domain);
    const ipIntel = {};
    for (const io of iocs) {
      if (io.type === 'ip' && !ipIntel[io.value]) {
        const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', [io.value]);
        if (row) ipIntel[io.value] = decodeIpIntel(row);
      }
    }
    let raw = null;
    if (item.raw_json) { try { raw = JSON.parse(item.raw_json); } catch { raw = null; } }
    res.json({ ...item, raw, cves, iocs, actors, families, domains, ip_intel: ipIntel });
  }));

  app.get('/api/ip-intel/:ip', h(async (req, res) => {
    const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', [req.params.ip]);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json(decodeIpIntel(row));
  }));

  app.get('/api/ioc-check', h(async (req, res) => {
    const url = (req.query.url || '').trim();
    if (!url) return res.status(400).json({ error: 'url required' });
    // Compare scheme/trailing-slash-normalized on both sides — same rule normalizeUrl()
    // applies in JS, expressed in SQL so it runs against the stored (unmodified) ioc_value.
    const matches = await store.all(`
      SELECT items.id AS "itemId", items.title, items.category, items.published_at AS "publishedAt",
             sources.name AS "sourceName"
      FROM item_iocs
      JOIN items ON items.id = item_iocs.item_id
      JOIN sources ON sources.id = items.source_id
      WHERE item_iocs.ioc_type = 'url'
        AND regexp_replace(regexp_replace(item_iocs.ioc_value, '^https?://', '', 'i'), '/+$', '') = $1
      ORDER BY items.published_at DESC
    `, [normalizeUrl(url)]);
    res.json({ url, found: matches.length > 0, matches });
  }));

  // Does this page allow itself to be framed? Asked before the UI creates a preview iframe,
  // because the browser gives script no way to find out afterwards: a site refusing to be
  // framed renders the browser's own error document inside the frame and still fires `load`,
  // so a refusal and a successful render look identical from the outside.
  //
  // Restricted to links belonging to an RSS item, mirroring the UI's own rule for offering the
  // preview at all (tf-browser-window's allowExpand). Two reasons, both load-bearing: without
  // it this is a general-purpose fetch proxy sitting behind the SSRF guard, and item links from
  // the abuse.ch/phishing feeds ARE live malicious URLs — nothing here should be dereferencing
  // those server-side just because someone passed one in.
  app.get('/api/preview-check', h(async (req, res) => {
    const url = (req.query.url || '').trim();
    if (!url) return res.status(400).json({ error: 'url required' });
    const known = await store.get(`
      SELECT 1 FROM items
      JOIN sources ON sources.id = items.source_id
      WHERE items.link = $1 AND sources.fetch_kind = 'rss'
      LIMIT 1
    `, [url]);
    if (!known) return res.status(404).json({ error: 'not a previewable item link' });
    try {
      await assertSafeUrl(url);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    // The viewer's own origin decides SAMEORIGIN / 'self' / host-source matches.
    const viewerOrigin = req.headers.origin || CORS_ORIGINS[0];
    let upstream;
    try {
      // GET, not HEAD: plenty of sites answer HEAD without the security headers they attach to
      // a real page render, and a verdict from headers the browser would never see is worse
      // than no verdict. The body is discarded.
      upstream = await safeRequest(url, { method: 'GET', timeoutMs: 8000 });
    } catch (err) {
      return res.json({ url, frameable: false, reason: 'unreachable', detail: err.message });
    }
    if (upstream.status >= 400) {
      return res.json({ url, status: upstream.status, frameable: false, reason: 'http-error', detail: `upstream returned ${upstream.status}` });
    }
    res.json({ url, status: upstream.status, ...frameVerdict(upstream.headers, { viewerOrigin, targetUrl: url }) });
  }));

  app.get('/api/domains', h(async (req, res) => {
    const rows = await store.all('SELECT domain, COUNT(*)::int AS c FROM item_domains GROUP BY domain');
    const counts = new Map(rows.map((r) => [r.domain, r.c]));
    res.json(DOMAINS.map((d) => ({ ...d, count: counts.get(d.slug) || 0 })));
  }));

  app.get('/api/facets', h(async (req, res) => {
    const distinct = async (sql) => (await store.all(sql)).map((r) => r.v).filter(Boolean);
    res.json({
      vendors: await distinct("SELECT DISTINCT vendor v FROM items WHERE vendor IS NOT NULL ORDER BY v LIMIT 100"),
      regions: await distinct("SELECT DISTINCT region v FROM items WHERE region IS NOT NULL ORDER BY v LIMIT 100"),
      actors: await distinct("SELECT DISTINCT actor v FROM item_actors ORDER BY v LIMIT 100"),
      families: await distinct("SELECT DISTINCT family v FROM item_malware_families ORDER BY v LIMIT 100"),
    });
  }));

  app.get('/api/stats', h(async (req, res) => {
    const total = (await store.get('SELECT COUNT(*)::int AS c FROM items')).c;
    const byCategory = await store.all('SELECT category, COUNT(*)::int AS c FROM items GROUP BY category ORDER BY c DESC');
    const recentCves = await store.all(`
      SELECT items.*, sources.name AS source_name FROM items JOIN sources ON sources.id = items.source_id
      WHERE items.category = 'cve' ORDER BY COALESCE(items.published_at, items.fetched_at) DESC LIMIT 10
    `);
    const recentNews = await store.all(`
      SELECT items.*, sources.name AS source_name FROM items JOIN sources ON sources.id = items.source_id
      WHERE items.category IN ('news', 'advisory', 'osint') ORDER BY COALESCE(items.published_at, items.fetched_at) DESC LIMIT 10
    `);
    const health = await store.get(`
      SELECT
        COUNT(*) FILTER (WHERE active)::int AS active_count,
        COUNT(*) FILTER (WHERE last_status LIKE 'error:%')::int AS error_count,
        COUNT(*) FILTER (WHERE last_status = 'unsupported')::int AS unsupported_count,
        COUNT(*) FILTER (WHERE last_synced_at IS NULL)::int AS never_synced_count,
        COUNT(*)::int AS total_sources
      FROM sources
    `);
    const topSources = await store.all(`
      SELECT sources.id, sources.name, COUNT(items.id)::int AS item_count
      FROM sources LEFT JOIN items ON items.source_id = sources.id
      GROUP BY sources.id ORDER BY item_count DESC LIMIT 5
    `);
    const byDomain = await store.all('SELECT domain, COUNT(*)::int AS c FROM item_domains GROUP BY domain ORDER BY c DESC');
    const byExploitation = await store.all("SELECT COALESCE(exploitation_status,'unknown') AS status, COUNT(*)::int AS c FROM items GROUP BY COALESCE(exploitation_status,'unknown')");

    res.json({ total, byCategory, recentCves, recentNews, health, topSources, byDomain, byExploitation });
  }));

  app.get('/api/stats/dashboard', h(async (req, res) => {
    res.json(await dashboardStats(store));
  }));

  app.get('/api/sources/:id/stats', h(async (req, res) => {
    const stats = await sourceStats(store, req.params.id);
    if (!stats) return res.status(404).json({ error: 'not found' });
    res.json(stats);
  }));

  app.get('/api/cves', h(async (req, res) => {
    const { rows, total } = await listCves(store, {
      q: req.query.q,
      severity: req.query.severity,
      kevOnly: req.query.kev === 'true',
      minCvss: req.query.min_cvss,
      minEpss: req.query.min_epss,
      limit: req.query.limit,
      offset: req.query.offset,
    });
    res.set('X-Total-Count', String(total));
    res.json(rows);
  }));

  app.get('/api/cves/:cveId', h(async (req, res) => {
    const detail = await cveDetail(store, String(req.params.cveId).toUpperCase());
    if (!detail) return res.status(404).json({ error: 'not found' });
    res.json(detail);
  }));

  app.get('/api/actors/:name', h(async (req, res) => {
    const profile = await entityProfile(store, 'actor', req.params.name);
    if (!profile) return res.status(404).json({ error: 'not found' });
    res.json(profile);
  }));

  app.get('/api/malware/:family', h(async (req, res) => {
    const profile = await entityProfile(store, 'family', req.params.family);
    if (!profile) return res.status(404).json({ error: 'not found' });
    res.json(profile);
  }));

  app.get('/api/feed', h(async (req, res) => {
    res.json(await feed(store, { since: req.query.since, limit: req.query.limit }));
  }));

  app.get('/api/search', h(async (req, res) => {
    const q = String(req.query.q || '').trim();
    if (q.length < 2) return res.json({ items: [], cves: [], actors: [], families: [], sources: [] });
    res.json(await search(store, q, req.query.limit));
  }));

  app.get('/api/export/iocs', h(async (req, res) => {
    // Same filter set GET /api/items supports, so the export always covers exactly what the
    // explorer's current filters show (not just source_id/category/type, which used to be all
    // that was honored here).
    const rows = await iocRows(store, {
      source_id: req.query.source_id, category: req.query.category, type: req.query.type,
      q: req.query.q, domain: req.query.domain, actor: req.query.actor,
      malware_family: req.query.malware_family, cve: req.query.cve,
      severity: req.query.severity, exploitation_status: req.query.exploitation_status,
      vendor: req.query.vendor, region: req.query.region, industry: req.query.industry,
      min_confidence: req.query.min_confidence,
    });
    // format=json backs "Copy all IOCs" (clipboard) — the CSV is properly RFC-4180 quoted, so
    // rather than have the frontend parse quoted CSV back apart it can ask for the same rows
    // straight as JSON. Both variants share the one iocRows() call/filter set above.
    if (req.query.format === 'json') return res.json(rows);
    // Quote every field and double embedded quotes — IOC values legitimately contain commas.
    const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    const csv = ['type,value,item_id,source,first_seen']
      .concat(rows.map((r) => [r.type, r.value, r.itemId, r.sourceName, r.firstSeen].map(esc).join(',')))
      .join('\n');
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', 'attachment; filename="threatflow-iocs.csv"');
    res.send(csv);
  }));

  return app;
}

// Run directly: apply schema, seed, then listen.
if (require.main === module) {
  const store = require('./db');
  (async () => {
    await store.applySchema();
    await seedFromConfig();
    const app = createApp(store);
    const PORT = process.env.PORT || 4173;
    // No auth layer (single-user local demo, see spec) - bind to loopback only so the
    // unauthenticated /api/sources* routes aren't reachable from the network.
    app.listen(PORT, '127.0.0.1', () => {
      console.log(`ThreatFlow demo listening on http://localhost:${PORT}`);
    });
    startScheduler(store, CONFIG_BY_NAME);
  })().catch((err) => {
    console.error('startup failed:', err);
    process.exit(1);
  });
}

module.exports = { createApp };
