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
const { remediationFor } = require('./remediation');
const { generateProse } = require('./relevance_prose');
const { generatePlaybookProse } = require('./playbook_prose');
const { linkStories } = require('./story_links_batch');
const { similarityLabel } = require('./story_links');

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

  // No DB round-trip on purpose: the frontend's health poll (shell.component.ts) only needs to
  // know the process itself is up and accepting connections. A dependency check here would be
  // redundant anyway — a stuck applySchema()/seedFromConfig() blocks app.listen() from ever
  // being reached at all, so the whole process (this route included) is unreachable regardless.
  app.get('/api/health', (req, res) => res.json({ ok: true }));

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

  // Separate from the deterministic recompute on purpose: this one needs Ollama, takes minutes
  // rather than a second, and its failure must never look like a scoring failure.
  app.post('/api/profiles/:id/relevance/prose', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });
    generateProse(store, id).catch(() => {});
    res.status(202).json({ started: true, profileVersion: profile.profile_version });
  }));

  app.post('/api/profiles/:id/relevance/recompute', h(async (req, res) => {
    const id = parseId(req.params.id);
    const result = id && await recomputeProfile(store, id);
    if (!result) return res.status(404).json({ error: 'not found' });
    res.status(202).json(result);
  }));

  // Self-report from the Check URL page: "I clicked this." Recomputes synchronously (unlike the
  // background profile-edit path above) because the reader is on the page waiting to be told
  // where the playbook is — a full corpus recompute is well under a second, so there's nothing
  // to gain by backgrounding it here.
  app.post('/api/profiles/:id/clicks/:itemId', h(async (req, res) => {
    const id = parseId(req.params.id);
    const itemId = parseId(req.params.itemId);
    if (!id || !itemId) return res.status(404).json({ error: 'not found' });
    const profile = await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });
    const item = await store.get('SELECT id FROM items WHERE id = $1', [itemId]);
    if (!item) return res.status(404).json({ error: 'not found' });
    await store.run(
      'INSERT INTO profile_reported_clicks (profile_id, item_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [id, itemId]);
    res.status(200).json(await recomputeProfile(store, id));
  }));

  // Undoes a click report — same posture as declining a version answer: the reader is never
  // trapped in a claim they can't retract.
  app.delete('/api/profiles/:id/clicks/:itemId', h(async (req, res) => {
    const id = parseId(req.params.id);
    const itemId = parseId(req.params.itemId);
    if (!id || !itemId) return res.status(404).json({ error: 'not found' });
    const profile = await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });
    await store.run(
      'DELETE FROM profile_reported_clicks WHERE profile_id = $1 AND item_id = $2', [id, itemId]);
    res.status(200).json(await recomputeProfile(store, id));
  }));

  // Mirrors /relevance/prose: needs Ollama, runs in the background, its failure never looks
  // like a scoring failure. Rewords item_playbooks.steps[].detail only.
  app.post('/api/profiles/:id/playbooks/word', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });
    generatePlaybookProse(store, id).catch(() => {});
    res.status(202).json({ started: true, profileVersion: profile.profile_version });
  }));

  // The remediation queue: one entry per asset the profile has told us about, each carrying its
  // open (act_now/watch) threats and what remediationFor says about each. Grouping happens here
  // rather than in relevance.js because an item can match more than one asset (e.g. two Windows
  // builds vulnerable to the same CVE) and the queue's whole point is "group by the thing you'd
  // actually go fix" — recomputeProfile's own per-item asset pick (for consequence/playbook
  // wording) only ever keeps one, which is the wrong shape for this page.
  app.get('/api/profiles/:id/remediation', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });

    const rows = await store.all(`
      SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState",
             i.id AS "itemId", i.title, i.cvss_version AS "cvssVersion", ir.tier, ir.score, ir.consequence,
             ci.affected_versions AS "affectedVersions", ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
             ci.cve_id AS "cveId", ci.cvss_score AS "cvssScore", ci.severity,
             ci.kev_listed AS "kevListed", to_char(ci.kev_due_date, 'YYYY-MM-DD') AS "kevDueDate", ci.kev_ransomware AS "kevRansomware",
             ci.source_count AS "sourceCount",
             ip.steps
        FROM profile_assets pa
        JOIN item_cpes c ON c.vendor = pa.vendor AND c.product = pa.product
        JOIN item_relevance ir ON ir.item_id = c.item_id AND ir.profile_id = pa.profile_id
                               AND ir.profile_version = $2 AND ir.tier IN ('act_now','watch')
        JOIN items i ON i.id = ir.item_id
        LEFT JOIN LATERAL (
          SELECT ci2.* FROM item_cves icv JOIN cve_intel ci2 ON ci2.cve_id = icv.cve_id
           WHERE icv.item_id = i.id
           ORDER BY ci2.kev_listed DESC, ci2.cvss_score DESC NULLS LAST LIMIT 1
        ) ci ON true
        LEFT JOIN item_playbooks ip ON ip.item_id = i.id AND ip.profile_id = pa.profile_id AND ip.profile_version = $2
       WHERE pa.profile_id = $1
       ORDER BY pa.vendor, pa.product, ir.score DESC
    `, [profile.id, profile.profile_version]);

    const groups = new Map();
    for (const r of rows) {
      const key = `${r.vendor}/${r.product}`;
      if (!groups.has(key)) {
        groups.set(key, {
          vendor: r.vendor, product: r.product, exposure: r.exposure,
          version: r.version, versionState: r.versionState, items: [],
        });
      }
      const asset = { vendor: r.vendor, product: r.product, exposure: r.exposure, version: r.version, versionState: r.versionState };
      const rem = remediationFor(asset, r.affectedVersions || [], { patchUrl: r.patchUrl, advisoryUrl: r.advisoryUrl }, r.steps || []);
      const dueDate = (r.consequence && r.consequence.urgency && r.consequence.urgency.due) || null;
      groups.get(key).items.push({
        itemId: r.itemId, title: r.title, tier: r.tier, score: r.score, dueDate,
        patchUrl: r.patchUrl || null,
        // cveId/cvssScore/severity/kev*/sourceCount all come from the same LATERAL cve_intel
        // join patchUrl already reads — zero new joins. cvssVersion has no home in cve_intel so
        // it reads the item's own column instead; it may not describe the same source
        // cvssScore/severity were consolidated from when this item isn't cve_intel's own
        // tier-winning source for the CVE.
        cveId: r.cveId || null,
        cvssScore: r.cvssScore ?? null,
        cvssVersion: r.cvssVersion || null,
        severity: r.severity || null,
        kevListed: !!r.kevListed,
        kevDueDate: r.kevDueDate || null,
        kevRansomware: !!r.kevRansomware,
        sourceCount: r.sourceCount ?? 0,
        ...rem,
      });
    }
    res.json([...groups.values()]);
  }));

  // Category-playbook items (phishing today) have no CPEs, so they can never join through
  // profile_assets the way the route above requires — this is their own dashboard path, grouped
  // by category rather than vendor/product.
  //
  // A playbook's steps come from the CVE builder (server/playbook.js) whenever the item carries
  // a CVE or CVSS vector at all — regardless of the item's OWN `category` column. A 'news' or
  // 'malware' item reporting on a specific CVE still gets the CVE-shaped playbook, not the
  // category one, so filtering on `category <> 'cve'` alone is not enough (verified against real
  // data: news/malware/advisory items about a CVE leaked into this route under their own
  // category). The real discriminator is the step keys themselves: server/playbooks/*.js's
  // builders namespace every key (`phishing:confirm`), the CVE builder never does (`confirm`,
  // `patch`) — the same fact core/playbook.ts's groundingFooter() already relies on to tell the
  // two apart client-side.
  app.get('/api/profiles/:id/remediation/categories', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });

    const rows = await store.all(`
      SELECT i.id AS "itemId", i.title, i.category, ir.tier, ir.score, ip.steps,
             COALESCE(ds.done_keys, '{}') AS "doneKeys"
        FROM item_relevance ir
        JOIN items i ON i.id = ir.item_id
        JOIN item_playbooks ip ON ip.item_id = i.id AND ip.profile_id = ir.profile_id
                               AND ip.profile_version = ir.profile_version
        LEFT JOIN LATERAL (
          SELECT array_agg(step_key) AS done_keys FROM playbook_step_state
           WHERE item_id = i.id AND profile_id = ir.profile_id
        ) ds ON true
       WHERE ir.profile_id = $1 AND ir.profile_version = $2 AND ir.tier IN ('act_now','watch')
         AND jsonb_array_length(ip.steps) > 0
         AND (ip.steps->0->>'key') LIKE '%:%'
         AND NOT EXISTS (
           SELECT 1 FROM item_cpes c JOIN profile_assets pa
             ON pa.vendor = c.vendor AND pa.product = c.product
            WHERE c.item_id = i.id AND pa.profile_id = ir.profile_id
         )
       ORDER BY i.category, ir.score DESC
    `, [profile.id, profile.profile_version]);

    const groups = new Map();
    for (const r of rows) {
      if (!groups.has(r.category)) groups.set(r.category, { category: r.category, items: [] });
      const steps = r.steps || [];
      const stepKeys = new Set(steps.map((s) => s.key));
      const playbookDone = (r.doneKeys || []).filter((k) => stepKeys.has(k)).length;
      groups.get(r.category).items.push({
        itemId: r.itemId, title: r.title, category: r.category, tier: r.tier, score: r.score,
        playbookDone, playbookTotal: steps.length,
      });
    }
    res.json([...groups.values()]);
  }));

  // Per-item remediation detail. remediation is null when no profile_assets row matches the
  // item's CPEs — the same "no data, not a guess" posture as relevance/playbook already use for
  // an item with no CVE.
  app.get('/api/items/:id/remediation', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(404).json({ error: 'not found' });
    const profile = await resolveProfile(req);
    if (!profile) return res.status(400).json({ error: 'X-Profile-Id required' });

    const item = await store.get('SELECT * FROM items WHERE id = $1', [id]);
    if (!item) return res.status(404).json({ error: 'not found' });

    const rel = await store.get(
      'SELECT tier, matches, consequence FROM item_relevance WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [id, profile.id, profile.profile_version]);
    // Same query GET /api/items/:id already runs — without it, every reload of the guided page
    // (Step 2's version submit and Step 4's version-bump confirmation both re-fetch this route)
    // would render every step as unticked again, even though the rows are still there.
    const pbDone = pb
      ? (await store.all(
          'SELECT step_key FROM playbook_step_state WHERE item_id = $1 AND profile_id = $2',
          [id, profile.id])).map((r) => r.step_key)
      : [];
    const ci = await store.get(
      `SELECT ci.cve_id AS "cveId", ci.affected_versions AS "affectedVersions",
              ci.patch_url AS "patchUrl", ci.advisory_url AS "advisoryUrl",
              ci.cvss_score AS "cvssScore", ci.severity,
              ci.kev_listed AS "kevListed", to_char(ci.kev_due_date, 'YYYY-MM-DD') AS "kevDueDate", ci.kev_ransomware AS "kevRansomware",
              ci.source_count AS "sourceCount"
         FROM item_cves ic JOIN cve_intel ci ON ci.cve_id = ic.cve_id WHERE ic.item_id = $1
        ORDER BY ci.kev_listed DESC, ci.cvss_score DESC NULLS LAST LIMIT 1`, [id]);

    // The asset whose exposure ranks highest among those matching this item's CPEs — same
    // priority order relevance_score.js's EXPOSURE_RANK already uses (internet > unknown >
    // internal) to pick which exposure decides the tier, reused here so this read-time pick
    // agrees with what actually drove the item's own scoring.
    const asset = await store.get(
      `SELECT pa.vendor, pa.product, pa.exposure, pa.version, pa.version_state AS "versionState"
         FROM profile_assets pa JOIN item_cpes c ON c.vendor = pa.vendor AND c.product = pa.product
        WHERE pa.profile_id = $1 AND c.item_id = $2
        ORDER BY CASE pa.exposure WHEN 'internet' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END DESC
        LIMIT 1`, [profile.id, id]);

    const remediation = asset
      ? remediationFor(asset, (ci && ci.affectedVersions) || [], ci || {}, (pb && pb.steps) || [])
      : null;

    res.json({
      item,
      relevance: rel ? { tier: rel.tier, matches: rel.matches, consequence: rel.consequence } : null,
      playbook: pb ? { steps: pb.steps, done: pbDone } : null,
      remediation,
      // The asset the reader would write a version onto (Spec B's Step 2/Step 4 forms both PATCH
      // /api/profiles/:id/assets/:vendor/:product) — the route already resolves this row for
      // remediationFor above; this just also returns it, since remediation itself carries no
      // vendor/product (entry.vendor/product only exist when affected_versions matched).
      asset: asset ? { vendor: asset.vendor, product: asset.product, exposure: asset.exposure } : null,
      // Sibling of `remediation`, never inside `fix` — `ci` (fetched above for remediationFor's
      // own cveIntel argument) already carries this. Lets Step 3 show a vendor patch link
      // beneath a kind: 'version' fix without widening fixTarget's own return shape.
      patchUrl: (ci && ci.patchUrl) || null,
      // Same eight additive fields as the queue route, same reasoning: six from the cve_intel
      // row already fetched above for remediationFor's own cveIntel argument, cvssVersion from
      // the item row's own column instead (cve_intel carries no version).
      cveId: (ci && ci.cveId) || null,
      cvssScore: (ci && ci.cvssScore) ?? null,
      cvssVersion: item.cvss_version || null,
      severity: (ci && ci.severity) || null,
      kevListed: !!(ci && ci.kevListed),
      kevDueDate: (ci && ci.kevDueDate) || null,
      kevRansomware: !!(ci && ci.kevRansomware),
      sourceCount: (ci && ci.sourceCount) ?? 0,
    });
  }));

  // Records a version on one asset. Goes through profiles.updateProfile's own transaction (it
  // deletes and rewrites the whole asset set on every save) rather than a bespoke single-row
  // UPDATE — a direct UPDATE would be silently discarded by the next profile save, and
  // duplicating the version-bump/recompute logic in a second place is how the two drift apart.
  app.patch('/api/profiles/:id/assets/:vendor/:product', h(async (req, res) => {
    const id = parseId(req.params.id);
    const profile = id && await profiles.getProfile(store, id);
    if (!profile) return res.status(404).json({ error: 'not found' });

    const { vendor, product } = req.params;
    const idx = (profile.assets || []).findIndex((a) => a.vendor === vendor && a.product === product);
    if (idx === -1) return res.status(404).json({ error: 'not found' });

    // An explicit versionState always wins. Otherwise it's inferred from whether a version was
    // actually given — never defaulted to 'unset', because 'unset' means "never asked", and a
    // PATCH to this endpoint is proof someone was. A version with no state would otherwise be
    // stored and then silently ignored: remediationFor only reads asset.version when
    // versionState === 'known', so a bare {"version":"7.4.5"} would 200 and change nothing —
    // exactly the reassuring-direction failure this feature exists to avoid.
    const version = req.body.version ?? null;
    const versionState = req.body.versionState ?? (version ? 'known' : 'unknown');

    const nextAssets = profile.assets.map((a, i) => (i === idx ? { ...a, version, versionState } : a));

    // getProfile() returns the raw `profiles` row (snake_case: threat_domains, severity_floor).
    // validateProfile()/updateProfile() read camelCase input. Mapped explicitly here — a plain
    // { ...profile, assets: nextAssets } spread would leave threatDomains/severityFloor
    // undefined and validateProfile would silently default them to []/'medium', wiping both
    // on every version write.
    const input = {
      name: profile.name, sector: profile.sector, vendors: profile.vendors, products: profile.products,
      threatDomains: profile.threat_domains, region: profile.region, severityFloor: profile.severity_floor,
      assets: nextAssets,
    };

    let updated;
    try {
      updated = await profiles.updateProfile(store, id, input);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    if (!updated) return res.status(404).json({ error: 'not found' });

    // Synchronous, unlike PUT /api/profiles/:id's background recompute: the whole point of this
    // route (Spec B) is that the caller immediately asks "what did that change?", so the
    // response must reflect the new profile_version's verdicts, not the stale ones. The
    // recompute is ~1.3s over the full corpus — not an optimization to skip, per the spec.
    await recomputeProfile(store, updated.id);

    const savedAsset = updated.assets.find((a) => a.vendor === vendor && a.product === product);
    res.json(savedAsset);
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
    // Story linking runs after consolidation because it reads the cluster set rebuildClusters()
    // has just produced. It is deliberately outside the consolidate() transaction chain and its
    // own try/catch: it is the only part of this route that needs Ollama, and an unreachable
    // model must cost suggestion links and nothing else.
    if (consolidation) linkStories(store).catch(() => {});
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
    // Model-assigned signal quality. Demotion only: a non-intel verdict costs an item its
    // place in the ordering and nothing else — it stays in the results, stays searchable, and
    // stays one click away. A misclassification must never make something disappear.
    const qualityJoin = 'LEFT JOIN item_quality iq ON iq.item_id = items.id';
    const demotionRank = "CASE WHEN iq.verdict IN ('roundup','commentary','promotion') THEN 1 ELSE 0 END";

    let relJoin = '';
    let relSelect = 'NULL::text AS rel_tier, NULL::jsonb AS rel_matches, NULL::text AS rel_sentence, '
      + 'NULL::jsonb AS rel_consequence';
    let orderBy = `ORDER BY ${demotionRank}, COALESCE(items.published_at, items.fetched_at) DESC`;
    if (profile) {
      const pid = ph(profile.id);
      const pver = ph(profile.profile_version);
      relJoin = `LEFT JOIN item_relevance ir
                   ON ir.item_id = items.id AND ir.profile_id = ${pid} AND ir.profile_version = ${pver}
                 LEFT JOIN item_relevance_prose irp
                   ON irp.item_id = items.id AND irp.profile_id = ${pid} AND irp.profile_version = ${pver}`;
      relSelect = "COALESCE(ir.tier, 'not_yours') AS rel_tier, COALESCE(ir.matches, '[]'::jsonb) AS rel_matches, "
        + 'irp.sentence AS rel_sentence, ir.consequence AS rel_consequence';
      // Rank, don't hide — opt-in only.
      if (req.query.relevantOnly === '1') where.push("COALESCE(ir.tier, 'not_yours') IN ('act_now','watch')");
      // Personal relevance is the primary axis; quality only breaks ties beneath it. An
      // act_now item still leads even if the classifier called it promotional.
      orderBy = `ORDER BY CASE COALESCE(ir.tier, 'not_yours')
                   WHEN 'act_now' THEN 0 WHEN 'watch' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                 ${demotionRank},
                 COALESCE(ir.score, 0) DESC,
                 COALESCE(items.published_at, items.fetched_at) DESC`;
    }

    const whereSql = where.join(' AND ');
    const total = (await store.get(
      `SELECT COUNT(*)::int AS c FROM items JOIN sources ON sources.id = items.source_id ${relJoin} ${qualityJoin} WHERE ${whereSql}`,
      params)).c;
    const lim = Math.min(Number(limit) || 50, 200);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const rows = await store.all(`
      SELECT items.*, sources.name AS source_name, sources.tier AS source_tier,
             cl.id AS cluster_id, COALESCE(cl.source_count, 1) AS source_count,
             ${relSelect}, iq.verdict AS quality_verdict
      FROM items
      JOIN sources ON sources.id = items.source_id
      LEFT JOIN clusters cl ON cl.primary_item_id = items.id
      ${relJoin}
      ${qualityJoin}
      WHERE ${whereSql}
      ${orderBy}
      LIMIT ${ph(lim)} OFFSET ${ph(offset)}
    `, params);

    for (const row of rows) {
      // `sentence` is the model's wording and is null whenever it has not been written — the
      // frontend falls back to the templated sentence built from `matches`, so an unreachable
      // Ollama degrades the phrasing and nothing else.
      // `consequence` is null for a row written before the column existed, or for an item the
      // recompute has not reached yet. The panel renders that as a stated gap, not a blank.
      row.relevance = profile
        ? {
          tier: row.rel_tier,
          matches: row.rel_matches,
          sentence: row.rel_sentence ?? null,
          consequence: row.rel_consequence ?? null,
          exposure: row.rel_consequence?.exposure ?? 'unknown',
        }
        : null;
      row.quality = row.quality_verdict ? { verdict: row.quality_verdict } : null;
      delete row.rel_tier;
      delete row.rel_matches;
      delete row.rel_sentence;
      delete row.rel_consequence;
      delete row.quality_verdict;
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
      SELECT items.*, sources.name AS source_name, sources.tier AS source_tier, sources.url AS source_url,
             sources.fetch_kind AS source_fetch_kind, sources.last_status AS source_status
      FROM items JOIN sources ON sources.id = items.source_id
      WHERE items.id = $1
    `, [id]);
    if (!item) return res.status(404).json({ error: 'not found' });

    // Same shape GET /api/items builds per row — the detail page gets nothing "for free" from
    // that endpoint, so without this a single item's relevance/quality never reaches the page
    // that has room to actually show it (rather than a hover-only badge in the dense list).
    const profile = await resolveProfile(req);
    let relevance = null;
    if (profile) {
      const rel = await store.get(
        'SELECT tier, matches, consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
        [id, profile.id, profile.profile_version]);
      const prose = await store.get(
        'SELECT sentence FROM item_relevance_prose WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
        [id, profile.id, profile.profile_version]);
      relevance = {
        tier: rel?.tier ?? 'not_yours',
        matches: rel?.matches ?? [],
        sentence: prose?.sentence ?? null,
        consequence: rel?.consequence ?? null,
        exposure: rel?.consequence?.exposure ?? 'unknown',
      };
    }
    let playbook = null;
    if (profile) {
      const pb = await store.get(
        'SELECT steps FROM item_playbooks WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
        [id, profile.id, profile.profile_version]);
      if (pb) {
        const done = (await store.all(
          'SELECT step_key FROM playbook_step_state WHERE item_id = $1 AND profile_id = $2',
          [id, profile.id]
        )).map((r) => r.step_key);
        playbook = { steps: pb.steps, done };
      }
    }
    const quality = await store.get('SELECT verdict FROM item_quality WHERE item_id = $1', [id]);
    // Drill-down (the demo's headline feature) needs the associated entities, not just
    // the flat row. Embed each child collection so a detail view has one source of truth.
    const cves = (await store.all('SELECT cve_id FROM item_cves WHERE item_id = $1', [id])).map((r) => r.cve_id);
    const iocs = await store.all('SELECT ioc_type AS type, ioc_value AS value FROM item_iocs WHERE item_id = $1', [id]);
    const actors = (await store.all('SELECT actor FROM item_actors WHERE item_id = $1', [id])).map((r) => r.actor);
    const families = (await store.all('SELECT family FROM item_malware_families WHERE item_id = $1', [id])).map((r) => r.family);
    const domains = (await store.all('SELECT domain FROM item_domains WHERE item_id = $1', [id])).map((r) => r.domain);
    const cwes = (await store.all('SELECT cwe_id FROM item_cwes WHERE item_id = $1', [id])).map((r) => r.cwe_id);
    const ipIntel = {};
    for (const io of iocs) {
      if (io.type === 'ip' && !ipIntel[io.value]) {
        const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', [io.value]);
        if (row) ipIntel[io.value] = decodeIpIntel(row);
      }
    }
    let raw = null;
    if (item.raw_json) { try { raw = JSON.parse(item.raw_json); } catch { raw = null; } }

    // Only a cluster primary can carry related stories: story_links pairs clusters, and a
    // non-primary member is a duplicate of its primary rather than a story in its own right.
    // The cluster id travels with the count so the detail page can follow it to
    // /api/clusters/:id/related without a second lookup.
    const cluster = await store.get(`
      SELECT cl.id,
             (SELECT COUNT(*)::int FROM story_links sl
               WHERE sl.cluster_a_id = cl.id OR sl.cluster_b_id = cl.id) AS related_count
        FROM clusters cl
       WHERE cl.primary_item_id = $1`, [id]);

    res.json({
      ...item, raw, cves, iocs, actors, families, domains, cwes, ip_intel: ipIntel,
      clusterId: cluster ? cluster.id : null,
      relatedStoryCount: cluster ? cluster.related_count : 0,
      relevance,
      playbook,
      quality: quality ? { verdict: quality.verdict } : null,
    });
  }));

  // Step routes take the profile from X-Profile-Id, like every other profile-scoped route.
  // An unknown step_key is a caller error (a stale key from a superseded skeleton, or a typo),
  // not a database write — storing a tick against a step that does not exist would be
  // unreachable dead data.
  app.post('/api/items/:id/playbook/steps/:key', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(404).json({ error: 'not found' });
    const profile = await resolveProfile(req);
    if (!profile) return res.status(400).json({ error: 'X-Profile-Id required' });

    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
      [id, profile.id, profile.profile_version]);
    if (!pb || !pb.steps.some((s) => s.key === req.params.key)) {
      return res.status(404).json({ error: 'not found' });
    }

    await store.run(
      `INSERT INTO playbook_step_state (profile_id, item_id, step_key) VALUES ($1,$2,$3)
       ON CONFLICT (profile_id, item_id, step_key) DO NOTHING`,
      [profile.id, id, req.params.key]);
    res.status(204).end();
  }));

  app.delete('/api/items/:id/playbook/steps/:key', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(404).json({ error: 'not found' });
    const profile = await resolveProfile(req);
    if (!profile) return res.status(400).json({ error: 'X-Profile-Id required' });

    await store.run(
      'DELETE FROM playbook_step_state WHERE profile_id = $1 AND item_id = $2 AND step_key = $3',
      [profile.id, id, req.params.key]);
    res.status(204).end();
  }));

  // Model-derived "possibly related story" suggestions. Separate from /clusters/:id/items,
  // which returns the other outlets covering the SAME story — these are different stories that
  // merely look related, and nothing downstream acts on them.
  app.get('/api/clusters/:id/related', h(async (req, res) => {
    const id = parseId(req.params.id);
    if (id === null) return res.status(404).json({ error: 'not found' });
    const cluster = await store.get('SELECT id FROM clusters WHERE id = $1', [id]);
    if (!cluster) return res.status(404).json({ error: 'not found' });

    // Either direction of the pair: story_links stores one canonical row with a < b, so the
    // other side of the edge has to be selected rather than assumed to be cluster_b_id.
    const rows = await store.all(`
      SELECT other.id AS "clusterId", other.title, other.primary_item_id AS "primaryItemId",
             sl.similarity
        FROM story_links sl
        JOIN clusters other
          ON other.id = CASE WHEN sl.cluster_a_id = $1 THEN sl.cluster_b_id ELSE sl.cluster_a_id END
       WHERE sl.cluster_a_id = $1 OR sl.cluster_b_id = $1
       ORDER BY sl.similarity DESC`, [id]);

    // The raw float never leaves the API as the thing to display — it implies a precision the
    // measurement does not have — but it is kept alongside the label for sorting and debugging.
    res.json(rows.map((r) => ({ ...r, label: similarityLabel(r.similarity) })));
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
