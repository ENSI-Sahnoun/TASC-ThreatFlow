// Materializes the relevance ladder's verdicts into item_relevance, one row per (profile, item,
// profile_version).
//
// Scoring is pure JS with no network, so a full recompute of the whole corpus takes well under a
// second. That is why there is no NOT-EXISTS resume query, no partial-progress bookkeeping and no
// bounded concurrency here — that machinery only exists to survive slow model calls, and this
// path has none.
const { scoreRelevance } = require('./relevance_score');
const { buildConsequence } = require('./consequence');
const { buildPlaybook } = require('./playbook');
const { buildCategoryPlaybook } = require('./playbooks');
const { buildAttackMitigationsMap } = require('./playbooks/attack-mitigations');
const { getProfile } = require('./profiles');

// 7 params per row; Postgres caps a statement at 65535 bind parameters, so 1000 rows (7000
// params) stays far inside the limit while cutting round-trips by three orders of magnitude.
const INSERT_BATCH = 1000;

// One pass over the corpus with the child rows folded in, rather than a query per item.
// CVE facts come from cve_intel (consolidated across every source that reported the CVE), not
// items.exploitation_status / items.epss_score, which are populated on 166 and 50 rows.
async function assembleItems(store) {
  const rows = await store.all(`
    SELECT i.id, i.severity, i.cvss_score, i.cvss_version, i.cvss_vector, i.published_at, i.industry,
           i.category, i.title,
           COALESCE(d.domains, '{}') AS domains,
           COALESCE(c.cpes, '[]'::jsonb) AS cpes,
           COALESCE(io.iocs, '[]'::jsonb) AS iocs,
           COALESCE(ac.actors, '{}') AS actors,
           COALESCE(fa.families, '{}') AS families,
           ci.kev_listed, ci.epss_score, ci.severity AS cve_severity, ci.cvss_score AS cve_cvss,
           ci.kev_ransomware, ci.patch_url, ci.advisory_url, ci.affected_versions,
           -- As text, never as a Date: pg parses DATE at local midnight, so serializing it
           -- through toISOString() would render CISA's deadline a day early.
           to_char(ci.kev_due_date, 'YYYY-MM-DD') AS kev_due_date
      FROM items i
      LEFT JOIN LATERAL (
        SELECT array_agg(domain) AS domains FROM item_domains WHERE item_id = i.id
      ) d ON true
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object('vendor', vendor, 'product', product)) AS cpes
          FROM item_cpes WHERE item_id = i.id
      ) c ON true
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object('type', ioc_type, 'value', ioc_value)) AS iocs
          FROM item_iocs WHERE item_id = i.id
      ) io ON true
      LEFT JOIN LATERAL (
        SELECT array_agg(actor) AS actors FROM item_actors WHERE item_id = i.id
      ) ac ON true
      LEFT JOIN LATERAL (
        SELECT array_agg(family) AS families FROM item_malware_families WHERE item_id = i.id
      ) fa ON true
      LEFT JOIN LATERAL (
        -- An item can carry several CVE ids; the most severe consolidated record is the one
        -- that should drive the verdict.
        SELECT ci2.* FROM item_cves ic
          JOIN cve_intel ci2 ON ci2.cve_id = ic.cve_id
         WHERE ic.item_id = i.id
         ORDER BY ci2.kev_listed DESC, ci2.cvss_score DESC NULLS LAST
         LIMIT 1
      ) ci ON true
  `);

  return rows.map((r) => ({
    id: r.id,
    severity: r.severity,
    cvssScore: r.cvss_score,
    cvssVersion: r.cvss_version,
    cvssVector: r.cvss_vector,
    publishedAt: r.published_at,
    industry: r.industry,
    category: r.category,
    title: r.title,
    domains: r.domains || [],
    cpes: r.cpes || [],
    iocs: r.iocs || [],
    actors: r.actors || [],
    families: r.families || [],
    cve: r.kev_listed == null && r.cve_severity == null && r.cve_cvss == null
      ? null
      : {
        kevListed: !!r.kev_listed,
        kevDueDate: r.kev_due_date,
        epssScore: r.epss_score,
        severity: r.cve_severity,
        cvssScore: r.cve_cvss,
        knownRansomware: !!r.kev_ransomware,
        patchUrl: r.patch_url,
        advisoryUrl: r.advisory_url,
        affectedVersions: r.affected_versions || [],
      },
  }));
}

async function recomputeProfile(store, profileId, { now = new Date() } = {}) {
  const rawProfile = await getProfile(store, profileId);
  if (!rawProfile) return null;

  // Loaded once per recompute, same "no per-item query" discipline as attackMitigations below.
  // A shallow copy, not a write to the fetched row: scoreRelevance reads clickedItemIds off the
  // same profile object it already receives everything else through.
  const clickedRows = await store.all(
    'SELECT item_id FROM profile_reported_clicks WHERE profile_id = $1', [profileId]);
  const profile = { ...rawProfile, clickedItemIds: new Set(clickedRows.map((r) => r.item_id)) };

  const items = await assembleItems(store);
  // Loaded once per recompute call, not per item -- same reasoning as the rest of this file's
  // "no per-item query" discipline. A stale or empty table just means attackStep() returns null
  // for everything, identical to the old curated-file "no match" behavior.
  const attackMitigations = buildAttackMitigationsMap(await store.all('SELECT * FROM attack_mitigations'));
  const tiers = { act_now: 0, watch: 0, low: 0, not_yours: 0 };
  const values = [];
  const playbookValues = [];

  for (const item of items) {
    const { tier, score, matches, exposure } = scoreRelevance(profile, item, now);
    tiers[tier] += 1;

    // Deterministic, pure and cheap, so it is materialized in the same pass rather than
    // recomputed on every read. It cannot affect `tier` — that was decided on the line above.
    // The asset whose exposure the scorer settled on is the one whose vendor/product names the
    // role, so the sentence describes the thing that actually made this urgent.
    const asset = (profile.assets || []).find((a) => a.exposure === exposure
      && (item.cpes || []).some((c) => c.vendor === a.vendor && c.product === a.product));
    const consequence = buildConsequence({
      vector: item.cvssVector,
      exposure,
      vendor: asset ? asset.vendor : null,
      product: asset ? asset.product : null,
      kevListed: !!(item.cve && item.cve.kevListed),
      kevDueDate: item.cve ? item.cve.kevDueDate : null,
      epssScore: item.cve ? item.cve.epssScore : null,
    });

    // exposure rides inside the stored JSON so the read path never has to recover it by
    // parsing a `from` string, which is human-facing provenance rather than a data channel.
    values.push([profile.id, item.id, profile.profile_version, tier, score,
      JSON.stringify(matches), JSON.stringify({ ...consequence, exposure })]);

    // Playbooks only for the tiers a user will actually read. A CVE-shaped item (has a CVE
    // record or its own CVSS vector) keeps the existing per-CVE builder; everything else falls
    // through to the category dispatcher, which returns null for a category with nothing to
    // ground a step on (advisory/osint/news/other) or for an ioc-category item with zero
    // indicators. Cheap and pure, so it is materialized in the same pass as consequence.
    if (tier === 'act_now' || tier === 'watch') {
      let playbookSteps = null;
      if (item.cve || item.cvssVector) {
        playbookSteps = buildPlaybook({
          vector: item.cvssVector,
          exposure,
          vendor: asset ? asset.vendor : null,
          product: asset ? asset.product : null,
          kevListed: !!(item.cve && item.cve.kevListed),
          kevDueDate: item.cve ? item.cve.kevDueDate : null,
          kevRansomware: !!(item.cve && item.cve.knownRansomware),
          patchUrl: item.cve ? item.cve.patchUrl : null,
          advisoryUrl: item.cve ? item.cve.advisoryUrl : null,
          affectedVersions: item.cve ? item.cve.affectedVersions : [],
        });
      } else {
        playbookSteps = buildCategoryPlaybook({
          category: item.category,
          title: item.title,
          actors: item.actors,
          families: item.families,
          iocs: item.iocs,
          attackMitigations,
        });
      }

      if (playbookSteps && playbookSteps.length > 0) {
        playbookValues.push([profile.id, item.id, profile.profile_version, JSON.stringify(playbookSteps)]);
      }
    }
  }

  await store.tx(async (t) => {
    // Delete-then-insert scoped to this version only, so rows at superseded versions survive
    // and a reverted profile edit re-exposes its cached verdicts without re-scoring.
    await t.run('DELETE FROM item_relevance WHERE profile_id = $1 AND profile_version = $2',
      [profile.id, profile.profile_version]);

    // Multi-row inserts, not one statement per item. Scoring 24k items takes milliseconds; 24k
    // separate round-trips took ~4.8s and were the entire cost of a recompute.
    for (let i = 0; i < values.length; i += INSERT_BATCH) {
      const chunk = values.slice(i, i + INSERT_BATCH);
      const params = [];
      const tuples = chunk.map((v) => {
        const base = params.length;
        params.push(...v);
        return `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6}::jsonb,$${base + 7}::jsonb)`;
      });
      await t.run(
        `INSERT INTO item_relevance (profile_id, item_id, profile_version, tier, score, matches, consequence)
         VALUES ${tuples.join(',')}`, params);
    }

    await t.run('DELETE FROM item_playbooks WHERE profile_id = $1 AND profile_version = $2',
      [profile.id, profile.profile_version]);

    for (let i = 0; i < playbookValues.length; i += INSERT_BATCH) {
      const chunk = playbookValues.slice(i, i + INSERT_BATCH);
      const params = [];
      const tuples = chunk.map((v) => {
        const base = params.length;
        params.push(...v);
        return `($${base + 1},$${base + 2},$${base + 3},$${base + 4}::jsonb)`;
      });
      await t.run(
        `INSERT INTO item_playbooks (profile_id, item_id, profile_version, steps)
         VALUES ${tuples.join(',')}`, params);
    }
  });

  return { scored: values.length, tiers };
}

module.exports = { recomputeProfile, assembleItems };
