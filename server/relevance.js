// Materializes the relevance ladder's verdicts into item_relevance, one row per (profile, item,
// profile_version).
//
// Scoring is pure JS with no network, so a full recompute of the whole corpus takes well under a
// second. That is why there is no NOT-EXISTS resume query, no partial-progress bookkeeping and no
// bounded concurrency here — that machinery only exists to survive slow model calls, and this
// path has none.
const { scoreRelevance } = require('./relevance_score');
const { getProfile } = require('./profiles');

// 6 params per row; Postgres caps a statement at 65535 bind parameters, so 1000 rows (6000
// params) stays far inside the limit while cutting round-trips by three orders of magnitude.
const INSERT_BATCH = 1000;

// One pass over the corpus with the child rows folded in, rather than a query per item.
// CVE facts come from cve_intel (consolidated across every source that reported the CVE), not
// items.exploitation_status / items.epss_score, which are populated on 166 and 50 rows.
async function assembleItems(store) {
  const rows = await store.all(`
    SELECT i.id, i.severity, i.cvss_score, i.cvss_version, i.published_at, i.industry,
           COALESCE(d.domains, '{}') AS domains,
           COALESCE(c.cpes, '[]'::jsonb) AS cpes,
           ci.kev_listed, ci.epss_score, ci.severity AS cve_severity, ci.cvss_score AS cve_cvss
      FROM items i
      LEFT JOIN LATERAL (
        SELECT array_agg(domain) AS domains FROM item_domains WHERE item_id = i.id
      ) d ON true
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object('vendor', vendor, 'product', product)) AS cpes
          FROM item_cpes WHERE item_id = i.id
      ) c ON true
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
    publishedAt: r.published_at,
    industry: r.industry,
    domains: r.domains || [],
    cpes: r.cpes || [],
    cve: r.kev_listed == null && r.cve_severity == null && r.cve_cvss == null
      ? null
      : {
        kevListed: !!r.kev_listed,
        epssScore: r.epss_score,
        severity: r.cve_severity,
        cvssScore: r.cve_cvss,
      },
  }));
}

async function recomputeProfile(store, profileId, { now = new Date() } = {}) {
  const profile = await getProfile(store, profileId);
  if (!profile) return null;

  const items = await assembleItems(store);
  const tiers = { act_now: 0, watch: 0, low: 0, not_yours: 0 };
  const values = [];

  for (const item of items) {
    const { tier, score, matches } = scoreRelevance(profile, item, now);
    tiers[tier] += 1;
    values.push([profile.id, item.id, profile.profile_version, tier, score, JSON.stringify(matches)]);
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
        return `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6}::jsonb)`;
      });
      await t.run(
        `INSERT INTO item_relevance (profile_id, item_id, profile_version, tier, score, matches)
         VALUES ${tuples.join(',')}`, params);
    }
  });

  return { scored: values.length, tiers };
}

module.exports = { recomputeProfile, assembleItems };
