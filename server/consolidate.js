// Post-sync pass. Rebuilds everything that is DERIVED from items — never touches item rows
// except to set their confidence. Safe to run repeatedly; each rebuild is a full replace.
const { clusterItems } = require('./cluster');
const { computeConfidence } = require('./confidence');
const { severityFromScore, canonicalSeverity } = require('./cvss');
const { parseCpe } = require('./cpe');

// CVSS precedence, most authoritative first. NVD is the reference scorer; vendors score
// their own product's context and legitimately disagree, which is why cve_sources keeps
// every number rather than averaging them.
const SOURCE_RANK = [
  'NVD CVE API',
  'Red Hat Security Data',
  'OSV.dev',
  'CIRCL Vulnerability-Lookup',
  'Ubuntu Security Notices',
  'Microsoft MSRC',
];

const KEV_SOURCE = 'CISA Known Exploited Vulnerabilities';
const BOILERPLATE_MIN = 40;

function rankOf(sourceName) {
  const i = SOURCE_RANK.indexOf(sourceName);
  return i === -1 ? SOURCE_RANK.length : i;
}

// CISA publishes dueDate as a bare YYYY-MM-DD. It is stored in a DATE column, so it is passed
// through as a string rather than turned into a Date — constructing one here would apply the
// server's timezone to a date that has none and can shift it by a day.
const DUE_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function kevDueDateFrom(kevRow) {
  if (!kevRow || !kevRow.raw_json) return null;
  let raw;
  try { raw = JSON.parse(kevRow.raw_json); } catch { return null; }
  const due = raw && raw.dueDate;
  return typeof due === 'string' && DUE_DATE_RE.test(due) ? due : null;
}

// CISA's own remediation sentence. Almost always boilerplate ("Apply mitigations per vendor
// instructions or discontinue use of the product...") — kept as a citation a playbook step can
// quote, never as the step's only content.
function kevRequiredActionFrom(kevRow) {
  if (!kevRow || !kevRow.raw_json) return null;
  let raw;
  try { raw = JSON.parse(kevRow.raw_json); } catch { return null; }
  const action = raw && raw.requiredAction;
  return typeof action === 'string' && action.trim() ? action.trim() : null;
}

// CISA's own field is the literal string "Known" or "Unknown", not a boolean.
function kevRansomwareFrom(kevRow) {
  if (!kevRow || !kevRow.raw_json) return false;
  let raw;
  try { raw = JSON.parse(kevRow.raw_json); } catch { return false; }
  const flag = raw && raw.knownRansomwareCampaignUse;
  return typeof flag === 'string' && flag.trim().toLowerCase() === 'known';
}

const PATCH_TAG = 'Patch';
const ADVISORY_TAG = 'Vendor Advisory';

// NVD tags each of its own references[] entries ('Patch', 'Vendor Advisory', 'Press/Media
// Coverage', ...) — reading its tag is how a playbook step cites a real fix location instead
// of guessing one. Only the real NVD row can supply this, same rule kevDueDateFrom follows for
// the real CISA row: an incidentally-shared CVE from another source has no references to give.
function referenceUrlFrom(nvdRow, tag) {
  if (!nvdRow || !nvdRow.raw_json) return null;
  let raw;
  try { raw = JSON.parse(nvdRow.raw_json); } catch { return null; }
  const refs = Array.isArray(raw && raw.references) ? raw.references : [];
  const match = refs.find((r) => r && Array.isArray(r.tags) && r.tags.includes(tag) && typeof r.url === 'string');
  return match ? match.url : null;
}

// Formats one CPE match's version bound into a plain-English fragment. Only vulnerable:true
// matches are ever passed in by affectedVersionsFrom — a "runs on" platform dependency isn't a
// statement about which version of the affected product itself is unsafe.
function versionRangeText(match) {
  const startIncluding = match.versionStartIncluding;
  const startExcluding = match.versionStartExcluding;
  const endIncluding = match.versionEndIncluding;
  const endExcluding = match.versionEndExcluding;
  const start = startIncluding || startExcluding;
  const end = endIncluding || endExcluding;
  if (start && end) {
    return endIncluding ? `${start} through ${end}` : `${start} up to (not including) ${end}`;
  }
  if (end) return endExcluding ? `before ${end}` : `${end} and earlier`;
  if (start) return startExcluding ? `after ${start}` : `${start} and later`;
  // No bound fields — fall back to the CPE's own pinned version segment.
  const version = pinnedVersion(match);
  return version ? `version ${version}` : null;
}

// The CPE's own version segment (5th colon field, cpe : 2.3 : part : vendor : product : version
// : ...), when it isn't the wildcard '*' or the not-applicable '-'.
function pinnedVersion(match) {
  const fields = typeof match.criteria === 'string' ? match.criteria.split(':') : [];
  const version = fields[5];
  return version && version !== '*' && version !== '-' ? version : null;
}

// The same facts as versionRangeText, as fields instead of a sentence. versionRangeText is what a
// reader sees; this is what code compares against a version someone actually runs. Every field is
// null unless NVD supplied it — this function derives nothing.
//
// endExcluding is the only field that names a fixed version. endIncluding says "this and earlier
// is broken" and names no fix; pinned says "exactly this version is broken" and names no fix
// either. Any caller turning one of these into an upgrade target would be inventing it.
function versionBounds(match) {
  return {
    startIncluding: match.versionStartIncluding || null,
    startExcluding: match.versionStartExcluding || null,
    endIncluding: match.versionEndIncluding || null,
    endExcluding: match.versionEndExcluding || null,
    pinned: pinnedVersion(match),
  };
}

// One line of text per distinct (vendor, product) the real NVD row calls vulnerable, in the
// order NVD lists them. Reuses parseCpe so the vendor/product spelling matches item_cpes exactly
// — this is what buildPlaybook/buildConsequence key their lookup on.
function affectedVersionsFrom(nvdRow) {
  if (!nvdRow || !nvdRow.raw_json) return [];
  let raw;
  try { raw = JSON.parse(nvdRow.raw_json); } catch { return []; }
  const out = [];
  const seen = new Set();
  for (const config of raw.configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        if (!match || match.vulnerable !== true) continue;
        const parsed = parseCpe(match.criteria);
        if (!parsed) continue;
        const key = `${parsed.vendor}:${parsed.product}`;
        if (seen.has(key)) continue;
        const text = versionRangeText(match);
        if (!text) continue;
        seen.add(key);
        out.push({ vendor: parsed.vendor, product: parsed.product, text, ...versionBounds(match) });
      }
    }
  }
  return out;
}

async function rebuildCveIntel(store) {
  const rows = await store.all(
    `SELECT ic.cve_id, i.id AS item_id, i.source_id, i.cvss_score, i.epss_score, i.severity, i.summary,
            i.published_at, i.exploitation_status, i.raw_json, s.name AS source_name
       FROM item_cves ic
       JOIN items i ON i.id = ic.item_id
       JOIN sources s ON s.id = i.source_id`);

  const byCve = new Map();
  for (const r of rows) {
    if (!byCve.has(r.cve_id)) byCve.set(r.cve_id, []);
    byCve.get(r.cve_id).push(r);
  }

  // Pure JS below (no awaits) builds one row's worth of data per CVE into parallel arrays,
  // then three batched statements replace what used to be 1 + N*2 awaited queries per CVE —
  // at ~20k distinct CVEs and ~25k evidence rows, that was tens of thousands of sequential
  // round-trips, which is what made consolidate() take minutes instead of seconds.
  const cveIntel = { cveId: [], cvss: [], cvssSource: [], severity: [], epss: [], kevListed: [], kevAddedAt: [],
    kevDueDate: [], kevRequiredAction: [], kevRansomware: [], patchUrl: [], advisoryUrl: [],
    description: [], firstSeen: [], lastSeen: [], sourceCount: [] };
  const cveSources = { cveId: [], itemId: [], sourceId: [], cvss: [], severity: [] };
  // Keyed by item_id so a later CVE group's backfill deterministically wins over an earlier
  // one for the same item — matching the original loop's sequential-overwrite behavior.
  const staleSeverityByItem = new Map();

  for (const [cveId, evidence] of byCve) {
    const scored = evidence
      .filter((e) => e.cvss_score != null)
      .sort((a, b) => rankOf(a.source_name) - rankOf(b.source_name));
    const winner = scored[0] || null;
    const cvss = winner ? Number(winner.cvss_score) : null;

    // FIRST EPSS is the only source that populates epss_score, so match on the column rather
    // than on the source name — a renamed source must not silently drop the score.
    const epss = evidence.find((e) => e.epss_score != null);

    // "Is this exploited" and "when did CISA add it to the KEV catalog" are different
    // questions. enrich.js sets exploitation_status = 'actively_exploited' on ANY item
    // whose CVE is in the KEV set at ingest — not only the actual CISA KEV item — so the
    // date must come only from the real KEV row, never from an incidentally-flagged one.
    const kevRow = evidence.find((e) => e.source_name === KEV_SOURCE);
    const exploited = kevRow || evidence.find((e) => e.exploitation_status === 'actively_exploited');

    // The remediation deadline CISA set, read from the KEV record itself. Same rule as
    // kev_added_at: only the real CISA row can supply it, because an incidentally-flagged
    // NVD row has no deadline to give. Unparseable or absent means null, never a guess.
    const kevDueDate = kevDueDateFrom(kevRow);
    const kevRequiredAction = kevRequiredActionFrom(kevRow);
    const kevRansomware = kevRansomwareFrom(kevRow);

    // The real NVD row, not `winner` — winner is chosen by CVSS-source rank and may be a
    // different source entirely when NVD didn't score this CVE.
    const nvdRow = evidence.find((e) => e.source_name === 'NVD CVE API');
    const patchUrl = referenceUrlFrom(nvdRow, PATCH_TAG);
    const advisoryUrl = referenceUrlFrom(nvdRow, ADVISORY_TAG);

    // Authority first (same SOURCE_RANK used for the CVSS winner above), length only as a
    // tiebreak — otherwise a verbose but unranked news write-up can out-length NVD's summary
    // and become the canonical description.
    const description = evidence
      .filter((e) => typeof e.summary === 'string' && e.summary.length >= BOILERPLATE_MIN)
      .sort((a, b) =>
        rankOf(a.source_name) - rankOf(b.source_name)
        || b.summary.length - a.summary.length)[0]?.summary || null;

    const times = evidence.map((e) => e.published_at).filter(Boolean).map((d) => new Date(d).getTime()).sort((a, b) => a - b);
    const severity = severityFromScore(cvss)
      || (evidence.map((e) => canonicalSeverity(e.severity)).find((s) => s !== 'unknown'))
      || 'unknown';

    // Some sources for this CVE (KEV, EPSS, Exploit-DB, Project Zero...) never carry a native
    // severity/CVSS of their own — their item rows stay severity IS NULL forever even once
    // corroborating sources (NVD, OSV, Red Hat) resolve one for the same CVE. Backfill it.
    if (severity !== 'unknown') {
      for (const e of evidence) {
        if (e.severity == null) staleSeverityByItem.set(e.item_id, severity);
      }
    }

    cveIntel.cveId.push(cveId);
    cveIntel.cvss.push(cvss);
    cveIntel.cvssSource.push(winner ? winner.source_name : null);
    cveIntel.severity.push(severity);
    cveIntel.epss.push(epss ? Number(epss.epss_score) : null);
    cveIntel.kevListed.push(Boolean(exploited));
    cveIntel.kevAddedAt.push(kevRow ? kevRow.published_at : null);
    cveIntel.kevDueDate.push(kevDueDate);
    cveIntel.kevRequiredAction.push(kevRequiredAction);
    cveIntel.kevRansomware.push(kevRansomware);
    cveIntel.patchUrl.push(patchUrl);
    cveIntel.advisoryUrl.push(advisoryUrl);
    cveIntel.description.push(description);
    cveIntel.firstSeen.push(times.length ? new Date(times[0]) : null);
    cveIntel.lastSeen.push(times.length ? new Date(times[times.length - 1]) : null);
    cveIntel.sourceCount.push(new Set(evidence.map((e) => e.source_id)).size);

    for (const e of evidence) {
      cveSources.cveId.push(cveId);
      cveSources.itemId.push(e.item_id);
      cveSources.sourceId.push(e.source_id);
      cveSources.cvss.push(e.cvss_score);
      cveSources.severity.push(canonicalSeverity(e.severity));
    }
  }

  await store.tx(async (t) => {
    await t.run('DELETE FROM cve_intel');   // cve_sources cascades

    if (staleSeverityByItem.size) {
      await t.run(
        `UPDATE items SET severity = v.severity
           FROM (SELECT * FROM unnest($1::int[], $2::text[]) AS v(item_id, severity)) v
          WHERE items.id = v.item_id`,
        [[...staleSeverityByItem.keys()], [...staleSeverityByItem.values()]]);
    }

    if (cveIntel.cveId.length) {
      await t.run(
        `INSERT INTO cve_intel (cve_id, cvss_score, cvss_source, severity, epss_score, kev_listed,
                                kev_added_at, kev_due_date, kev_required_action, kev_ransomware,
                                patch_url, advisory_url, description, first_seen, last_seen, source_count)
         SELECT * FROM unnest($1::text[], $2::float8[], $3::text[], $4::text[], $5::float8[],
                              $6::bool[], $7::timestamptz[], $8::date[], $9::text[], $10::bool[],
                              $11::text[], $12::text[], $13::text[], $14::timestamptz[], $15::timestamptz[], $16::int[])`,
        [cveIntel.cveId, cveIntel.cvss, cveIntel.cvssSource, cveIntel.severity, cveIntel.epss,
         cveIntel.kevListed, cveIntel.kevAddedAt, cveIntel.kevDueDate, cveIntel.kevRequiredAction, cveIntel.kevRansomware,
         cveIntel.patchUrl, cveIntel.advisoryUrl, cveIntel.description, cveIntel.firstSeen, cveIntel.lastSeen, cveIntel.sourceCount]);
    }

    if (cveSources.cveId.length) {
      await t.run(
        `INSERT INTO cve_sources (cve_id, item_id, source_id, cvss_score, severity)
         SELECT * FROM unnest($1::text[], $2::int[], $3::int[], $4::float8[], $5::text[])
         ON CONFLICT (cve_id, item_id) DO NOTHING`,
        [cveSources.cveId, cveSources.itemId, cveSources.sourceId, cveSources.cvss, cveSources.severity]);
    }
  });

  return byCve.size;
}

async function rebuildClusters(store) {
  const items = await store.all(
    `SELECT i.id, i.title, i.published_at, i.source_id, i.confidence,
            COALESCE(c.cves, '{}') AS cves, COALESCE(a.actors, '{}') AS actors, COALESCE(f.families, '{}') AS families
       FROM items i
       LEFT JOIN (SELECT item_id, array_agg(cve_id) AS cves FROM item_cves GROUP BY item_id) c ON c.item_id = i.id
       LEFT JOIN (SELECT item_id, array_agg(actor) AS actors FROM item_actors GROUP BY item_id) a ON a.item_id = i.id
       LEFT JOIN (SELECT item_id, array_agg(family) AS families FROM item_malware_families GROUP BY item_id) f ON f.item_id = i.id`);

  const clusters = clusterItems(items);

  // Batched inserts instead of one INSERT per cluster plus one per member — at ~24k items
  // (mostly singleton clusters) that was tens of thousands of sequential round-trips, the
  // dominant remaining cost in rebuildClusters() once clusterItems() itself was indexed.
  // primary_item_id is a safe correlation key: exactly one cluster owns any given item as
  // its primary, so it's unique across the batch and lets the generated ids be mapped back
  // after a single INSERT...RETURNING.
  await store.tx(async (t) => {
    await t.run('DELETE FROM clusters');   // cluster_items cascades

    if (clusters.length) {
      const inserted = await t.all(
        `INSERT INTO clusters (primary_item_id, title, first_seen, last_seen, source_count)
         SELECT * FROM unnest($1::int[], $2::text[], $3::timestamptz[], $4::timestamptz[], $5::int[])
         RETURNING id, primary_item_id`,
        [clusters.map((c) => c.primaryItemId), clusters.map((c) => c.title),
         clusters.map((c) => c.firstSeen), clusters.map((c) => c.lastSeen), clusters.map((c) => c.sourceIds.length)]);

      const idByPrimaryItem = new Map(inserted.map((r) => [r.primary_item_id, r.id]));
      const clusterIds = [];
      const itemIds = [];
      for (const c of clusters) {
        const clusterId = idByPrimaryItem.get(c.primaryItemId);
        for (const itemId of c.itemIds) { clusterIds.push(clusterId); itemIds.push(itemId); }
      }

      if (itemIds.length) {
        await t.run(
          `INSERT INTO cluster_items (cluster_id, item_id)
           SELECT * FROM unnest($1::int[], $2::int[])
           ON CONFLICT (item_id) DO NOTHING`,
          [clusterIds, itemIds]);
      }
    }
  });

  return clusters.length;
}

async function applyConfidence(store) {
  // Corroboration = distinct sources sharing this item's cluster. A singleton cluster is
  // one source, which is the no-bonus case.
  const rows = await store.all(
    `SELECT i.id, s.category AS source_category, COALESCE(cl.source_count, 1) AS corroboration
       FROM items i
       JOIN sources s ON s.id = i.source_id
       LEFT JOIN cluster_items ci ON ci.item_id = i.id
       LEFT JOIN clusters cl ON cl.id = ci.cluster_id`);

  // One UPDATE...FROM unnest() instead of one UPDATE per row — at 24k+ items, the per-row
  // version was 24k+ sequential awaited round-trips, the dominant cost in consolidate().
  if (rows.length) {
    const ids = rows.map((r) => r.id);
    const confidences = rows.map((r) => computeConfidence(r.source_category, r.corroboration));
    await store.run(
      `UPDATE items SET confidence = v.confidence
         FROM (SELECT * FROM unnest($1::int[], $2::float8[]) AS v(id, confidence)) v
        WHERE items.id = v.id`,
      [ids, confidences]);
  }

  return rows.length;
}

async function pruneSyncHistory(store, days = 90) {
  const res = await store.run(
    `DELETE FROM source_syncs WHERE started_at < now() - ($1 || ' days')::interval`, [String(days)]);
  return res.rowCount;
}

async function consolidate(store) {
  const cves = await rebuildCveIntel(store);
  const clusters = await rebuildClusters(store);
  const items = await applyConfidence(store);
  const pruned = await pruneSyncHistory(store, 90);
  return { cves, clusters, items, pruned };
}

module.exports = { consolidate, rebuildCveIntel, rebuildClusters, applyConfidence, pruneSyncHistory, SOURCE_RANK, versionRangeText, versionBounds, affectedVersionsFrom };
