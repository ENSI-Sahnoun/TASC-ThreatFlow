// Regenerates attack_mitigations from MITRE's own STIX bundle: for each name in
// data/threat-actors.json / data/malware-families.json, find the matching ATT&CK
// intrusion-set/malware/tool object(s), walk their `uses` relationships to a technique set,
// walk every course-of-action's `mitigates` relationships against that set, and keep the top 5
// mitigations ranked by how many of the subject's techniques each one addresses.
//
// Idempotent, DELETE + reinsert on every run -- same rebuild-not-merge posture as
// rebuildClusters(). Rerun manually whenever the dictionaries gain entries or periodically to
// pick up ATT&CK's own updates (roughly twice a year). Not on any live request path.
const path = require('node:path');
const fs = require('node:fs');
const { fetchStixBundle, objectsByType } = require('./attack_stix');

const ACTORS = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'threat-actors.json'), 'utf8'));
const FAMILIES = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'malware-families.json'), 'utf8'));

const TOP_N = 5;

function stixNames(obj) {
  return [obj.name, ...(obj.aliases || obj.x_mitre_aliases || [])].filter(Boolean).map((n) => n.toLowerCase());
}

// Exact match only, case-insensitive, tried against every non-revoked candidate's own name+
// alias set. No fuzzy matching, no partial/substring match, no invented mitigation for a name
// that doesn't hit.
function findStixMatches(entry, candidates) {
  const ourNames = new Set([entry.name, ...(entry.aliases || [])].map((n) => n.toLowerCase()));
  return candidates.filter((c) => stixNames(c).some((n) => ourNames.has(n)));
}

function externalRef(obj, sourceName = 'mitre-attack') {
  return (obj.external_references || []).find((r) => r.source_name === sourceName && r.external_id) || null;
}

function techniqueSetFor(stixIds, usesRelationships) {
  const set = new Set();
  for (const rel of usesRelationships) {
    if (stixIds.has(rel.source_ref)) set.add(rel.target_ref);
  }
  return set;
}

function buildMitigationIndex(courseOfAction) {
  const byStixId = new Map();
  for (const m of courseOfAction) {
    const ref = externalRef(m);
    if (!ref) continue;
    const urlRef = (m.external_references || []).find((r) => r.source_name === 'mitre-attack' && r.url);
    byStixId.set(m.id, {
      mitigationId: ref.external_id,
      mitigationName: m.name,
      mitigationUrl: (urlRef && urlRef.url) || `https://attack.mitre.org/mitigations/${ref.external_id}/`,
    });
  }
  return byStixId;
}

function rankMitigations(techniqueIds, mitigatesRelationships, mitigationsByStixId) {
  const tally = new Map();
  for (const rel of mitigatesRelationships) {
    if (!techniqueIds.has(rel.target_ref)) continue;
    if (!mitigationsByStixId.has(rel.source_ref)) continue;
    tally.set(rel.source_ref, (tally.get(rel.source_ref) || 0) + 1);
  }
  return [...tally.entries()]
    .map(([stixId, count]) => ({ ...mitigationsByStixId.get(stixId), techniqueCount: count }))
    .sort((a, b) => b.techniqueCount - a.techniqueCount)
    .slice(0, TOP_N);
}

// Pure: given an already-fetched bundle and the two dictionaries, returns the rows to write.
// Exported separately from backfill() so the fixture test never has to fake a network call.
function buildRows(bundle, actors = ACTORS, families = FAMILIES) {
  const candidates = [
    ...objectsByType(bundle, 'intrusion-set', { excludeRevoked: true }),
    ...objectsByType(bundle, 'malware', { excludeRevoked: true }),
    ...objectsByType(bundle, 'tool', { excludeRevoked: true }),
  ];
  const courseOfAction = objectsByType(bundle, 'course-of-action', { excludeRevoked: true });
  const relationships = objectsByType(bundle, 'relationship', { excludeRevoked: true });
  const usesRels = relationships.filter((r) => r.relationship_type === 'uses');
  const mitigatesRels = relationships.filter((r) => r.relationship_type === 'mitigates');
  const mitigationsByStixId = buildMitigationIndex(courseOfAction);

  const rows = [];
  function buildFor(list, subjectType) {
    for (const entry of list) {
      const matches = findStixMatches(entry, candidates);
      if (!matches.length) continue;
      const stixIds = new Set(matches.map((m) => m.id));
      const techniqueIds = techniqueSetFor(stixIds, usesRels);
      if (!techniqueIds.size) continue;
      const ranked = rankMitigations(techniqueIds, mitigatesRels, mitigationsByStixId);
      for (const r of ranked) {
        rows.push({
          subjectType, subjectName: entry.name,
          mitigationId: r.mitigationId, mitigationName: r.mitigationName, mitigationUrl: r.mitigationUrl,
          techniqueCount: r.techniqueCount,
        });
      }
    }
  }
  buildFor(actors, 'actor');
  buildFor(families, 'family');
  return rows;
}

async function backfill(store, { dryRun = false, requestFn, now = () => new Date() } = {}) {
  const bundle = await fetchStixBundle(requestFn);
  const rows = buildRows(bundle);
  const subjectsMatched = new Set(rows.map((r) => `${r.subjectType}:${r.subjectName}`)).size;

  if (!dryRun) {
    const syncedAt = now();
    await store.tx(async (t) => {
      await t.run('DELETE FROM attack_mitigations');
      for (const r of rows) {
        await t.run(
          `INSERT INTO attack_mitigations
             (subject_type, subject_name, mitigation_id, mitigation_name, mitigation_url, technique_count, synced_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (subject_type, subject_name, mitigation_id) DO NOTHING`,
          [r.subjectType, r.subjectName, r.mitigationId, r.mitigationName, r.mitigationUrl, r.techniqueCount, syncedAt]);
      }
    });
  }

  return { rows: rows.length, subjectsMatched };
}

module.exports = { backfill, buildRows, findStixMatches, rankMitigations };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => {
      console.log(`${dryRun ? '[dry run] ' : ''}${r.rows} mitigation rows across ${r.subjectsMatched} matched subjects`);
      return store.close();
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
