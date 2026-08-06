// Pure Map lookup over attack_mitigations rows, keyed by "<subjectType>:<name lowercase>". The
// DB table is MITRE's own STIX data (see server/backfill-attack.js); this module has no I/O of
// its own and no fallback -- an empty or stale map means every lookup returns null, same
// "no match => absent step" posture the old curated JSON file had.
function attackStep(name, subjectType, map) {
  if (!name || !subjectType || !map) return null;
  return map.get(`${subjectType}:${name.toLowerCase()}`) || null;
}

// Builds the Map from attack_mitigations rows (as returned by `SELECT * FROM
// attack_mitigations`), grouping by subject. synced_at is normalized to a bare YYYY-MM-DD for
// the step's `source` string, matching the rest of this codebase's rule that a DATE-shaped
// value is rendered as text rather than as a Date object.
function buildAttackMitigationsMap(rows) {
  const map = new Map();
  for (const r of rows || []) {
    const key = `${r.subject_type}:${r.subject_name.toLowerCase()}`;
    const list = map.get(key) || [];
    list.push({
      id: r.mitigation_id,
      name: r.mitigation_name,
      url: r.mitigation_url,
      techniqueCount: r.technique_count,
      syncedAt: r.synced_at ? new Date(r.synced_at).toISOString().slice(0, 10) : null,
    });
    map.set(key, list);
  }
  return map;
}

module.exports = { attackStep, buildAttackMitigationsMap };
