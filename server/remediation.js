// The fix ladder and the per-(asset,item) remediation summary. Pure: no I/O, no model, no
// database — same discipline as playbook.js, which this module reads from and never duplicates.
//
// fixTarget composes no URL and names no version it did not read verbatim from an NVD bound
// field or a stored patch_url/advisory_url. A fabricated patch instruction is the worst output
// this whole feature could produce, because a reader would act on it.
const { affectedStatus } = require('./version_compare');

// entry: one cve_intel.affected_versions element (or null — no entry matched this asset).
// cveIntel: { patchUrl, advisoryUrl } — the same camelCase shape relevance.js already builds
// from cve_intel for a given item.
//
// Order is exactly endExcluding, then patch, then advisory, then none. endExcluding is the only
// field that names a fixed version — endIncluding ("X and earlier is broken") and pinned
// ("exactly X is broken") both name a broken version, never a fixed one, and must never reach
// kind: 'version'. This is consolidate.js's own rule for versionBounds(), enforced here where
// the inference from "broken version" to "fixed version" would otherwise happen.
function fixTarget(entry, cveIntel) {
  if (entry && entry.endExcluding) return { kind: 'version', value: entry.endExcluding };
  if (cveIntel && cveIntel.patchUrl) return { kind: 'patch', value: cveIntel.patchUrl };
  if (cveIntel && cveIntel.advisoryUrl) return { kind: 'advisory', value: cveIntel.advisoryUrl };
  return { kind: 'none' };
}

// asset: { vendor, product, exposure, version, versionState } — one profile_assets row.
// affectedVersions: the full cve_intel.affected_versions array for the item's CVE; the matching
// entry (if any) is found here, the same rule playbook.js's confirmStep already applies, so there
// is exactly one place this match happens rather than two copies of it drifting apart.
// cveIntel: { patchUrl, advisoryUrl }.
// playbookSteps: the item's already-built buildPlaybook() output.
function remediationFor(asset, affectedVersions, cveIntel, playbookSteps) {
  const entry = (affectedVersions || [])
    .find((v) => v.vendor === asset.vendor && v.product === asset.product) || null;

  // Only a recorded ('known') version is a claim about what the reader runs. 'unset'/'unknown'
  // must never be treated as a version to compare — affectedStatus already treats a null
  // installed as unknown, but this is where that null is decided, not left to the caller.
  const installed = asset.versionState === 'known' ? asset.version : null;

  return {
    status: affectedStatus(installed, entry),
    installed,
    versionState: asset.versionState,
    entry,
    fix: fixTarget(entry, cveIntel),
    // The subset of the playbook that acts without a fix — surfaced explicitly so a kind:
    // 'none' fix has something to offer instead of a dead end. These steps are already guarded
    // by the CVSS vector in playbook.js; this only names them as the fallback path.
    mitigations: (playbookSteps || []).filter((s) => s.key === 'restrict' || s.key === 'rotate'),
  };
}

module.exports = { fixTarget, remediationFor };
