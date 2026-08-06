// Shared MITRE ATT&CK STIX 2.1 bundle fetch/parse, used by backfill-attack.js (real ATT&CK
// mitigation ingestion) and backfill-actor-dictionary.js (growing the actor/family dictionary).
// Not on any live request path -- a manual backfill rerun only, same idiom as this codebase's
// other backfill-*.js scripts.
const { safeRequest } = require('./safe-request');

const STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

// ~30-40MB. adapters/bespoke.js's own large-page NVD fetches use up to 90s for multi-MB
// responses; the same budget applies here.
const STIX_TIMEOUT_MS = 90000;

async function fetchStixBundle(requestFn = safeRequest) {
  const res = await requestFn(STIX_URL, { timeoutMs: STIX_TIMEOUT_MS });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} fetching ATT&CK STIX bundle`);
  let bundle;
  try { bundle = JSON.parse(res.body); } catch { throw new Error('malformed ATT&CK STIX bundle: not valid JSON'); }
  if (!bundle || !Array.isArray(bundle.objects)) throw new Error('malformed ATT&CK STIX bundle: no objects[]');
  return bundle;
}

function isRevoked(obj) {
  return obj.revoked === true || obj.x_mitre_deprecated === true;
}

// type is a STIX object type ('intrusion-set', 'malware', 'tool', 'course-of-action',
// 'attack-pattern', 'relationship'). excludeRevoked drops anything MITRE itself no longer
// stands behind, before matching ever sees it.
function objectsByType(bundle, type, { excludeRevoked = false } = {}) {
  return (bundle.objects || []).filter((o) => o.type === type && (!excludeRevoked || !isRevoked(o)));
}

module.exports = { fetchStixBundle, objectsByType, isRevoked, STIX_URL };
