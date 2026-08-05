// Curated, hand-maintained ATT&CK mitigation lookup — not MITRE ATT&CK ingestion. Keyed by the
// exact name strings already used in data/threat-actors.json / data/malware-families.json.
// Exact match only: no fuzzy matching, no partial match, no invented mitigation for a name this
// map doesn't carry.
const path = require('node:path');
const fs = require('node:fs');

const MITIGATIONS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'data', 'attack-mitigations.json'), 'utf8'));

function attackStep(name) {
  if (!name) return null;
  return MITIGATIONS[name] || null;
}

module.exports = { attackStep };
