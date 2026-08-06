// Regenerates data/threat-actors.json / data/malware-families.json from MITRE's own STIX
// bundle. Static JSON output, not a DB table -- enrich.js:matchDictionary runs synchronously in
// the per-item ingest hot path with no DB round trip today, and nothing here needs per-item
// freshness. Idempotent, one-off, --dry-run to preview, bare invocation writes. Rerun manually,
// same cadence as backfill-attack.js (ATT&CK updates roughly twice a year).
const path = require('node:path');
const fs = require('node:fs');
const { fetchStixBundle, objectsByType } = require('./attack_stix');

const MIN_NAME_LENGTH = 5;

// Seed case: 'Empire' is a real ATT&CK software name and an ordinary English word. Grows as
// real matches surface further false positives -- this is the intended maintenance loop, not a
// bug each time an entry gets added here.
const AMBIGUOUS_NAMES = new Set(['empire']);

function passesFilter(name) {
  const n = String(name || '').trim();
  if (n.length < MIN_NAME_LENGTH) return false;
  if (AMBIGUOUS_NAMES.has(n.toLowerCase())) return false;
  return true;
}

// name and each alias are filtered independently: the primary name must pass for the STIX
// object to produce an entry at all, and each alias survives or is dropped on its own merits.
function toEntry(stixObj) {
  if (!passesFilter(stixObj.name)) return null;
  const rawAliases = stixObj.aliases || stixObj.x_mitre_aliases || [];
  const aliases = rawAliases.filter((a) => a !== stixObj.name && passesFilter(a));
  return { name: stixObj.name, aliases };
}

function byName(a, b) { return a.name.localeCompare(b.name); }

// Pure: given an already-fetched bundle, returns the two dictionaries. Exported separately from
// regenerate() so the fixture test never has to fake a network call.
function buildDictionary(bundle) {
  const actors = objectsByType(bundle, 'intrusion-set', { excludeRevoked: true })
    .map(toEntry).filter(Boolean).sort(byName);
  const families = [
    ...objectsByType(bundle, 'malware', { excludeRevoked: true }),
    ...objectsByType(bundle, 'tool', { excludeRevoked: true }),
  ].map(toEntry).filter(Boolean).sort(byName);
  return { actors, families };
}

const ACTORS_PATH = path.join(__dirname, '..', 'data', 'threat-actors.json');
const FAMILIES_PATH = path.join(__dirname, '..', 'data', 'malware-families.json');

async function regenerate({ dryRun = false, requestFn } = {}) {
  const bundle = await fetchStixBundle(requestFn);
  const { actors, families } = buildDictionary(bundle);
  if (!dryRun) {
    fs.writeFileSync(ACTORS_PATH, `${JSON.stringify(actors, null, 2)}\n`);
    fs.writeFileSync(FAMILIES_PATH, `${JSON.stringify(families, null, 2)}\n`);
  }
  return { actors: actors.length, families: families.length };
}

module.exports = { buildDictionary, regenerate, AMBIGUOUS_NAMES, MIN_NAME_LENGTH };

if (require.main === module) {
  const dryRun = process.argv.includes('--dry-run');
  regenerate({ dryRun })
    .then((r) => {
      console.log(`${dryRun ? '[dry run] ' : ''}${r.actors} actors, ${r.families} families`);
    })
    .catch((err) => { console.error(err); process.exit(1); });
}
