const test = require('node:test');
const assert = require('node:assert');
const { buildDictionary } = require('./backfill-actor-dictionary');

function intrusionSet(name, aliases, extra = {}) {
  return { type: 'intrusion-set', id: `intrusion-set--${name.toLowerCase().replace(/\s+/g, '-')}`, name, aliases, ...extra };
}
function malware(name, aliases, extra = {}) {
  return { type: 'malware', id: `malware--${name.toLowerCase().replace(/\s+/g, '-')}`, name, x_mitre_aliases: aliases, ...extra };
}
function tool(name, aliases, extra = {}) {
  return { type: 'tool', id: `tool--${name.toLowerCase().replace(/\s+/g, '-')}`, name, x_mitre_aliases: aliases, ...extra };
}

function bundle() {
  return {
    objects: [
      // Legitimate: survives length + ambiguity filters.
      intrusionSet('Sandworm Team', ['Voodoo Bear', 'Telebots']),
      malware('TrickBot', []),
      // Revoked: excluded entirely, regardless of name.
      intrusionSet('OldGroupName', ['Some Alias'], { revoked: true }),
      // Deprecated: same treatment as revoked.
      malware('DeprecatedFamily', [], { x_mitre_deprecated: true }),
      // Primary name under 5 chars (a LOTL-tool-shaped false positive): excluded entirely.
      tool('cmd', []),
      // On the AMBIGUOUS_NAMES exclusion list: excluded entirely even though it is long enough
      // and not revoked.
      tool('Empire', ['PS Empire']),
      // Legitimate name, but one alias is itself under 5 chars -- the alias is dropped, the
      // entry survives with its remaining alias.
      malware('QuietVault', ['sc', 'Vault Stealer']),
    ],
  };
}

test('buildDictionary keeps only non-revoked, long-enough, non-ambiguous names', () => {
  const { actors, families } = buildDictionary(bundle());
  assert.deepStrictEqual(actors.map((a) => a.name), ['Sandworm Team']);
  assert.deepStrictEqual(families.map((f) => f.name).sort(), ['QuietVault', 'TrickBot']);
});

test('buildDictionary preserves aliases for a surviving entry', () => {
  const { actors } = buildDictionary(bundle());
  assert.deepStrictEqual(actors[0].aliases, ['Voodoo Bear', 'Telebots']);
});

test('buildDictionary drops an individual short alias while keeping its parent entry', () => {
  const { families } = buildDictionary(bundle());
  const quietVault = families.find((f) => f.name === 'QuietVault');
  assert.deepStrictEqual(quietVault.aliases, ['Vault Stealer']);
});

test('buildDictionary excludes revoked and deprecated objects entirely', () => {
  const { actors, families } = buildDictionary(bundle());
  assert.ok(!actors.some((a) => a.name === 'OldGroupName'));
  assert.ok(!families.some((f) => f.name === 'DeprecatedFamily'));
});

test('buildDictionary excludes a name under 5 characters', () => {
  const { families } = buildDictionary(bundle());
  assert.ok(!families.some((f) => f.name === 'cmd'));
});

test('buildDictionary excludes a name on the AMBIGUOUS_NAMES list', () => {
  const { families } = buildDictionary(bundle());
  assert.ok(!families.some((f) => f.name === 'Empire'));
});

test('malware and tool objects both feed the families dictionary', () => {
  const b = { objects: [intrusionSet('Some Group Name', []), tool('Cobalt Striker', [])] };
  const { actors, families } = buildDictionary(b);
  assert.deepStrictEqual(actors.map((a) => a.name), ['Some Group Name']);
  assert.deepStrictEqual(families.map((f) => f.name), ['Cobalt Striker']);
});
