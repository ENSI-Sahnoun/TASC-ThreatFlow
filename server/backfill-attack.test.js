const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfill, buildRows } = require('./backfill-attack');

function technique(n) {
  return {
    type: 'attack-pattern', id: `attack-pattern--t${n}`, name: `Technique ${n}`,
    external_references: [{ source_name: 'mitre-attack', external_id: `T${1000 + n}` }],
  };
}
function mitigation(n) {
  return {
    type: 'course-of-action', id: `course-of-action--m${n}`, name: `Mitigation ${n}`,
    external_references: [{
      source_name: 'mitre-attack', external_id: `M${1000 + n}`,
      url: `https://attack.mitre.org/mitigations/M${1000 + n}/`,
    }],
  };
}
const T = (n) => `attack-pattern--t${n}`;
const M = (n) => `course-of-action--m${n}`;
function uses(sourceId, targetId) { return { type: 'relationship', relationship_type: 'uses', source_ref: sourceId, target_ref: targetId }; }
function mitigates(sourceId, targetId) { return { type: 'relationship', relationship_type: 'mitigates', source_ref: sourceId, target_ref: targetId }; }

const SANDWORM = { type: 'intrusion-set', id: 'intrusion-set--sandworm', name: 'Sandworm', aliases: ['Voodoo Bear'] };
const TRICKBOT = { type: 'malware', id: 'malware--trickbot', name: 'TrickBot', x_mitre_aliases: [] };
const LOCKBIT_GROUP = { type: 'intrusion-set', id: 'intrusion-set--lockbit', name: 'LockBit', aliases: [] };
const LOCKBIT_MALWARE = { type: 'malware', id: 'malware--lockbit', name: 'LockBit', x_mitre_aliases: [] };
const REVOKED_GHOST = { type: 'intrusion-set', id: 'intrusion-set--ghost-old', name: 'GhostGroup', revoked: true };

const TECHNIQUE_NUMS = [1, 2, 11, 12, 13, 14, 15, 16, 21, 22, 23, 24];
const MITIGATION_NUMS = [1, 2, 3, 4, 5, 6, 7, 8, 10, 11];

function bundle() {
  return {
    objects: [
      SANDWORM, TRICKBOT, LOCKBIT_GROUP, LOCKBIT_MALWARE, REVOKED_GHOST,
      ...TECHNIQUE_NUMS.map(technique),
      ...MITIGATION_NUMS.map(mitigation),

      // Sandworm uses T1, T2. M1 addresses both (top rank), M2 addresses one.
      uses(SANDWORM.id, T(1)), uses(SANDWORM.id, T(2)),
      mitigates(M(1), T(1)), mitigates(M(1), T(2)), mitigates(M(2), T(1)),

      // TrickBot uses T11-T16 (6 techniques). 6 mitigations with a strict descending
      // technique_count, to prove the top-5 cap drops the 6th.
      ...[11, 12, 13, 14, 15, 16].map((n) => uses(TRICKBOT.id, T(n))),
      mitigates(M(3), T(11)), mitigates(M(3), T(12)), mitigates(M(3), T(13)), mitigates(M(3), T(14)), mitigates(M(3), T(15)), mitigates(M(3), T(16)),
      mitigates(M(4), T(11)), mitigates(M(4), T(12)), mitigates(M(4), T(13)), mitigates(M(4), T(14)), mitigates(M(4), T(15)),
      mitigates(M(5), T(11)), mitigates(M(5), T(12)), mitigates(M(5), T(13)), mitigates(M(5), T(14)),
      mitigates(M(6), T(11)), mitigates(M(6), T(12)), mitigates(M(6), T(13)),
      mitigates(M(7), T(11)), mitigates(M(7), T(12)),
      mitigates(M(8), T(11)),

      // LockBit-the-group uses T21, T22; LockBit-the-malware (a distinct STIX object sharing
      // the same name) uses T23, T24 -- both the 'actor' and 'family' dictionary entries are
      // spelled exactly "LockBit", so both searches hit the same two STIX objects and both get
      // the identical unioned technique set {T21,T22,T23,T24}.
      uses(LOCKBIT_GROUP.id, T(21)), uses(LOCKBIT_GROUP.id, T(22)),
      uses(LOCKBIT_MALWARE.id, T(23)), uses(LOCKBIT_MALWARE.id, T(24)),
      mitigates(M(10), T(21)), mitigates(M(10), T(23)),
      mitigates(M(11), T(21)),
    ],
  };
}

test('buildRows ranks mitigations by technique_count, highest first', () => {
  const rows = buildRows(bundle(), [{ name: 'Sandworm', aliases: [] }], []);
  assert.deepStrictEqual(rows.map((r) => [r.mitigationId, r.techniqueCount]), [['M1001', 2], ['M1002', 1]]);
  assert.ok(rows.every((r) => r.subjectType === 'actor' && r.subjectName === 'Sandworm'));
});

test('buildRows caps a subject at the top 5 mitigations', () => {
  const rows = buildRows(bundle(), [], [{ name: 'TrickBot', aliases: [] }]);
  assert.strictEqual(rows.length, 5);
  assert.deepStrictEqual(rows.map((r) => r.techniqueCount), [6, 5, 4, 3, 2]);
  assert.ok(!rows.some((r) => r.mitigationId === 'M1008'), 'the 6th-ranked mitigation must be dropped by the cap');
});

test('buildRows unions technique sets when a name matches more than one STIX object', () => {
  const rows = buildRows(bundle(), [{ name: 'LockBit', aliases: [] }], [{ name: 'LockBit', aliases: [] }]);
  const actorRow = rows.find((r) => r.subjectType === 'actor' && r.mitigationId === 'M1010');
  const familyRow = rows.find((r) => r.subjectType === 'family' && r.mitigationId === 'M1010');
  // Both dictionary entries search the same STIX candidate pool and match the same two
  // objects, so both get the identical unioned set {T21,T22,T23,T24} -- M1010 addresses 2 of
  // those 4 regardless of which dictionary the row is filed under.
  assert.strictEqual(actorRow.techniqueCount, 2);
  assert.strictEqual(familyRow.techniqueCount, 2);
});

test('a revoked STIX object is excluded from matching entirely', () => {
  assert.deepStrictEqual(buildRows(bundle(), [{ name: 'GhostGroup', aliases: [] }], []), []);
});

test('a name with no ATT&CK match produces no rows, not an error', () => {
  assert.deepStrictEqual(buildRows(bundle(), [{ name: 'Totally Unlisted Group', aliases: [] }], []), []);
});

test('backfill writes rows to attack_mitigations and a rerun replaces rather than accumulates', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const requestFn = async () => ({ status: 200, headers: {}, body: JSON.stringify(bundle()) });
    // Real ACTORS/FAMILIES (data/threat-actors.json, data/malware-families.json) already
    // contain 'Sandworm', 'TrickBot' and 'LockBit' by name, so the default dictionaries match
    // this fixture bundle without needing an override.
    const r1 = await backfill(store, { requestFn, now: () => new Date('2026-08-06T00:00:00Z') });
    assert.ok(r1.rows > 0);
    const rows1 = await store.all('SELECT subject_type, subject_name FROM attack_mitigations');
    assert.ok(rows1.length > 0);

    const r2 = await backfill(store, { requestFn, now: () => new Date('2026-08-07T00:00:00Z') });
    const rows2 = await store.all('SELECT subject_type, subject_name FROM attack_mitigations');
    assert.strictEqual(rows2.length, rows1.length, 'a rerun must not accumulate duplicate rows');
    assert.strictEqual(r2.rows, r1.rows);
  } finally { await cleanup(); }
});

test('backfill --dry-run writes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const requestFn = async () => ({ status: 200, headers: {}, body: JSON.stringify(bundle()) });
    await backfill(store, { requestFn, dryRun: true, now: () => new Date('2026-08-06T00:00:00Z') });
    const rows = await store.all('SELECT 1 FROM attack_mitigations');
    assert.strictEqual(rows.length, 0);
  } finally { await cleanup(); }
});
