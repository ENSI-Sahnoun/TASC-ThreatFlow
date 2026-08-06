const test = require('node:test');
const assert = require('node:assert');
const { attackStep, buildAttackMitigationsMap } = require('./attack-mitigations');

function fixtureMap() {
  return buildAttackMitigationsMap([
    { subject_type: 'actor', subject_name: 'LockBit', mitigation_id: 'M1053', mitigation_name: 'Data Backup', mitigation_url: 'https://attack.mitre.org/mitigations/M1053/', technique_count: 7, synced_at: '2026-08-06T00:00:00Z' },
    { subject_type: 'actor', subject_name: 'LockBit', mitigation_id: 'M1040', mitigation_name: 'Behavior Prevention on Endpoint', mitigation_url: 'https://attack.mitre.org/mitigations/M1040/', technique_count: 3, synced_at: '2026-08-06T00:00:00Z' },
    { subject_type: 'family', subject_name: 'LockBit', mitigation_id: 'M1053', mitigation_name: 'Data Backup', mitigation_url: 'https://attack.mitre.org/mitigations/M1053/', technique_count: 2, synced_at: '2026-08-06T00:00:00Z' },
  ]);
}

test('a matched subject returns its mitigations, richest first', () => {
  const result = attackStep('LockBit', 'actor', fixtureMap());
  assert.strictEqual(result.length, 2);
  assert.strictEqual(result[0].id, 'M1053');
  assert.strictEqual(result[0].techniqueCount, 7);
  assert.strictEqual(result[0].syncedAt, '2026-08-06');
});

test('subject_type disambiguates -- the same name in a different dictionary gets its own row set', () => {
  const result = attackStep('LockBit', 'family', fixtureMap());
  assert.strictEqual(result.length, 1);
  assert.strictEqual(result[0].techniqueCount, 2);
});

test('an unmatched name returns null', () => {
  assert.strictEqual(attackStep('NotARealGroup', 'actor', fixtureMap()), null);
});

test('no partial or fuzzy match', () => {
  assert.strictEqual(attackStep('Lock', 'actor', fixtureMap()), null);
  assert.strictEqual(attackStep('lockbitx', 'actor', fixtureMap()), null);
});

test('the wrong subject_type for an otherwise-matching name returns null', () => {
  const map = buildAttackMitigationsMap([
    { subject_type: 'actor', subject_name: 'Emotet', mitigation_id: 'M1049', mitigation_name: 'Antivirus/Antimalware', mitigation_url: 'https://attack.mitre.org/mitigations/M1049/', technique_count: 4, synced_at: '2026-08-06T00:00:00Z' },
  ]);
  assert.strictEqual(attackStep('Emotet', 'family', map), null);
});

test('null/empty name, subject_type or map returns null', () => {
  assert.strictEqual(attackStep(null, 'actor', fixtureMap()), null);
  assert.strictEqual(attackStep('LockBit', null, fixtureMap()), null);
  assert.strictEqual(attackStep('LockBit', 'actor', null), null);
});

test('lookup is case-insensitive', () => {
  const map = buildAttackMitigationsMap([
    { subject_type: 'actor', subject_name: 'APT28', mitigation_id: 'M1017', mitigation_name: 'User Training', mitigation_url: 'https://attack.mitre.org/mitigations/M1017/', technique_count: 5, synced_at: '2026-08-06T00:00:00Z' },
  ]);
  assert.ok(attackStep('apt28', 'actor', map));
  assert.ok(attackStep('APT28', 'actor', map));
});
