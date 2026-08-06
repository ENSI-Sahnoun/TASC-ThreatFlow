const test = require('node:test');
const assert = require('node:assert');
const { buildIocPlaybook } = require('./ioc');
const { buildAttackMitigationsMap } = require('./attack-mitigations');

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

const ATTACK_MAP = buildAttackMitigationsMap([
  { subject_type: 'family', subject_name: 'Mirai', mitigation_id: 'M1030', mitigation_name: 'Network Segmentation', mitigation_url: 'https://attack.mitre.org/mitigations/M1030/', technique_count: 6, synced_at: '2026-08-06T00:00:00Z' },
]);

test('no indicators yields no playbook at all', () => {
  assert.strictEqual(buildIocPlaybook({ families: [], iocs: [], attackMitigations: new Map() }), null);
  assert.strictEqual(buildIocPlaybook({ families: ['Mirai'], iocs: [], attackMitigations: ATTACK_MAP }), null);
});

test('block-iocs and watch-reoccurrence appear once indicators exist', () => {
  const steps = buildIocPlaybook({ families: [], iocs: [{ type: 'ip', value: '198.51.100.9' }], attackMitigations: new Map() });
  assert.ok(find(steps, 'ioc:block-iocs'));
  assert.ok(find(steps, 'ioc:watch-reoccurrence'));
  assert.match(find(steps, 'ioc:block-iocs').detail, /198\.51\.100\.9/);
});

test('attack-mitigation appears and links out when a family matches the table', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }], attackMitigations: ATTACK_MAP });
  const step = find(steps, 'ioc:attack-mitigation');
  assert.ok(step);
  assert.match(step.detail, /Network Segmentation \(M1030, addresses 6 techniques\)/);
  assert.match(step.link, /^https:\/\/attack\.mitre\.org\/mitigations\//);
});

test('attack-mitigation is absent when no family matches the table', () => {
  const steps = buildIocPlaybook({ families: ['Some Unlisted Family'], iocs: [{ type: 'ip', value: '198.51.100.9' }], attackMitigations: ATTACK_MAP });
  assert.ok(!find(steps, 'ioc:attack-mitigation'));
});

test('every emitted step carries a non-empty source', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }], attackMitigations: ATTACK_MAP });
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }], attackMitigations: ATTACK_MAP });
  assert.deepStrictEqual(keysOf(steps), ['ioc:block-iocs', 'ioc:attack-mitigation', 'ioc:watch-reoccurrence']);
});
