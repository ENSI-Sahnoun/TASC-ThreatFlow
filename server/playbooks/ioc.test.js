const test = require('node:test');
const assert = require('node:assert');
const { buildIocPlaybook } = require('./ioc');

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

test('no indicators yields no playbook at all', () => {
  assert.strictEqual(buildIocPlaybook({ families: [], iocs: [] }), null);
  assert.strictEqual(buildIocPlaybook({ families: ['Mirai'], iocs: [] }), null);
});

test('block-iocs and watch-reoccurrence appear once indicators exist', () => {
  const steps = buildIocPlaybook({ families: [], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  assert.ok(find(steps, 'ioc:block-iocs'));
  assert.ok(find(steps, 'ioc:watch-reoccurrence'));
  assert.match(find(steps, 'ioc:block-iocs').detail, /198\.51\.100\.9/);
});

test('attack-mitigation appears and links out when a family is in the curated map', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  const step = find(steps, 'ioc:attack-mitigation');
  assert.ok(step);
  assert.match(step.detail, /Mirai/);
  assert.match(step.link, /^https:\/\/attack\.mitre\.org\/mitigations\//);
});

test('attack-mitigation is absent when no family matches the curated map', () => {
  const steps = buildIocPlaybook({ families: ['Some Unlisted Family'], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  assert.ok(!find(steps, 'ioc:attack-mitigation'));
});

test('every emitted step carries a non-empty source', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = buildIocPlaybook({ families: ['Mirai'], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  assert.deepStrictEqual(keysOf(steps), ['ioc:block-iocs', 'ioc:attack-mitigation', 'ioc:watch-reoccurrence']);
});
