const test = require('node:test');
const assert = require('node:assert');
const { buildDataBreachPlaybook } = require('./data-breach');

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

const base = (over = {}) => buildDataBreachPlaybook({ iocs: [], ...over });

test('confirm and notify-customers are always present', () => {
  const steps = base();
  assert.ok(find(steps, 'data-breach:confirm'));
  assert.ok(find(steps, 'data-breach:notify-customers'));
});

test('request-takedown appears only when a url-typed IOC is present', () => {
  assert.ok(find(base({ iocs: [{ type: 'url', value: 'https://leak.example/dump' }] }), 'data-breach:request-takedown'));
  assert.ok(!find(base({ iocs: [{ type: 'ip', value: '203.0.113.5' }] }), 'data-breach:request-takedown'));
  assert.ok(!find(base({ iocs: [] }), 'data-breach:request-takedown'));
});

test('every emitted step carries a non-empty source', () => {
  const steps = base({ iocs: [{ type: 'url', value: 'https://leak.example/dump' }] });
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = base({ iocs: [{ type: 'url', value: 'https://leak.example/dump' }] });
  assert.deepStrictEqual(keysOf(steps), [
    'data-breach:confirm', 'data-breach:notify-customers', 'data-breach:request-takedown',
  ]);
});

test('the minimal case still yields confirm and notify-customers', () => {
  assert.deepStrictEqual(keysOf(base()), ['data-breach:confirm', 'data-breach:notify-customers']);
});
