const test = require('node:test');
const assert = require('node:assert');
const { buildPhishingPlaybook } = require('./phishing');

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

const base = (over = {}) => buildPhishingPlaybook({ iocs: [], ...over });

test('confirm and check-clicked are always present', () => {
  const steps = base();
  assert.ok(find(steps, 'phishing:confirm'));
  assert.ok(find(steps, 'phishing:check-clicked'));
});

test('block-iocs appears and lists indicator values when iocs are present', () => {
  const steps = base({ iocs: [{ type: 'url', value: 'https://evil.example/login' }] });
  assert.match(find(steps, 'phishing:block-iocs').detail, /https:\/\/evil\.example\/login/);
});

test('block-iocs is absent when there are no iocs', () => {
  assert.ok(!find(base(), 'phishing:block-iocs'));
});

test('report-phishing-url appears only when a url-typed IOC is present', () => {
  assert.ok(find(base({ iocs: [{ type: 'url', value: 'https://evil.example' }] }), 'phishing:report-phishing-url'));
  assert.ok(!find(base({ iocs: [{ type: 'ip', value: '203.0.113.5' }] }), 'phishing:report-phishing-url'));
  assert.ok(!find(base({ iocs: [] }), 'phishing:report-phishing-url'));
});

test('every emitted step carries a non-empty source', () => {
  const steps = base({ iocs: [{ type: 'url', value: 'https://evil.example' }] });
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = base({ iocs: [{ type: 'url', value: 'https://evil.example' }] });
  assert.deepStrictEqual(keysOf(steps), [
    'phishing:confirm', 'phishing:block-iocs', 'phishing:report-phishing-url', 'phishing:check-clicked',
  ]);
});

test('the minimal case still yields confirm and check-clicked', () => {
  assert.deepStrictEqual(keysOf(base()), ['phishing:confirm', 'phishing:check-clicked']);
});
