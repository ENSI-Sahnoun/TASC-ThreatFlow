const test = require('node:test');
const assert = require('node:assert');
const { buildRansomwarePlaybook } = require('./ransomware');

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

const base = (over = {}) => buildRansomwarePlaybook({
  title: 'Acme Corp (LockBit)', actors: ['LockBit'], iocs: [], ...over,
});

// --- confirm: always ---

test('confirm is always present and names the victim, stripped of the trailing group suffix', () => {
  const steps = base();
  assert.match(find(steps, 'ransomware:confirm').detail, /Acme Corp/);
  assert.doesNotMatch(find(steps, 'ransomware:confirm').detail, /\(LockBit\)/);
});

test('confirm falls back to the raw title when there is no matched actor', () => {
  const steps = base({ title: 'Some Victim Co', actors: [] });
  assert.match(find(steps, 'ransomware:confirm').detail, /Some Victim Co/);
});

test('confirm stays generic when there is no title at all', () => {
  const steps = base({ title: null, actors: [] });
  assert.match(find(steps, 'ransomware:confirm').detail, /the named organization/);
});

// --- attack-mitigation: actor matched in curated map ---

test('attack-mitigation appears and links out when the actor is in the curated map', () => {
  const steps = base({ actors: ['LockBit'] });
  const step = find(steps, 'ransomware:attack-mitigation');
  assert.ok(step);
  assert.match(step.detail, /LockBit/);
  assert.match(step.link, /^https:\/\/attack\.mitre\.org\/mitigations\//);
  assert.strictEqual(step.source, 'data/attack-mitigations.json');
});

test('attack-mitigation is absent when no actor matches the curated map', () => {
  assert.ok(!find(base({ actors: ['Some Unlisted Group'] }), 'ransomware:attack-mitigation'));
  assert.ok(!find(base({ actors: [] }), 'ransomware:attack-mitigation'));
});

// --- block-iocs: iocs.length > 0 ---

test('block-iocs appears and lists indicator values when iocs are present', () => {
  const steps = base({ iocs: [{ type: 'ip', value: '203.0.113.5' }, { type: 'url', value: 'https://evil.example' }] });
  const step = find(steps, 'ransomware:block-iocs');
  assert.match(step.detail, /203\.0\.113\.5/);
  assert.match(step.detail, /https:\/\/evil\.example/);
});

test('block-iocs is absent when there are no iocs', () => {
  assert.ok(!find(base({ iocs: [] }), 'ransomware:block-iocs'));
});

// --- always-present repo-derived steps ---

test('protect-backups, reset-credentials and payment-decision are always present', () => {
  const steps = base();
  assert.ok(find(steps, 'ransomware:protect-backups'));
  assert.ok(find(steps, 'ransomware:reset-credentials'));
  assert.ok(find(steps, 'ransomware:payment-decision'));
});

// --- source is mandatory ---

test('every emitted step carries a non-empty source', () => {
  const steps = base({ actors: ['LockBit'], iocs: [{ type: 'ip', value: '203.0.113.5' }] });
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

// --- ordering is stable ---

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = base({ actors: ['LockBit'], iocs: [{ type: 'ip', value: '203.0.113.5' }] });
  assert.deepStrictEqual(keysOf(steps), [
    'ransomware:confirm', 'ransomware:attack-mitigation', 'ransomware:block-iocs',
    'ransomware:protect-backups', 'ransomware:reset-credentials', 'ransomware:payment-decision',
  ]);
});

test('the minimal case still yields confirm plus the three always-present steps', () => {
  assert.deepStrictEqual(keysOf(base({ actors: [], iocs: [] })), [
    'ransomware:confirm', 'ransomware:protect-backups', 'ransomware:reset-credentials', 'ransomware:payment-decision',
  ]);
});
