const test = require('node:test');
const assert = require('node:assert');
const { buildCategoryPlaybook } = require('./index');

test('dispatches to the ransomware module', () => {
  const steps = buildCategoryPlaybook({ category: 'ransomware', title: 'Acme (LockBit)', actors: ['LockBit'], families: [], iocs: [] });
  assert.ok(steps.every((s) => s.key.startsWith('ransomware:')));
});

test('dispatches to the phishing module', () => {
  const steps = buildCategoryPlaybook({ category: 'phishing', title: null, actors: [], families: [], iocs: [] });
  assert.ok(steps.every((s) => s.key.startsWith('phishing:')));
});

test('dispatches to the malware module', () => {
  const steps = buildCategoryPlaybook({ category: 'malware', title: null, actors: [], families: [], iocs: [] });
  assert.ok(steps.every((s) => s.key.startsWith('malware:')));
});

test('dispatches to the data-breach module', () => {
  const steps = buildCategoryPlaybook({ category: 'data-breach', title: null, actors: [], families: [], iocs: [] });
  assert.ok(steps.every((s) => s.key.startsWith('data-breach:')));
});

test('dispatches to the ioc module, including its no-indicator null case', () => {
  assert.strictEqual(buildCategoryPlaybook({ category: 'ioc', title: null, actors: [], families: [], iocs: [] }), null);
  const steps = buildCategoryPlaybook({ category: 'ioc', title: null, actors: [], families: [], iocs: [{ type: 'ip', value: '198.51.100.9' }] });
  assert.ok(steps.every((s) => s.key.startsWith('ioc:')));
});

test('an unmapped category (cve, advisory, osint, news, other) returns null', () => {
  for (const category of ['cve', 'advisory', 'osint', 'news', 'other', undefined, null]) {
    assert.strictEqual(buildCategoryPlaybook({ category, title: null, actors: [], families: [], iocs: [] }), null);
  }
});
