// server/sources.config.test.js
const test = require('node:test');
const assert = require('node:assert');
const { SOURCES } = require('./sources.config');
const { isDomain } = require('./domains');

const KINDS = new Set(['rss','json_api','text_feed','osv','misp_feed','abuse_ch','kev','epss','nvd_cve','ransomware_live','feodo','unsupported']);

test('registry has >=35 sources', () => { assert.ok(SOURCES.length >= 35, `got ${SOURCES.length}`); });

test('every source has valid shape', () => {
  const names = new Set();
  for (const s of SOURCES) {
    assert.ok(s.name && !names.has(s.name), `unique name: ${s.name}`);
    names.add(s.name);
    assert.ok(KINDS.has(s.kind), `${s.name}: valid kind ${s.kind}`);
    assert.ok(Array.isArray(s.domains) && s.domains.length > 0, `${s.name}: has domains`);
    for (const d of s.domains) assert.ok(isDomain(d), `${s.name}: valid domain ${d}`);
    assert.ok(typeof s.active === 'boolean', `${s.name}: active is boolean`);
    if (s.auth) assert.ok(s.auth.env, `${s.name}: auth needs env`);
  }
});

test('key-gated sources are inactive', () => {
  for (const s of SOURCES) {
    if (s.auth) assert.strictEqual(s.active, false, `${s.name}: key-gated must start inactive`);
  }
});

test('rss sources declare a mapping', () => {
  for (const s of SOURCES.filter((x) => x.kind === 'rss')) {
    assert.ok(s.mapping && s.mapping.title, `${s.name}: rss mapping.title`);
  }
});
