const test = require('node:test');
const assert = require('node:assert');
const osv = require('./osv');

test('osv flattens vulns and prefers CVE alias', async () => {
  const body = JSON.stringify({ vulns: [{ id: 'GHSA-xxxx', aliases: ['CVE-2025-77'], summary: 'RCE in lib', details: 'long details', published: '2025-02-02', references: [{ url: 'https://osv/1' }] }] });
  const source = { category: 'Vulnerability Intelligence' };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body }) };
  const items = await osv.fetch(source, ctx);
  assert.ok(items.length >= 1);
  const it = items.find((x) => x.native.cveIds.includes('CVE-2025-77'));
  assert.ok(it, 'CVE alias captured');
  assert.strictEqual(it.title, 'RCE in lib');
});
