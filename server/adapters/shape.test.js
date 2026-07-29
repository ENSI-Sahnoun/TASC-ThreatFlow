const test = require('node:test');
const assert = require('node:assert');
const { normalizedItem } = require('./shape');

test('normalizedItem fills defaults', () => {
  const it = normalizedItem({ title: 'x', external_id: 'id1' });
  assert.strictEqual(it.title, 'x');
  assert.strictEqual(it.external_id, 'id1');
  assert.strictEqual(it.summary, null);
  assert.deepStrictEqual(it.native.cveIds, []);
  assert.deepStrictEqual(it.native.iocs, []);
  assert.strictEqual(it.native.vendor, null);
});

test('normalizedItem preserves provided native fields', () => {
  const it = normalizedItem({ title: 't', external_id: 'e', native: { vendor: 'Acme', cveIds: ['CVE-2024-1'] } });
  assert.strictEqual(it.native.vendor, 'Acme');
  assert.deepStrictEqual(it.native.cveIds, ['CVE-2024-1']);
  assert.deepStrictEqual(it.native.iocs, []); // still defaulted
});

test('normalizedItem applies presentation rules and harvests URL titles', () => {
  const item = normalizedItem({
    title: 'sh: http://202.155.8.56/RSW0',
    summary: 'malware_download',
    link: null,
    category: 'malware',
    external_id: 'x1',
  });
  assert.strictEqual(item.title, 'Malware payload (sh) · 202.155.8.56');
  assert.strictEqual(item.summary, 'Malware download');
  assert.strictEqual(item.link, 'http://202.155.8.56/RSW0');
  assert.deepStrictEqual(item.native.iocs, [{ type: 'url', value: 'http://202.155.8.56/RSW0' }]);
});

test('normalizedItem repairs bare-domain links and leaves real titles alone', () => {
  const item = normalizedItem({
    title: '000webhost', summary: null, link: '000webhost.com', category: 'data-breach', external_id: 'x2',
  });
  assert.strictEqual(item.title, '000webhost');
  assert.strictEqual(item.link, 'https://000webhost.com');
});

test('normalizedItem carries epssScore on native', () => {
  const item = normalizedItem({ title: 'CVE-2024-3400', category: 'cve', external_id: 'e1', native: { epssScore: 0.5 } });
  assert.strictEqual(item.native.epssScore, 0.5);
  assert.strictEqual(normalizedItem({ title: 'x', category: 'cve', external_id: 'e2' }).native.epssScore, null);
});

// Not in the task brief's literal diff, but required for the OSV fix (which sets
// native.cvssVector) to actually reach enrichItem() in the real sync pipeline — shape.js's
// native block is a fixed whitelist, so an unlisted field is silently dropped here.
test('normalizedItem carries cvssVector on native', () => {
  const item = normalizedItem({ title: 'CVE-2024-3400', category: 'cve', external_id: 'e1', native: { cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } });
  assert.strictEqual(item.native.cvssVector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.strictEqual(normalizedItem({ title: 'x', category: 'cve', external_id: 'e2' }).native.cvssVector, null);
});
