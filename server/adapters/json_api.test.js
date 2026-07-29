const test = require('node:test');
const assert = require('node:assert');
const jsonApi = require('./json_api');

test('json_api maps records via recordsPath + mapping + enrichHints', async () => {
  const body = JSON.stringify({ value: [{ CVE: 'CVE-2025-1', bugzilla_description: 'desc', public_date: '2025-01-01', cvss3_score: '9.8', severity: 'critical', resource_url: 'https://rh/1' }] });
  const source = { category: 'Vendor Advisory', recordsPath: 'value', mapping: { title: 'CVE', summary: 'bugzilla_description', link: 'resource_url', date: 'public_date', id: 'CVE' }, enrichHints: { cveField: 'CVE', cvssField: 'cvss3_score', severityField: 'severity' } };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body }) };
  const items = await jsonApi.fetch(source, ctx);
  assert.strictEqual(items.length, 1);
  assert.strictEqual(items[0].title, 'CVE-2025-1');
  assert.deepStrictEqual(items[0].native.cveIds, ['CVE-2025-1']);
  assert.strictEqual(items[0].native.cvssScore, 9.8);
  assert.strictEqual(items[0].native.severity, 'critical');
});

test('json_api falls back to top-level array', async () => {
  const body = JSON.stringify([{ Name: 'Adobe', Description: 'breach', BreachDate: '2024-01-01', Domain: 'adobe.com' }]);
  const source = { category: 'Data Breaches', recordsPath: null, mapping: { title: 'Name', summary: 'Description', link: 'Domain', date: 'BreachDate', id: 'Name' } };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body }) };
  const items = await jsonApi.fetch(source, ctx);
  assert.strictEqual(items[0].title, 'Adobe');
});
