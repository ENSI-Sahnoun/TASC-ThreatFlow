const test = require('node:test');
const assert = require('node:assert');
const { enrichItem, extractCves, extractIocs } = require('./enrich');
const { normalizedItem } = require('./adapters/shape');

test('extractCves finds CVE ids case-insensitively', () => {
  assert.deepStrictEqual(extractCves('fixes cve-2024-1234 and CVE-2025-99999'), ['CVE-2024-1234', 'CVE-2025-99999']);
});

test('extractIocs types ips, domains, hashes', () => {
  const iocs = extractIocs('c2 at 8.8.8.8 domain evil.example hash d41d8cd98f00b204e9800998ecf8427e');
  assert.ok(iocs.some((i) => i.type === 'ip' && i.value === '8.8.8.8'));
  assert.ok(iocs.some((i) => i.type === 'md5'));
});

test('enrichItem tags exploitation from KEV set and derives severity', () => {
  const item = normalizedItem({ title: 'Critical RCE CVE-2024-1234', summary: 'exploited in the wild', category: 'news', native: { cvssScore: 9.8 } });
  const out = enrichItem(item, { kevCveSet: new Set(['CVE-2024-1234']) });
  assert.deepStrictEqual(out.cves, ['CVE-2024-1234']);
  assert.strictEqual(out.exploitationStatus, 'actively_exploited');
  assert.strictEqual(out.severity, 'critical');
});

test('enrichItem never attaches CVEs for phishing items, even with an incidental mention', () => {
  const item = normalizedItem({
    title: 'Phishing kit exploits CVE-2024-1234', summary: 'lure page', category: 'phishing',
    native: { cvssScore: 9.8 },
  });
  const out = enrichItem(item, { kevCveSet: new Set(['CVE-2024-1234']) });
  assert.deepStrictEqual(out.cves, []);
});

test('enrichItem matches known actor and malware family', () => {
  const item = normalizedItem({ title: 'LockBit affiliate deploys Cobalt Strike', summary: 'APT28 involved', category: 'malware' });
  const out = enrichItem(item, { kevCveSet: new Set() });
  assert.ok(out.families.includes('Cobalt Strike'));
  assert.ok(out.actors.includes('APT28'));
  assert.ok(out.domains.includes('malware'));
});

test('enrichItem never emits a non-canonical severity', () => {
  const blob = '{"{\\"type\\":\\"CVSS_V3\\",\\"score\\":\\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\\"}"}';
  const out = enrichItem({ title: 'x', summary: '', category: 'cve', native: { severity: blob } });
  assert.strictEqual(out.severity, 'unknown');
});

test('enrichItem scores a CVSS vector when the feed gives no number', () => {
  const out = enrichItem({
    title: 'x', summary: '', category: 'cve',
    native: { cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  });
  assert.strictEqual(out.cvssScore, 9.8);
  assert.strictEqual(out.severity, 'critical');
});

test('enrichItem maps vendor severity words', () => {
  const out = enrichItem({ title: 'x', summary: '', category: 'cve', native: { severity: 'Important' } });
  assert.strictEqual(out.severity, 'high');
});

test('enrichItem carries the EPSS probability through', () => {
  const out = enrichItem({ title: 'x', summary: '', category: 'cve', native: { epssScore: 0.99999 } });
  assert.strictEqual(out.epssScore, 0.99999);
  // absent is null, never undefined — the column is nullable and writeItem binds it directly
  assert.strictEqual(enrichItem({ title: 'x', summary: '', category: 'cve' }).epssScore, null);
});
