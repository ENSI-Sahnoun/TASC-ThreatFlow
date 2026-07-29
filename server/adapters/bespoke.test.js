const test = require('node:test');
const assert = require('node:assert');
const bespoke = require('./bespoke');

test('kev marks items actively_exploited with vendor', async () => {
  const body = JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2024-9', vendorProject: 'Acme', product: 'Widget', shortDescription: 'bad', dateAdded: '2024-05-05' }] });
  const source = { url: 'x', requestBody: '10' };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }) };
  const items = await bespoke.kev.fetch(source, ctx);
  assert.strictEqual(items[0].native.cveIds[0], 'CVE-2024-9');
  assert.strictEqual(items[0].native.exploitation, 'actively_exploited');
  assert.strictEqual(items[0].native.vendor, 'Acme');
});

test('epss marks high-score CVEs likely', async () => {
  const body = JSON.stringify({ data: [{ cve: 'CVE-2025-5', epss: '0.90', percentile: '0.99', date: '2025-01-01' }] });
  const source = { url: 'x', requestBody: '5' };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }) };
  const items = await bespoke.epss.fetch(source, ctx);
  assert.strictEqual(items[0].native.exploitation, 'likely');
});

test('vulnetix parses real CVEListV5 /gcve records, sends dated range + ApiKey header', async () => {
  const record = {
    cveMetadata: { cveId: 'CVE-2026-9720', datePublished: '2026-07-29T09:16:30Z' },
    containers: {
      cna: {
        descriptions: [{ lang: 'en', value: 'CSRF in a WordPress plugin.' }],
        metrics: [
          { cvssV3_1: { baseScore: 4.3, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:N' } },
          { cvssV4_0: { baseScore: 6.8, baseSeverity: 'MEDIUM', vectorString: 'CVSS:4.0/AV:N' } },
        ],
      },
      adp: [{ x_dataSource: 'nist-nvd' }],
    },
  };
  const gcveBody = JSON.stringify({ timestamp: 1, total: 1, limit: 50, offset: 0, hasMore: false, records: [record] });
  const exploitsBody = JSON.stringify({ results: [] });
  const seenUrls = [];
  let seenHeaders = null;
  const source = { url: 'https://api.vdb.vulnetix.com/v1/gcve', api_key: 'org-uuid:hexkey' };
  const ctx = {
    now: () => new Date('2026-07-29T12:00:00Z'),
    request: async (url, opts) => {
      seenUrls.push(url);
      seenHeaders = opts.headers;
      return { status: 200, headers: {}, body: url.includes('/exploits') ? exploitsBody : gcveBody };
    },
  };
  const items = await bespoke.vulnetix.fetch(source, ctx);
  assert.strictEqual(seenUrls[0], 'https://api.vdb.vulnetix.com/v1/gcve?start=2026-07-28&end=2026-07-29&limit=50');
  assert.strictEqual(seenUrls[1], 'https://api.vdb.vulnetix.com/v1/exploits?limit=25&sort=recent');
  assert.strictEqual(seenHeaders.Authorization, 'ApiKey org-uuid:hexkey');
  assert.strictEqual(items.length, 1);
  assert.strictEqual(items[0].external_id, 'CVE-2026-9720');
  assert.strictEqual(items[0].native.cveIds[0], 'CVE-2026-9720');
  // cvssV4_0 wins over cvssV3_1 when both are present.
  assert.strictEqual(items[0].native.cvssScore, 6.8);
  assert.strictEqual(items[0].native.severity, 'medium');
  assert.strictEqual(items[0].summary, 'CSRF in a WordPress plugin.');
  assert.strictEqual(items[0].author, 'NIST-NVD');
});

test('vulnetix merges /exploits into a matching /gcve CVE and adds exploits-only CVEs', async () => {
  const gcveRecord = {
    cveMetadata: { cveId: 'CVE-2026-1111', datePublished: '2026-07-29T00:00:00Z' },
    containers: { cna: { descriptions: [{ lang: 'en', value: 'Some RCE.' }], metrics: [] }, adp: [] },
  };
  const gcveBody = JSON.stringify({ records: [gcveRecord] });
  const exploitsBody = JSON.stringify({
    results: [
      // Matches the /gcve CVE — should upgrade exploitation + fill in missing cvss/severity.
      { cveId: 'CVE-2026-1111', kev: { inCisaKev: true }, metrics: { highestScore: 9.8, highestSeverity: 'CRITICAL' } },
      // Not in the /gcve window — should be added as its own item.
      {
        cveId: 'CVE-2025-2222', title: 'Old but exploited', description: 'Actively exploited in the wild.',
        kev: { inCisaKev: true }, metrics: { highestScore: 8.1, highestSeverity: 'HIGH' },
        timeline: { datePublished: '2025-01-01T00:00:00Z' }, provenance: { source: 'cisa' },
      },
    ],
  });
  const source = { url: 'https://api.vdb.vulnetix.com/v1/gcve', api_key: 'k' };
  const ctx = {
    now: () => new Date('2026-07-29T12:00:00Z'),
    request: async (url) => ({ status: 200, headers: {}, body: url.includes('/exploits') ? exploitsBody : gcveBody }),
  };
  const items = await bespoke.vulnetix.fetch(source, ctx);
  assert.strictEqual(items.length, 2);
  const merged = items.find((i) => i.external_id === 'CVE-2026-1111');
  assert.strictEqual(merged.summary, 'Some RCE.'); // /gcve's description wins
  assert.strictEqual(merged.native.exploitation, 'actively_exploited'); // upgraded by /exploits
  assert.strictEqual(merged.native.cvssScore, 9.8); // filled in — /gcve had none
  assert.strictEqual(merged.native.severity, 'critical');
  const exploitsOnly = items.find((i) => i.external_id === 'CVE-2025-2222');
  assert.ok(exploitsOnly);
  assert.strictEqual(exploitsOnly.native.exploitation, 'actively_exploited');
  assert.strictEqual(exploitsOnly.summary, 'Actively exploited in the wild.');
  assert.strictEqual(exploitsOnly.author, 'CISA');
});
