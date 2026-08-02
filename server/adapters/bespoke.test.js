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

test('nvd_cve paginates the publication pass and passes an apiKey header when present', async () => {
  const page0 = JSON.stringify({
    totalResults: 2500,
    vulnerabilities: [{ cve: { id: 'CVE-2026-0001', descriptions: [{ lang: 'en', value: 'First page.' }], published: '2026-06-01T00:00:00.000' } }],
  });
  const page1 = JSON.stringify({
    totalResults: 2500,
    vulnerabilities: [{ cve: { id: 'CVE-2026-0002', descriptions: [{ lang: 'en', value: 'Second page.' }], published: '2026-06-02T00:00:00.000' } }],
  });
  const empty = JSON.stringify({ totalResults: 0, vulnerabilities: [] });
  const pubUrls = [];
  const seenHeaders = [];
  const source = { url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', api_key: 'nvd-key' };
  const ctx = {
    now: () => new Date('2026-07-30T00:00:00Z'),
    sleep: async () => {},
    request: async (url, opts) => {
      seenHeaders.push(opts.headers);
      if (!url.includes('pubStartDate')) return { status: 200, headers: {}, body: empty };
      pubUrls.push(url);
      return { status: 200, headers: {}, body: pubUrls.length === 1 ? page0 : page1 };
    },
  };
  const items = await bespoke.nvd_cve.fetch(source, ctx);
  assert.strictEqual(pubUrls.length, 2, 'pass 1 paginates past startIndex 0');
  // 45-day publication window ending at now — not the old 120-day lastMod window.
  assert.match(pubUrls[0], /pubStartDate=2026-06-15T00:00:00\.000&pubEndDate=2026-07-30T00:00:00\.000&resultsPerPage=2000&startIndex=0/);
  assert.match(pubUrls[1], /startIndex=2000/);
  assert.strictEqual(seenHeaders[0].apiKey, 'nvd-key');
  assert.strictEqual(items.length, 2);
  assert.strictEqual(items[0].external_id, 'CVE-2026-0001');
  assert.strictEqual(items[1].external_id, 'CVE-2026-0002');
});

test('msrc composes title/summary from ID/Alias/Severity/dates, not the missing description field', async () => {
  const body = JSON.stringify({
    value: [
      { ID: '2011-Aug', Alias: '2011-Aug', DocumentTitle: 'Mariner Release Notes', Severity: null, InitialReleaseDate: '2011-08-02T00:00:00Z', CurrentReleaseDate: '2026-02-18T14:28:28Z', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2011-Aug' },
      { ID: '2000-Jan', Alias: '2000-Jan', DocumentTitle: 'Mariner Release Notes', Severity: null, InitialReleaseDate: '2000-01-02T00:00:00Z', CurrentReleaseDate: '2026-02-18T01:04:13Z', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2000-Jan' },
    ],
  });
  const source = { url: 'x' };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }) };
  const items = await bespoke.msrc.fetch(source, ctx);
  assert.strictEqual(items.length, 2);
  assert.notStrictEqual(items[0].title, items[1].title);
  assert.match(items[0].title, /Mariner Release Notes \(2011-Aug\)/);
  assert.match(items[0].summary, /released 2011-08-02/);
  assert.match(items[0].summary, /updated 2026-02-18/);
});

test('ghsa maps summary and cvss from a real advisory shape, without faking a vendor from the package id', async () => {
  const body = JSON.stringify([{
    ghsa_id: 'GHSA-c9hr-64h3-gxpc', cve_id: 'CVE-2026-67424', html_url: 'https://github.com/advisories/GHSA-c9hr-64h3-gxpc',
    summary: 'Guarded HTTP modules follow redirects into internal space without per-hop SSRF revalidation',
    severity: 'high', published_at: '2026-07-30T14:48:16Z',
    cvss: { score: 8.5, vector_string: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N' },
    vulnerabilities: [{ package: { ecosystem: 'pip', name: 'flyto-core' } }],
  }]);
  const source = { url: 'x', category: 'Vulnerability Intelligence' };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }) };
  const items = await bespoke.ghsa.fetch(source, ctx);
  assert.strictEqual(items[0].external_id, 'GHSA-c9hr-64h3-gxpc');
  assert.strictEqual(items[0].title, 'CVE-2026-67424');
  assert.match(items[0].summary, /SSRF revalidation/);
  assert.strictEqual(items[0].native.cvssScore, 8.5);
  assert.strictEqual(items[0].native.severity, 'high');
  assert.strictEqual(items[0].native.vendor, null);
  assert.strictEqual(items[0].category, 'cve');
});

test('dshield builds one item per attacking IP with rank/reports/targets, no per-record date', async () => {
  const body = JSON.stringify([{ rank: 1, source: '13.94.254.200', reports: 319739, targets: 1 }]);
  const source = { url: 'https://isc.sans.edu/api/topips/records', requestBody: '20', category: 'Threat Intelligence' };
  const ctx = { request: async () => ({ status: 200, headers: {}, body }), now: () => new Date('2026-07-30T00:00:00Z') };
  const items = await bespoke.dshield.fetch(source, ctx);
  assert.strictEqual(items[0].external_id, '13.94.254.200');
  assert.match(items[0].title, /13\.94\.254\.200/);
  assert.match(items[0].summary, /Rank #1/);
  assert.match(items[0].summary, /319,739 reports/);
  assert.strictEqual(items[0].published_at, '2026-07-30T00:00:00.000Z');
  assert.deepStrictEqual(items[0].native.iocs, [{ type: 'ip', value: '13.94.254.200' }]);
  assert.strictEqual(items[0].category, 'ioc');
});

function nvdCtx(byUrl) {
  const calls = [];
  return {
    calls,
    now: () => new Date('2026-08-02T00:00:00Z'),
    sleep: async () => {},
    request: async (url) => {
      calls.push(url);
      const key = url.includes('pubStartDate') ? 'pub' : 'mod';
      return { status: 200, headers: {}, body: JSON.stringify(byUrl[key] || { vulnerabilities: [], totalResults: 0 }) };
    },
  };
}

function nvdRecord(id, published, extra = {}) {
  return { cve: { id, published, descriptions: [{ lang: 'en', value: `${id} description` }], ...extra } };
}

test('nvd_cve runs a pubStartDate pass and a lastMod pass', async () => {
  const ctx = nvdCtx({
    pub: { vulnerabilities: [nvdRecord('CVE-2026-1', '2026-07-20T00:00:00')], totalResults: 1 },
    mod: { vulnerabilities: [nvdRecord('CVE-2025-9', '2025-04-01T00:00:00')], totalResults: 1 },
  });
  const items = await bespoke.nvd_cve.fetch({ url: 'https://nvd.test/cves' }, ctx);
  assert.ok(ctx.calls.some((u) => u.includes('pubStartDate')));
  assert.ok(ctx.calls.some((u) => u.includes('lastModStartDate')));
  assert.deepStrictEqual(items.map((i) => i.external_id).sort(), ['CVE-2025-9', 'CVE-2026-1']);
});

// The whole point of the change: the lastMod pass must not re-import the backlog.
test('nvd_cve discards lastMod records published beyond the age cap', async () => {
  const ctx = nvdCtx({
    pub: { vulnerabilities: [], totalResults: 0 },
    mod: { vulnerabilities: [nvdRecord('CVE-2002-1', '2002-03-01T00:00:00')], totalResults: 1 },
  });
  const items = await bespoke.nvd_cve.fetch({ url: 'https://nvd.test/cves' }, ctx);
  assert.deepStrictEqual(items, []);
});

test('nvd_cve de-duplicates a CVE returned by both passes', async () => {
  const rec = nvdRecord('CVE-2026-1', '2026-07-20T00:00:00');
  const ctx = nvdCtx({
    pub: { vulnerabilities: [rec], totalResults: 1 },
    mod: { vulnerabilities: [rec], totalResults: 1 },
  });
  const items = await bespoke.nvd_cve.fetch({ url: 'https://nvd.test/cves' }, ctx);
  assert.strictEqual(items.length, 1);
});

test('nvd_cve extracts v2 metrics and CPEs', async () => {
  const rec = nvdRecord('CVE-2026-2', '2026-07-20T00:00:00', {
    metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5.0 }, baseSeverity: 'MEDIUM' }] },
    configurations: [{ nodes: [{ cpeMatch: [{ criteria: 'cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*' }] }] }],
  });
  const ctx = nvdCtx({ pub: { vulnerabilities: [rec], totalResults: 1 }, mod: { vulnerabilities: [], totalResults: 0 } });
  const [item] = await bespoke.nvd_cve.fetch({ url: 'https://nvd.test/cves' }, ctx);
  assert.strictEqual(item.native.cvssScore, 5.0);
  assert.strictEqual(item.native.cvssVersion, '2.0');
  assert.strictEqual(item.native.severity, 'medium');
  assert.deepStrictEqual(item.native.cpes, [{ part: 'a', vendor: 'fortinet', product: 'fortios' }]);
});
