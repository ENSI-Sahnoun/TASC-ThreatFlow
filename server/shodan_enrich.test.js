const assert = require('node:assert');
const { test } = require('node:test');
const { makeTempDb } = require('./test-helpers');
const { enrichIps } = require('./shodan_enrich');

function fakeRequest(responses) {
  return async (url) => {
    for (const [match, res] of responses) {
      if (url.includes(match)) return res;
    }
    return { status: 404, headers: {}, body: '' };
  };
}

test('enrichIps stores InternetDB data for a new IP', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const request = fakeRequest([
      ['internetdb.shodan.io/1.2.3.4', { status: 200, headers: {}, body: JSON.stringify({ ip: '1.2.3.4', ports: [22, 443], vulns: ['CVE-2021-1234'], tags: ['self-signed'], cpes: [], hostnames: [] }) }],
    ]);
    await enrichIps(store, ['1.2.3.4'], { request, apiKey: null });
    const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', ['1.2.3.4']);
    assert.ok(row);
    assert.deepStrictEqual(JSON.parse(row.ports_json), [22, 443]);
    assert.deepStrictEqual(JSON.parse(row.vulns_json), ['CVE-2021-1234']);
    assert.strictEqual(row.source, 'internetdb');
  } finally {
    await cleanup();
  }
});

test('enrichIps skips network call when cache is fresh', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    let calls = 0;
    const request = async () => { calls += 1; return { status: 200, headers: {}, body: JSON.stringify({ ports: [], vulns: [], tags: [], cpes: [], hostnames: [] }) }; };
    await enrichIps(store, ['9.9.9.9'], { request, apiKey: null });
    assert.strictEqual(calls, 1);
    await enrichIps(store, ['9.9.9.9'], { request, apiKey: null });
    assert.strictEqual(calls, 1, 'second call should hit cache, not network');
  } finally {
    await cleanup();
  }
});

test('enrichIps swallows per-IP errors without throwing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const request = async () => { throw new Error('network down'); };
    await assert.doesNotReject(enrichIps(store, ['5.5.5.5'], { request, apiKey: null }));
    const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', ['5.5.5.5']);
    assert.strictEqual(row, undefined);
  } finally {
    await cleanup();
  }
});

test('enrichIps merges Shodan host lookup fields when apiKey given', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const request = fakeRequest([
      ['internetdb.shodan.io/8.8.8.8', { status: 200, headers: {}, body: JSON.stringify({ ports: [53], vulns: [], tags: [], cpes: [], hostnames: ['dns.google'] }) }],
      ['api.shodan.io/shodan/host/8.8.8.8', { status: 200, headers: {}, body: JSON.stringify({ org: 'Google LLC', isp: 'Google LLC', city: 'Mountain View', country_code: 'US' }) }],
    ]);
    await enrichIps(store, ['8.8.8.8'], { request, apiKey: 'fake-key' });
    const row = await store.get('SELECT * FROM ip_intel WHERE ip = $1', ['8.8.8.8']);
    assert.strictEqual(row.org, 'Google LLC');
    assert.strictEqual(row.source, 'internetdb+shodan');
  } finally {
    await cleanup();
  }
});
