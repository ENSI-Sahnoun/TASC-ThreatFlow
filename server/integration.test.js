const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { seedFromConfig, configByName } = require('./seed');
const { syncSource, loadKevCveSet } = require('./fetchers');

const LIVE = process.env.RUN_LIVE === '1';

test('live: KEV ingests and enriches', { skip: !LIVE }, async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedFromConfig(store);
    const src = await store.get("SELECT * FROM sources WHERE name = 'CISA Known Exploited Vulnerabilities'");
    const res = await syncSource(src, { store, kevCveSet: await loadKevCveSet(store), configByName: configByName() });
    assert.strictEqual(res.status, 'ok');
    assert.ok(res.itemsFetched > 0);
    const exploited = (await store.get("SELECT COUNT(*)::int AS c FROM items WHERE exploitation_status='actively_exploited'")).c;
    assert.ok(exploited > 0, 'KEV items marked actively exploited');
  } finally { await cleanup(); }
});

test('live: an RSS news source ingests', { skip: !LIVE }, async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedFromConfig(store);
    const src = await store.get("SELECT * FROM sources WHERE name = 'BleepingComputer'");
    const res = await syncSource(src, { store, kevCveSet: new Set(), configByName: configByName() });
    assert.strictEqual(res.status, 'ok', res.status);
    assert.ok(res.itemsFetched > 0);
  } finally { await cleanup(); }
});
