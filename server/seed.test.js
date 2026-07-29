const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { seedFromConfig } = require('./seed');
const { SOURCES } = require('./sources.config');

test('seedFromConfig inserts all config sources once', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const r1 = await seedFromConfig(store);
    assert.strictEqual(r1.inserted, SOURCES.length);
    const r2 = await seedFromConfig(store); // idempotent
    assert.strictEqual(r2.inserted, 0);
    const active = (await store.get('SELECT COUNT(*)::int AS c FROM sources WHERE active = true')).c;
    assert.strictEqual(active, SOURCES.filter((s) => s.active).length);
  } finally { await cleanup(); }
});

test('seedFromConfig preserves operator active edits', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedFromConfig(store);
    await store.run("UPDATE sources SET active = true WHERE name = 'AlienVault OTX'");
    await seedFromConfig(store);
    const otx = await store.get("SELECT active FROM sources WHERE name = 'AlienVault OTX'");
    assert.strictEqual(otx.active, true); // not reset to false
  } finally { await cleanup(); }
});
