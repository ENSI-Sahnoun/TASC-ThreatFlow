const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');

test('makeTempDb returns an isolated db with items + sources tables', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const tables = (await store.all("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).map((r) => r.tablename);
    assert.ok(tables.includes('sources'), 'has sources table');
    assert.ok(tables.includes('items'), 'has items table');
  } finally {
    await cleanup();
  }
});
