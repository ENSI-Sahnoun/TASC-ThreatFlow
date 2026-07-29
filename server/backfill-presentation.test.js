const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfillItem, backfill } = require('./backfill-presentation');

test('backfillItem cleans a dirty row and returns null for a clean one', () => {
  const dirty = backfillItem({
    id: 1, category: 'phishing', title: 'https://www.roblox.com.ml/users/1/profile', summary: null, link: null,
  });
  assert.strictEqual(dirty.title, 'Phishing page · www.roblox.com.ml');
  assert.strictEqual(dirty.link, 'https://www.roblox.com.ml/users/1/profile');

  assert.strictEqual(backfillItem({
    id: 2, category: 'news', title: 'A real headline', summary: 'A real summary.', link: 'https://x.test/a',
  }), null);
});

test('backfill dry run reports changes without writing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('S','text_feed') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, summary, link)
       VALUES ($1,'phishing','https://evil.test/a', 'malware_download', '000webhost.com')`, [s.id]);

    const dry = await backfill(store, { dryRun: true });
    assert.strictEqual(dry.changed, 1);
    const unchanged = await store.get('SELECT title FROM items');
    assert.strictEqual(unchanged.title, 'https://evil.test/a');

    const real = await backfill(store, { dryRun: false });
    assert.strictEqual(real.changed, 1);
    const row = await store.get('SELECT title, summary, link FROM items');
    assert.strictEqual(row.title, 'Phishing page · evil.test');
    assert.strictEqual(row.summary, 'Malware download');
    assert.strictEqual(row.link, 'https://000webhost.com');
  } finally {
    await cleanup();
  }
});

test('backfill is idempotent — a second run changes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('S','text_feed') RETURNING id");
    await store.run("INSERT INTO items (source_id, category, title) VALUES ($1,'phishing','https://evil.test/a')", [s.id]);
    await backfill(store, { dryRun: false });
    const second = await backfill(store, { dryRun: false });
    assert.strictEqual(second.changed, 0);
  } finally {
    await cleanup();
  }
});
