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

// Task 6's template only reaches rows the adapter rewrites. writeItem's ON CONFLICT upsert
// never revisits a row whose feed stopped returning it (OpenPhish rotates URLs), so 1,400
// rows kept a null summary until this backfill existed.
test('backfill templates a summary for bulk-IOC rows that have none', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('OpenPhish','text_feed') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, summary, link, published_at)
       VALUES ($1,'phishing','https://evil.test/login', NULL, 'https://evil.test/login', NULL)`, [s.id]);

    await backfill(store, { dryRun: false });
    const row = await store.get('SELECT summary FROM items');
    assert.strictEqual(row.summary, 'Phishing page on evil.test, reported by OpenPhish.');
  } finally { await cleanup(); }
});

test('backfill includes the first-seen date when the row has one', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('abuse.ch URLhaus','abuse_ch') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, summary, link, published_at)
       VALUES ($1,'malware','https://bad.test/x.exe', NULL, 'https://bad.test/x.exe', '2026-07-30T10:00:00Z')`, [s.id]);

    await backfill(store, { dryRun: false });
    const row = await store.get('SELECT summary FROM items');
    assert.strictEqual(row.summary, 'Malware payload on bad.test, first seen 2026-07-30, reported by abuse.ch URLhaus.');
  } finally { await cleanup(); }
});

// A real upstream summary is never replaced by a template.
test('backfill leaves an existing bulk-IOC summary alone', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('OpenPhish','text_feed') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, summary, link)
       VALUES ($1,'phishing','https://evil.test/login', 'A genuine upstream description of this page.', 'https://evil.test/login')`, [s.id]);

    await backfill(store, { dryRun: false });
    const row = await store.get('SELECT summary FROM items');
    assert.strictEqual(row.summary, 'A genuine upstream description of this page.');
  } finally { await cleanup(); }
});

test('backfill does not template non-IOC categories', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get("INSERT INTO sources (name, fetch_kind) VALUES ('News','rss') RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, summary, link)
       VALUES ($1,'news','A headline', NULL, 'https://news.test/a')`, [s.id]);

    await backfill(store, { dryRun: false });
    const row = await store.get('SELECT summary FROM items');
    assert.strictEqual(row.summary, null);
  } finally { await cleanup(); }
});
