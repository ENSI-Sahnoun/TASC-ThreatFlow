const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { classifyQuality, buildPrompt, VERDICTS, CLASSIFIED_CATEGORIES } = require('./quality');

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
  const mk = async (category, title) => (await store.get(
    `INSERT INTO items (source_id, category, title, external_id, published_at)
     VALUES ($1,$2,$3,$3, now()) RETURNING id`, [src.id, category, title])).id;

  return {
    newsId: await mk('news', 'Scattered Spider hackers sentenced over theft'),
    podcastId: await mk('news', 'ISC Stormcast For Friday, July 17th'),
    cveId: await mk('cve', 'CVE-2026-1'),
    phishId: await mk('phishing', 'Phishing page on evil.test'),
  };
}

function fakeJudge(replies) {
  const queue = [...replies];
  return async () => (queue.length ? queue.shift() : null);
}

test('VERDICTS are the four shapes security feeds actually carry', () => {
  assert.deepStrictEqual(VERDICTS, ['intel', 'roundup', 'commentary', 'promotion']);
});

// A CVE row is structurally intel; classifying it would spend inference to learn nothing.
test('only news and osint categories are classified', () => {
  assert.deepStrictEqual(CLASSIFIED_CATEGORIES, ['news', 'osint']);
});

test('buildPrompt gives concrete examples, not abstract definitions', () => {
  const p = buildPrompt({ title: 'Some headline' });
  assert.match(p, /Some headline/);
  assert.match(p, /Weekly Recap/);   // roundup example
  assert.match(p, /Stormcast/);      // commentary example
  assert.match(p, /-> promotion/);
});

test('buildPrompt includes the summary when the item has one', () => {
  assert.match(buildPrompt({ title: 'T', summary: 'A detailed description.' }), /A detailed description/);
  assert.ok(!/Summary:/.test(buildPrompt({ title: 'T' })));
});

test('classifyQuality writes a verdict per news item and skips other categories', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { cveId, phishId } = await seed(store);
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'commentary' }]) });

    assert.strictEqual(res.considered, 2, 'only the two news rows');
    assert.strictEqual(res.written, 2);
    const rows = await store.all('SELECT item_id FROM item_quality');
    assert.ok(!rows.some((r) => r.item_id === cveId), 'cve rows are not classified');
    assert.ok(!rows.some((r) => r.item_id === phishId), 'phishing rows are not classified');
  } finally { await cleanup(); }
});

test('classifyQuality reports a breakdown by verdict', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'commentary' }]) });
    assert.strictEqual(res.counts.intel, 1);
    assert.strictEqual(res.counts.commentary, 1);
    assert.strictEqual(res.counts.roundup, 0);
  } finally { await cleanup(); }
});

// Absence over fabrication.
test('a failed judgement writes nothing and is retried next run', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const first = await classifyQuality(store, { judge: fakeJudge([null, null]) });
    assert.strictEqual(first.written, 0);
    assert.strictEqual(first.failed, 2);
    assert.strictEqual((await store.all('SELECT 1 FROM item_quality')).length, 0);

    const second = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'roundup' }]) });
    assert.strictEqual(second.written, 2, 'the failed items came back around');
  } finally { await cleanup(); }
});

test('classifyQuality does not re-classify an item it already judged', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'intel' }]) });
    const second = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'promotion' }]) });
    assert.strictEqual(second.considered, 0);
    assert.strictEqual(second.written, 0);
  } finally { await cleanup(); }
});

// The model cannot remove anything — the guarantee that makes a wrong verdict survivable.
test('classification never deletes or alters the item itself', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const before = await store.all('SELECT id, title, category, severity FROM items ORDER BY id');
    await classifyQuality(store, { judge: fakeJudge([{ verdict: 'promotion' }, { verdict: 'promotion' }]) });
    const after = await store.all('SELECT id, title, category, severity FROM items ORDER BY id');
    assert.deepStrictEqual(after, before);
  } finally { await cleanup(); }
});

test('classifyQuality honours a limit so a batch can be capped', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }]), limit: 1 });
    assert.strictEqual(res.considered, 1);
  } finally { await cleanup(); }
});
