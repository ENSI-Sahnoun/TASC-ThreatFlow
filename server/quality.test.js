const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { classifyQuality, buildPrompt, pickVerdict, VERDICTS, CLASSIFIED_CATEGORIES } = require('./quality');

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

test('pickVerdict: clear majority wins', () => {
  assert.strictEqual(pickVerdict(['intel', 'intel', 'intel', 'commentary', 'commentary']), 'intel');
});

test('pickVerdict: a lone valid vote wins outright', () => {
  assert.strictEqual(pickVerdict(['promotion']), 'promotion');
});

test('pickVerdict: a 2-2-1 tie for the top spot resolves to intel', () => {
  assert.strictEqual(pickVerdict(['roundup', 'roundup', 'commentary', 'commentary', 'promotion']), 'intel');
});

test('pickVerdict: a 1-1-1 tie resolves to intel', () => {
  assert.strictEqual(pickVerdict(['roundup', 'commentary', 'promotion']), 'intel');
});

test('pickVerdict: no valid votes returns null', () => {
  assert.strictEqual(pickVerdict([]), null);
});

test('pickVerdict: a plain majority of intel votes among survivors still wins after some failed', () => {
  // caller has already dropped the nulls before calling pickVerdict — this models 2 survivors
  // agreeing out of an original 5-shot batch where 3 failed
  assert.strictEqual(pickVerdict(['intel', 'intel']), 'intel');
});

test('classifyQuality writes a verdict per news item and skips other categories', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { cveId, phishId } = await seed(store);
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'commentary' }]), shots: 1 });

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
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'commentary' }]), shots: 1 });
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
    const first = await classifyQuality(store, { judge: fakeJudge([null, null]), shots: 1 });
    assert.strictEqual(first.written, 0);
    assert.strictEqual(first.failed, 2);
    assert.strictEqual((await store.all('SELECT 1 FROM item_quality')).length, 0);

    const second = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'roundup' }]), shots: 1 });
    assert.strictEqual(second.written, 2, 'the failed items came back around');
  } finally { await cleanup(); }
});

test('classifyQuality does not re-classify an item it already judged', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }, { verdict: 'intel' }]), shots: 1 });
    const second = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'promotion' }]), shots: 1 });
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
    await classifyQuality(store, { judge: fakeJudge([{ verdict: 'promotion' }, { verdict: 'promotion' }]), shots: 1 });
    const after = await store.all('SELECT id, title, category, severity FROM items ORDER BY id');
    assert.deepStrictEqual(after, before);
  } finally { await cleanup(); }
});

test('classifyQuality honours a limit so a batch can be capped', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const res = await classifyQuality(store, { judge: fakeJudge([{ verdict: 'intel' }]), limit: 1, shots: 1 });
    assert.strictEqual(res.considered, 1);
  } finally { await cleanup(); }
});

test('classifyQuality with shots > 1 takes a majority vote per item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
    const itemId = (await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Some headline','x', now()) RETURNING id`, [src.id])).id;

    // 3 votes for intel, 2 for commentary — intel should win.
    const judge = fakeJudge([
      { verdict: 'intel' }, { verdict: 'intel' }, { verdict: 'commentary' },
      { verdict: 'intel' }, { verdict: 'commentary' },
    ]);
    const res = await classifyQuality(store, { judge, shots: 5 });

    assert.strictEqual(res.written, 1);
    const row = await store.get('SELECT verdict FROM item_quality WHERE item_id = $1', [itemId]);
    assert.strictEqual(row.verdict, 'intel');
  } finally { await cleanup(); }
});

test('classifyQuality: an item fails as a whole only when every shot fails', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Some headline','x', now())`, [src.id]);

    // 2 real answers survive, 3 shots fail — should still write a verdict from the 2 survivors.
    const judge = fakeJudge([
      { verdict: 'promotion' }, null, { verdict: 'promotion' }, null, null,
    ]);
    const res = await classifyQuality(store, { judge, shots: 5 });

    assert.strictEqual(res.written, 1);
    assert.strictEqual(res.failed, 0);
    const row = await store.get('SELECT verdict FROM item_quality');
    assert.strictEqual(row.verdict, 'promotion');
  } finally { await cleanup(); }
});

test('classifyQuality: all shots failing writes nothing and counts as one failure', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Some headline','x', now())`, [src.id]);

    const judge = fakeJudge([null, null, null, null, null]);
    const res = await classifyQuality(store, { judge, shots: 5 });

    assert.strictEqual(res.written, 0);
    assert.strictEqual(res.failed, 1);
    assert.strictEqual((await store.all('SELECT 1 FROM item_quality')).length, 0);
  } finally { await cleanup(); }
});

test('classifyQuality passes voteTemperature through to the judge call options', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
    await store.run(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Some headline','x', now())`, [src.id]);

    const seenTemps = [];
    const judge = async (prompt, opts) => { seenTemps.push(opts.temperature); return { verdict: 'intel' }; };
    await classifyQuality(store, { judge, shots: 3, voteTemperature: 0.9 });

    assert.deepStrictEqual(seenTemps, [0.9, 0.9, 0.9]);
  } finally { await cleanup(); }
});
