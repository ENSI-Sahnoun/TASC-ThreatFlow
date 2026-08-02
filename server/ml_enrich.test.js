const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { runJob, JOBS, ML_SEVERITIES, SECTOR_SLUGS } = require('./ml_enrich');

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','rss',true) RETURNING id");
  const mk = async (over) => (await store.get(
    `INSERT INTO items (source_id, category, title, summary, external_id, severity, industry, published_at)
     VALUES ($1,$2,$3,$4,$3,$5,$6, now()) RETURNING id`,
    [src.id, over.category, over.title, over.summary ?? null, over.severity ?? null, over.industry ?? null])).id;

  return {
    // prose, unrated -> severity job. Given an industry so it does not also qualify for the
    // victim job, which targets news rows whose industry is still unknown.
    newsId: await mk({ category: 'news', title: 'Actor breaches hospital network', summary: 'A long enough summary to not be thin at all.', industry: 'technology-saas' }),
    // a CVE upstream has not scored -> must NOT be touched by the severity job
    cveId: await mk({ category: 'cve', title: 'CVE-2026-1', summary: 'A long enough summary to not be thin at all.' }),
    // thin -> summary job
    thinId: await mk({ category: 'cve', title: 'CVE-2026-2 kernel use-after-free', summary: null }),
    // bulk indicator -> excluded from the summary job
    phishId: await mk({ category: 'phishing', title: 'Phishing page', summary: null }),
    // breach story with no industry -> victim job
    // Needs >= 80 chars of prose: the victim job only asks about items that contain enough
    // narrative for a victim to actually be named in.
    breachId: await mk({
      category: 'data-breach',
      title: 'Ransomware hits German insurer',
      summary: 'A German insurance company confirmed that ransomware operators encrypted its claims systems and exfiltrated customer records.',
    }),
  };
}

const judgeReturning = (value) => async () => value;

test('ML severities exclude "unknown" — an undecidable rating is an absent one', () => {
  assert.deepStrictEqual(ML_SEVERITIES, ['critical', 'high', 'medium', 'low']);
  assert.ok(!ML_SEVERITIES.includes('unknown'));
});

test('runJob rejects an unknown job name rather than silently doing nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await assert.rejects(() => runJob(store, 'nope', {}), /unknown job/);
  } finally { await cleanup(); }
});

// --- severity ---

test('severity job targets unrated prose and leaves unscored CVEs alone', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { newsId, cveId } = await seed(store);
    const res = await runJob(store, 'severity', { judge: judgeReturning({ severity: 'high' }) });
    assert.strictEqual(res.considered, 1, 'only the prose row');
    const rows = await store.all('SELECT item_id, severity FROM item_severity_ml');
    assert.deepStrictEqual(rows, [{ item_id: newsId, severity: 'high' }]);
    assert.ok(!rows.some((r) => r.item_id === cveId), 'an unscored CVE is upstream silence, not a gap to fill');
  } finally { await cleanup(); }
});

// The whole point of a separate table.
test('severity job never writes to items.severity', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const before = await store.all('SELECT id, severity FROM items ORDER BY id');
    await runJob(store, 'severity', { judge: judgeReturning({ severity: 'critical' }) });
    assert.deepStrictEqual(await store.all('SELECT id, severity FROM items ORDER BY id'), before);
  } finally { await cleanup(); }
});

test('an omitted severity is recorded as checked-but-empty, not retried forever', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const res = await runJob(store, 'severity', { judge: judgeReturning({}) });
    assert.strictEqual(res.written, 1);
    assert.strictEqual(res.empty, 1);
    const row = await store.get('SELECT severity FROM item_severity_ml');
    assert.strictEqual(row.severity, null);

    const second = await runJob(store, 'severity', { judge: judgeReturning({ severity: 'high' }) });
    assert.strictEqual(second.considered, 0, 'already checked');
  } finally { await cleanup(); }
});

test('a failed call writes nothing and comes back around', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const first = await runJob(store, 'severity', { judge: judgeReturning(null) });
    assert.strictEqual(first.written, 0);
    assert.strictEqual(first.failed, 1);
    assert.strictEqual((await store.all('SELECT 1 FROM item_severity_ml')).length, 0);

    const second = await runJob(store, 'severity', { judge: judgeReturning({ severity: 'low' }) });
    assert.strictEqual(second.written, 1);
  } finally { await cleanup(); }
});

// --- summary ---

test('summary job targets thin rows and skips bulk indicator feeds', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { thinId, phishId } = await seed(store);
    const res = await runJob(store, 'summary', { judge: judgeReturning({ summary: 'A kernel use-after-free affecting Azure Linux.' }) });
    assert.strictEqual(res.considered, 1);
    const rows = await store.all('SELECT item_id FROM item_summary_ml');
    assert.deepStrictEqual(rows.map((r) => r.item_id), [thinId]);
    assert.ok(!rows.some((r) => r.item_id === phishId), 'indicator rows get a deterministic template instead');
  } finally { await cleanup(); }
});

test('summary job never overwrites items.summary', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const before = await store.all('SELECT id, summary FROM items ORDER BY id');
    await runJob(store, 'summary', { judge: judgeReturning({ summary: 'Generated text.' }) });
    assert.deepStrictEqual(await store.all('SELECT id, summary FROM items ORDER BY id'), before);
  } finally { await cleanup(); }
});

// --- victim ---

test('victim job records sector and region for a named victim', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { breachId } = await seed(store);
    const res = await runJob(store, 'victim', { judge: judgeReturning({ sector: 'finance', country: 'Germany' }) });
    assert.strictEqual(res.considered, 1);
    const row = await store.get('SELECT item_id, sector, region FROM item_victim_ml');
    assert.deepStrictEqual(row, { item_id: breachId, sector: 'finance', region: 'Germany' });
  } finally { await cleanup(); }
});

// CLAUDE.md: never infer victim geography from the issuer. An empty answer is the correct one.
test('victim job stores nothing when no victim is named', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const res = await runJob(store, 'victim', { judge: judgeReturning({}) });
    assert.strictEqual(res.empty, 1);
    const row = await store.get('SELECT sector, region FROM item_victim_ml');
    assert.deepStrictEqual(row, { sector: null, region: null });
  } finally { await cleanup(); }
});

test('victim job never writes to items.industry or items.region', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const before = await store.all('SELECT id, industry, region FROM items ORDER BY id');
    await runJob(store, 'victim', { judge: judgeReturning({ sector: 'healthcare', country: 'France' }) });
    assert.deepStrictEqual(await store.all('SELECT id, industry, region FROM items ORDER BY id'), before);
  } finally { await cleanup(); }
});

test('victim sector vocabulary matches the profile sectors exactly', () => {
  assert.ok(SECTOR_SLUGS.includes('healthcare'));
  assert.ok(SECTOR_SLUGS.includes('manufacturing-industrial'));
  assert.strictEqual(SECTOR_SLUGS.length, 10);
});

test('the victim prompt defaults to empty and excludes the reporter', () => {
  const p = JOBS.victim.prompt({ title: 'CERT-FR publishes advisory' });
  // The default answer must be "no victim" — the model volunteers one otherwise.
  assert.match(p, /default answer is \{\}/i);
  assert.match(p, /reporter, researcher, vendor or agency/i);
  // CLAUDE.md's rule, stated to the model in its own terms.
  assert.match(p, /Never infer a country from who published/i);
});

// Every literal value in an example gets reproduced as fact: an earlier prompt ended with
// {"sector":"healthcare","region":"Germany"} and the model returned exactly that for 12 of 18
// unrelated stories, including "Ruby on Rails Patches Critical Vulnerability".
test('the victim prompt contains no concrete sector or country to copy', () => {
  const p = JOBS.victim.prompt({ title: 'Some breach' });
  const exampleLine = p.split('\n').find((l) => l.includes('{}')) || '';
  assert.ok(!/germany|france|healthcare"/i.test(exampleLine),
    `example line offers a copyable value: ${exampleLine}`);
});

test('every job caps its batch when asked', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    for (const name of ['severity', 'summary', 'victim']) {
      const res = await runJob(store, name, { judge: judgeReturning({}), limit: 1 });
      assert.ok(res.considered <= 1, `${name} ignored its limit`);
    }
  } finally { await cleanup(); }
});
