const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { createProfile } = require('./profiles');
const { recomputeProfile } = require('./relevance');
const { buildPrompt, generateProse, isUsableSentence, PROSE_TIERS } = require('./relevance_prose');

const PROFILE_INPUT = {
  name: 'Acme', sector: 'finance',
  vendors: ['fortinet'], products: ['fortios'],
  threatDomains: ['ransomware'], severityFloor: 'medium',
  // Ladder v2: prose is written for act_now and watch only, and only an asset row can reach
  // them. This fixture represents a profile that actually runs FortiOS.
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }],
};

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");

  const hit = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
     VALUES ($1,'cve','FortiOS pre-auth RCE','CVE-2026-1','high', now() - interval '2 days') RETURNING id`, [src.id]);
  await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [hit.id]);

  const dull = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, published_at)
     VALUES ($1,'news','Totally unrelated','N-1', now() - interval '1 day') RETURNING id`, [src.id]);

  return { hitId: hit.id, dullId: dull.id };
}

// A stub standing in for judgeText: records prompts, returns whatever was queued.
function fakeJudge(replies) {
  const prompts = [];
  const queue = [...replies];
  const fn = async (prompt) => { prompts.push(prompt); return queue.length ? queue.shift() : null; };
  fn.prompts = prompts;
  return fn;
}

test('PROSE_TIERS covers only the tiers a user will actually read', () => {
  assert.deepStrictEqual(PROSE_TIERS, ['act_now', 'watch']);
});

test('buildPrompt states the verdict and the reasons, and forbids changing them', () => {
  const p = buildPrompt(
    { name: 'Acme', sector: 'finance' },
    { title: 'FortiOS pre-auth RCE', tier: 'act_now', matches: [{ kind: 'product', value: 'fortinet fortios' }] },
  );
  assert.match(p, /FortiOS pre-auth RCE/);
  assert.match(p, /fortinet fortios/);
  assert.match(p, /finance/);
  // The model must not be invited to re-judge — it explains a decision already made.
  assert.match(p, /do not|never/i);
});

test('generateProse writes a sentence for the prominent tiers only', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId, dullId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    const judge = fakeJudge([{ sentence: 'You run FortiOS; this is exploitable pre-auth.' }]);
    const res = await generateProse(store, p.id, { judge });

    assert.strictEqual(res.written, 1);
    const rows = await store.all('SELECT item_id, sentence, model FROM item_relevance_prose');
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].item_id, hitId);
    assert.match(rows[0].sentence, /FortiOS/);
    assert.ok(rows[0].model, 'the writing model is recorded');
    assert.ok(!rows.some((r) => r.item_id === dullId), 'not_yours items get no prose');
  } finally { await cleanup(); }
});

// The whole Phase 3 guardrail, asserted structurally.
test('generating prose never alters a tier', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);
    const before = await store.all('SELECT item_id, tier, score FROM item_relevance ORDER BY item_id');

    // A model doing its worst: screaming a different verdict.
    await generateProse(store, p.id, { judge: fakeJudge([{ sentence: 'URGENT CRITICAL ACT NOW not_yours low' }]) });

    const after = await store.all('SELECT item_id, tier, score FROM item_relevance ORDER BY item_id');
    assert.deepStrictEqual(after, before);
  } finally { await cleanup(); }
});

// Absence over fabrication.
test('a null judgement writes no row and is retried on the next run', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    const failed = await generateProse(store, p.id, { judge: fakeJudge([null]) });
    assert.strictEqual(failed.written, 0);
    assert.strictEqual(failed.failed, 1);
    assert.strictEqual((await store.all('SELECT 1 FROM item_relevance_prose')).length, 0);

    const ok = await generateProse(store, p.id, { judge: fakeJudge([{ sentence: 'This flaw could expose your FortiOS appliance to unauthenticated attackers.' }]) });
    assert.strictEqual(ok.written, 1);
  } finally { await cleanup(); }
});

test('generateProse skips items that already have a sentence at this version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    await generateProse(store, p.id, { judge: fakeJudge([{ sentence: 'This flaw could let an attacker reach your FortiOS appliance directly.' }]) });
    const second = await generateProse(store, p.id, { judge: fakeJudge([{ sentence: 'This second sentence should never be requested or written.' }]) });

    assert.strictEqual(second.written, 0);
    assert.strictEqual(second.considered, 0, 'nothing left to do');
    const row = await store.get('SELECT sentence FROM item_relevance_prose');
    assert.match(row.sentence, /attacker reach your FortiOS/);
  } finally { await cleanup(); }
});

test('generateProse returns null for an unknown profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    assert.strictEqual(await generateProse(store, 999, { judge: fakeJudge([]) }), null);
  } finally { await cleanup(); }
});

test('an unreachable model leaves the deterministic verdicts fully intact', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);
    const before = await store.all('SELECT item_id, tier FROM item_relevance ORDER BY item_id');

    const res = await generateProse(store, p.id, { judge: async () => null });

    assert.strictEqual(res.written, 0);
    assert.deepStrictEqual(await store.all('SELECT item_id, tier FROM item_relevance ORDER BY item_id'), before);
  } finally { await cleanup(); }
});

// --- output guard ---

test('isUsableSentence accepts a well-formed impact sentence', () => {
  assert.strictEqual(
    isUsableSentence('You run Fortinet FortiOS and this critical flaw would let an attacker in without valid credentials.'),
    true);
});

test('isUsableSentence rejects echoed prompt scaffolding', () => {
  for (const s of [
    'This security report is relevant to a reader in the finance sector.',
    '{"sentence": "your one sentence here"}',
    'Answer with JSON in exactly this form.',
    // The fictional vendor from the one-shot example, asserted as fact about the reader.
    'You run Acme VPN, so this critical flaw is directly exposed in your environment.',
  ]) {
    assert.strictEqual(isUsableSentence(s), false, `should reject: ${s}`);
  }
});

// The model asserts this from a headline about somebody else. Prompting does not stop it at
// 1.7B, so the filter must.
test('isUsableSentence rejects any claim the reader has already been breached', () => {
  for (const s of [
    "You're a victim of ransomware attacks against financial institutions and your data is exposed.",
    'You are a target of this campaign and should assume compromise has already occurred.',
    'You have been breached by this actor and must begin incident response immediately.',
    'Your data has been leaked publicly by the group behind this campaign.',
    'Attackers have stolen your customer records in this incident, according to the report.',
  ]) {
    assert.strictEqual(isUsableSentence(s), false, `should reject breach claim: ${s}`);
  }
});

test('isUsableSentence still allows describing what an issue could do', () => {
  for (const s of [
    'This flaw could let an attacker steal your customer data if you run the affected version.',
    'You run Cisco IOS XE, and this would allow privilege escalation on an exposed web UI.',
  ]) {
    assert.strictEqual(isUsableSentence(s), true, `should allow: ${s}`);
  }
});

test('isUsableSentence rejects a too-short fragment', () => {
  assert.strictEqual(isUsableSentence('Bad.'), false);
  assert.strictEqual(isUsableSentence(''), false);
  assert.strictEqual(isUsableSentence(null), false);
});

// --- Prose v2: slots, not key/value pairs ---

const { templateSentence } = require('./relevance_prose');

const FULL = {
  reach: { text: 'anyone on the internet, with no password', from: 'AV:N/PR:N/UI:N + exposure=internet' },
  impact: { text: 'read, change and shut down', from: 'C:H/I:H/A:H' },
  role: { text: 'your company email', from: 'asset_roles: microsoft/exchange_server' },
  urgency: { text: 'already used in real attacks', due: '2026-08-17', from: 'KEV' },
};

test('templateSentence names the reach, the impact and the role', () => {
  const s = templateSentence(FULL, []);
  // Case-insensitive: the reach clause opens the sentence, so it is capitalized.
  assert.match(s, /anyone on the internet/i);
  assert.match(s, /read, change and shut down/);
  assert.match(s, /your company email/);
});

test('templateSentence starts with a capital and ends with a full stop', () => {
  const s = templateSentence(FULL, []);
  assert.match(s, /^[A-Z]/);
  assert.match(s, /\.$/);
});

test('templateSentence omits a null slot without leaving a gap', () => {
  const s = templateSentence({ ...FULL, urgency: null }, []);
  assert.ok(!/undefined|null/.test(s));
  assert.ok(!/already used/.test(s));
});

test('templateSentence still says something with only an impact', () => {
  const s = templateSentence({ reach: null, impact: FULL.impact, role: FULL.role, urgency: null }, []);
  assert.match(s, /read, change and shut down/);
  assert.ok(!/undefined/.test(s));
});

test('templateSentence names the thing generically when the role is unmapped', () => {
  const s = templateSentence({ ...FULL, role: null }, []);
  assert.match(s, /this system/);
});

// The whole point of v2: a rejected model output must land on something specific, not on
// "Matches your stack (microsoft windows)".
test('templateSentence falls back to the match reasons only when every slot is null', () => {
  const s = templateSentence({ reach: null, impact: null, role: null, urgency: null },
    [{ kind: 'product', value: 'fortinet fortios' }]);
  assert.ok(s.length > 0);
  assert.ok(!/undefined/.test(s));
});

test('templateSentence tolerates a null consequence entirely', () => {
  assert.ok(templateSentence(null, [{ kind: 'kev', value: 'CISA KEV' }]).length > 0);
});

test('buildPrompt states the slot facts and never the raw kind:value pairs', () => {
  const p = buildPrompt({ sector: 'finance' },
    { title: 'Exchange flaw', summary: null, consequence: FULL, matches: [] });
  assert.match(p, /anyone on the internet/);
  assert.match(p, /read, change and shut down/);
  assert.ok(!/"kind"/.test(p));
});

test('buildPrompt keeps the no-breach-claim instruction', () => {
  const p = buildPrompt({ sector: 'finance' },
    { title: 't', summary: null, consequence: FULL, matches: [] });
  assert.match(p, /never state or imply/i);
});

test('buildPrompt works when the consequence is empty, falling back to matches', () => {
  const p = buildPrompt({ sector: 'finance' },
    { title: 't', summary: null, consequence: null, matches: [{ kind: 'kev', value: 'CISA KEV' }] });
  assert.match(p, /exploited/i);
});
