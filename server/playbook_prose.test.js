const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { createProfile } = require('./profiles');
const { recomputeProfile } = require('./relevance');
const {
  generatePlaybookProse, buildStepPrompt, isUsableDetail, INVENTED_LINK_RE,
} = require('./playbook_prose');

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

const PROFILE_INPUT = {
  name: 'Acme', sector: 'finance',
  vendors: ['fortinet'], products: ['fortios'],
  threatDomains: ['ransomware'], severityFloor: 'medium',
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
};

async function seed(store) {
  const s = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
  const i = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
     VALUES ($1,'cve','FortiOS pre-auth RCE','CVE-2026-30',$2, now() - interval '2 days') RETURNING id`,
    [s.id, WORST]);
  await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [i.id]);
  await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-30')", [i.id]);
  await store.run(`INSERT INTO cve_intel (cve_id, severity, kev_listed) VALUES ('CVE-2026-30','critical',true)`);
  return { itemId: i.id };
}

function fakeJudge(replies) {
  const queue = [...replies];
  return async () => (queue.length ? queue.shift() : null);
}

test('buildStepPrompt states the step title and original detail, and forbids inventing facts', () => {
  const p = buildStepPrompt({ title: 'FortiOS pre-auth RCE' },
    { key: 'restrict', title: 'Limit who can reach it', detail: 'Allow connections only from addresses you control.', source: 'x', link: null });
  assert.match(p, /Limit who can reach it/);
  assert.match(p, /Allow connections only from addresses you control/);
  assert.match(p, /invent/i);
});

test('generatePlaybookProse rewords a step detail and sets worded_by', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { itemId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    const judge = fakeJudge([
      { detail: 'Only let trusted addresses connect.' },  // confirm
      { detail: 'Only let trusted addresses connect to your VPN and firewall.' }, // restrict
      { detail: 'Rotate every password and key on that box right away.' }, // rotate
    ]);
    const res = await generatePlaybookProse(store, p.id, { judge });

    assert.strictEqual(res.written, 1);
    const row = await store.get(
      'SELECT steps, worded_by FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [itemId, p.id]);
    assert.ok(row.worded_by);
    assert.ok(row.steps.some((s) => s.detail.includes('trusted addresses')));
  } finally { await cleanup(); }
});

test('title, key, source and link are never altered by rewording', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { itemId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);
    const before = await store.get('SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [itemId, p.id]);

    await generatePlaybookProse(store, p.id, {
      judge: fakeJudge(before.steps.map(() => ({ detail: 'Reworded detail text goes here.' }))),
    });

    const after = await store.get('SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [itemId, p.id]);
    for (let i = 0; i < before.steps.length; i += 1) {
      assert.strictEqual(after.steps[i].key, before.steps[i].key);
      assert.strictEqual(after.steps[i].title, before.steps[i].title);
      assert.strictEqual(after.steps[i].source, before.steps[i].source);
      assert.strictEqual(after.steps[i].link, before.steps[i].link);
    }
  } finally { await cleanup(); }
});

test('a null judgement for every step leaves the row unwritten and it is retried next run', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { itemId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    const failed = await generatePlaybookProse(store, p.id, { judge: async () => null });
    assert.strictEqual(failed.written, 0);
    const row = await store.get('SELECT worded_by FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [itemId, p.id]);
    assert.strictEqual(row.worded_by, null);

    const ok = await generatePlaybookProse(store, p.id, {
      judge: fakeJudge([{ detail: 'A reworded sentence.' }, { detail: 'Another reworded sentence.' }, { detail: 'A third one.' }]),
    });
    assert.strictEqual(ok.written, 1);
  } finally { await cleanup(); }
});

test('generatePlaybookProse returns null for an unknown profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    assert.strictEqual(await generatePlaybookProse(store, 999, { judge: fakeJudge([]) }), null);
  } finally { await cleanup(); }
});

// --- isUsableDetail ---

test('isUsableDetail accepts a faithful rewording', () => {
  assert.strictEqual(isUsableDetail('Allow connections only from addresses you control.', 'Only let addresses you trust connect.'), true);
});

test('isUsableDetail rejects an invented URL, CVE id or version not present in the original', () => {
  assert.strictEqual(isUsableDetail('Apply the fix.', 'Download it from https://evil.example/fix'), false);
  assert.strictEqual(isUsableDetail('Apply the fix.', 'This is CVE-2099-9999, patch it now.'), false);
  assert.strictEqual(isUsableDetail('Apply the fix.', 'Upgrade to version 4.2.1 immediately.'), false);
});

test('isUsableDetail allows a version/CVE/URL that was already present in the original', () => {
  const original = 'Upgrade FortiOS to 7.2.1 or apply https://example.com/patch for CVE-2026-1.';
  const reworded = 'Get FortiOS to 7.2.1, or use https://example.com/patch for CVE-2026-1.';
  assert.strictEqual(isUsableDetail(original, reworded), true);
});

test('isUsableDetail rejects a breach claim, reusing BREACH_CLAIM_RE unchanged', () => {
  assert.strictEqual(isUsableDetail('Rotate credentials.', 'Your data has been leaked publicly by the group behind this campaign.'), false);
});

test('isUsableDetail rejects an empty or too-short reply', () => {
  assert.strictEqual(isUsableDetail('Rotate credentials.', ''), false);
  assert.strictEqual(isUsableDetail('Rotate credentials.', 'Ok.'), false);
});

// INVENTED_LINK_RE carries the 'g' flag (inventedToken() collects every match via
// String.match()), so assert.match/doesNotMatch — which call RegExp#test() and thereby mutate
// lastIndex across calls — cannot be chained against the same instance here. String#match()
// always searches from the start and does not leave lastIndex in a state that corrupts the
// next call, so it is the safe way to assert this.
test('INVENTED_LINK_RE matches URLs, CVE ids and version numbers', () => {
  assert.ok('see https://x.test/y'.match(INVENTED_LINK_RE));
  assert.ok('CVE-2026-1234'.match(INVENTED_LINK_RE));
  assert.ok('version 3.2.1'.match(INVENTED_LINK_RE));
  assert.ok(!'rotate your passwords'.match(INVENTED_LINK_RE));
});
