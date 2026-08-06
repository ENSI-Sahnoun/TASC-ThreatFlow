const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { createProfile, updateProfile } = require('./profiles');
const { recomputeProfile, assembleItems } = require('./relevance');

const PROFILE_INPUT = {
  name: 'Acme', sector: 'finance',
  vendors: ['fortinet'], products: ['fortios'],
  threatDomains: ['ransomware'], severityFloor: 'medium',
  // Ladder v2: only a profile_assets row can reach act_now. This fixture represents a profile
  // that actually runs FortiOS, so it carries the asset as well as the legacy arrays.
  assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }],
};

async function seed(store) {
  const src = await store.get(
    "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");

  // 1: exact asset match, KEV-listed, recent -> act_now
  const hit = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, severity, cvss_score, cvss_version, published_at)
     VALUES ($1,'cve','FortiOS RCE','CVE-2026-1','high',8.1,'3.1', now() - interval '2 days') RETURNING id`, [src.id]);
  await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [hit.id]);
  await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-1')", [hit.id]);
  await store.run(
    `INSERT INTO cve_intel (cve_id, severity, cvss_score, kev_listed, source_count)
     VALUES ('CVE-2026-1','high',8.1,true,1)`);

  // 2: followed domain, at floor, recent -> watch
  const dom = await store.get(
    `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
     VALUES ($1,'news','Ransomware wave','N-1','medium', now() - interval '1 day') RETURNING id`, [src.id]);
  await store.run("INSERT INTO item_domains (item_id, domain) VALUES ($1,'ransomware')", [dom.id]);

  // 3: nothing in common -> not_yours
  await store.run(
    `INSERT INTO items (source_id, category, title, external_id, published_at)
     VALUES ($1,'news','Unrelated','N-2', now() - interval '1 day')`, [src.id]);

  return { srcId: src.id, hitId: hit.id, domId: dom.id };
}

test('assembleItems joins domains, cpes and cve_intel facts onto each item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId } = await seed(store);
    const rows = await assembleItems(store);
    const hit = rows.find((r) => r.id === hitId);
    assert.deepStrictEqual(hit.cpes, [{ vendor: 'fortinet', product: 'fortios' }]);
    assert.strictEqual(hit.cve.kevListed, true);
    assert.strictEqual(hit.cve.severity, 'high');
  } finally { await cleanup(); }
});

test('assembleItems gives a non-CVE item a null cve and empty arrays', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { domId } = await seed(store);
    const row = (await assembleItems(store)).find((r) => r.id === domId);
    assert.strictEqual(row.cve, null);
    assert.deepStrictEqual(row.cpes, []);
    assert.deepStrictEqual(row.domains, ['ransomware']);
  } finally { await cleanup(); }
});

test('assembleItems joins category, title, iocs, actors and families onto each item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S2','json_api',true) RETURNING id");
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'ransomware','Acme Corp (LockBit)','R-1', now() - interval '1 days') RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_iocs (item_id, ioc_type, ioc_value) VALUES ($1,'ip','203.0.113.5')", [item.id]);
    await store.run("INSERT INTO item_actors (item_id, actor) VALUES ($1,'LockBit')", [item.id]);
    await store.run("INSERT INTO item_malware_families (item_id, family) VALUES ($1,'LockBit')", [item.id]);

    const rows = await assembleItems(store);
    const row = rows.find((r) => r.id === item.id);
    assert.strictEqual(row.category, 'ransomware');
    assert.strictEqual(row.title, 'Acme Corp (LockBit)');
    assert.deepStrictEqual(row.iocs, [{ type: 'ip', value: '203.0.113.5' }]);
    assert.deepStrictEqual(row.actors, ['LockBit']);
    assert.deepStrictEqual(row.families, ['LockBit']);
  } finally { await cleanup(); }
});

test('recomputeProfile materializes a category playbook for a watch-tier item with no CVE', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S3','json_api',true) RETURNING id");
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
       VALUES ($1,'ransomware','Acme Corp (LockBit)','R-2','medium', now() - interval '1 days') RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_domains (item_id, domain) VALUES ($1,'ransomware')", [item.id]);
    await store.run("INSERT INTO item_actors (item_id, actor) VALUES ($1,'LockBit')", [item.id]);
    await store.run(
      `INSERT INTO attack_mitigations (subject_type, subject_name, mitigation_id, mitigation_name, mitigation_url, technique_count, synced_at)
       VALUES ('actor','LockBit','M1053','Data Backup','https://attack.mitre.org/mitigations/M1053/',7, now())`);

    const profile = await createProfile(store, {
      name: 'RansomProfile', sector: 'finance', vendors: [], products: [],
      threatDomains: ['ransomware'], severityFloor: 'medium', assets: [],
    });
    await recomputeProfile(store, profile.id);

    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
      [item.id, profile.id, profile.profile_version]);
    assert.ok(pb);
    assert.ok(pb.steps.some((s) => s.key === 'ransomware:confirm'));
    assert.ok(pb.steps.some((s) => s.key === 'ransomware:attack-mitigation'));
  } finally { await cleanup(); }
});

test('recomputeProfile writes no playbook row for an ioc-category watch item with zero indicators', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S4','json_api',true) RETURNING id");
    const item = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
       VALUES ($1,'ioc','Raw indicator feed item','I-1','medium', now() - interval '1 days') RETURNING id`, [src.id]);
    await store.run("INSERT INTO item_domains (item_id, domain) VALUES ($1,'malware')", [item.id]);

    const profile = await createProfile(store, {
      name: 'IocProfile', sector: 'finance', vendors: [], products: [],
      threatDomains: ['malware'], severityFloor: 'medium', assets: [],
    });
    await recomputeProfile(store, profile.id);

    const pb = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
      [item.id, profile.id, profile.profile_version]);
    assert.strictEqual(pb, undefined);
  } finally { await cleanup(); }
});

test('recomputeProfile writes one row per item at the current profile_version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId, domId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);

    const result = await recomputeProfile(store, p.id);
    assert.strictEqual(result.scored, 3);

    const rows = await store.all(
      'SELECT item_id, tier, profile_version FROM item_relevance WHERE profile_id=$1 ORDER BY item_id', [p.id]);
    assert.strictEqual(rows.length, 3);
    assert.ok(rows.every((r) => r.profile_version === 1));
    assert.strictEqual(rows.find((r) => r.item_id === hitId).tier, 'act_now');
    assert.strictEqual(rows.find((r) => r.item_id === domId).tier, 'watch');
  } finally { await cleanup(); }
});

test('recomputeProfile stores the match reasons as JSON', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);
    const row = await store.get('SELECT matches FROM item_relevance WHERE profile_id=$1 AND item_id=$2', [p.id, hitId]);
    const kinds = row.matches.map((m) => m.kind);
    assert.ok(kinds.includes('product'));
    assert.ok(kinds.includes('kev'));
  } finally { await cleanup(); }
});

test('recomputeProfile is idempotent — a second run leaves the same row count', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);
    await recomputeProfile(store, p.id);
    const rows = await store.all('SELECT 1 FROM item_relevance WHERE profile_id=$1', [p.id]);
    assert.strictEqual(rows.length, 3, 'rows must be replaced, not accumulated');
  } finally { await cleanup(); }
});

// profile_version is the cache key: an edit must produce a new verdict set without destroying
// the old one, so reverting the edit re-exposes it instantly.
test('a profile edit scores into a new version and leaves the old rows in place', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { domId } = await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    await recomputeProfile(store, p.id);

    // Drop the ransomware interest — the domain-matched item should stop being 'watch'.
    await updateProfile(store, p.id, { ...PROFILE_INPUT, threatDomains: [] });
    await recomputeProfile(store, p.id);

    const v1 = await store.get(
      'SELECT tier FROM item_relevance WHERE profile_id=$1 AND item_id=$2 AND profile_version=1', [p.id, domId]);
    const v2 = await store.get(
      'SELECT tier FROM item_relevance WHERE profile_id=$1 AND item_id=$2 AND profile_version=2', [p.id, domId]);
    assert.strictEqual(v1.tier, 'watch', 'the version-1 verdict survives');
    assert.strictEqual(v2.tier, 'low', 'no longer a followed domain, but severity still meets the floor');
  } finally { await cleanup(); }
});

test('recomputeProfile returns null for an unknown profile rather than throwing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    assert.strictEqual(await recomputeProfile(store, 999), null);
  } finally { await cleanup(); }
});

test('recomputeProfile reports a tier breakdown', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const p = await createProfile(store, PROFILE_INPUT);
    const r = await recomputeProfile(store, p.id);
    assert.strictEqual(r.tiers.act_now, 1);
    assert.strictEqual(r.tiers.watch, 1);
    assert.strictEqual(r.tiers.not_yours, 1);
  } finally { await cleanup(); }
});

// --- Consequence materialization (Spec A) ---

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

test('recomputeProfile materializes consequence slots', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','FortiOS RCE','CVE-2026-9',$2, now() - interval '2 days') RETURNING id`,
      [s.id, WORST]);
    await store.run(
      "INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')",
      [i.id]);
    const p = await createProfile(store, {
      ...PROFILE_INPUT,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2', [i.id, p.id]);
    assert.match(row.consequence.reach.text, /anyone on the internet/);
    assert.strictEqual(row.consequence.impact.text, 'read, change and shut down');
    assert.strictEqual(row.consequence.role.text, 'your VPN and firewall');
    // exposure rides inside the stored JSON so the read path never re-derives it.
    assert.strictEqual(row.consequence.exposure, 'internet');
  } finally { await cleanup(); }
});

test('an item with no vector still gets a consequence object with null slots', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, published_at)
       VALUES ($1,'news','Unrelated','N-9', now()) RETURNING id`, [s.id]);
    const p = await createProfile(store, PROFILE_INPUT);

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2', [i.id, p.id]);
    assert.deepStrictEqual(row.consequence,
      { reach: null, impact: null, role: null, urgency: null, exposure: 'unknown' });
  } finally { await cleanup(); }
});

test('a KEV CVE carries its CISA deadline into the urgency slot', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','t','CVE-2026-8',$2, now()) RETURNING id`, [s.id, WORST]);
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [i.id, 'CVE-2026-8']);
    await store.run(
      `INSERT INTO cve_intel (cve_id, severity, kev_listed, kev_due_date)
       VALUES ('CVE-2026-8','critical',true,'2026-08-17')`);
    const p = await createProfile(store, PROFILE_INPUT);

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2', [i.id, p.id]);
    // A bare YYYY-MM-DD, never a timestamp: pg parses DATE at local midnight and toISOString()
    // would render the deadline a day early.
    assert.strictEqual(row.consequence.urgency.due, '2026-08-17');
    assert.strictEqual(row.consequence.urgency.from, 'KEV');
  } finally { await cleanup(); }
});

test('assembleItems exposes the vector and the KEV due date', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','t','CVE-2026-7',$2, now()) RETURNING id`, [s.id, WORST]);
    await store.run('INSERT INTO item_cves (item_id, cve_id) VALUES ($1,$2)', [i.id, 'CVE-2026-7']);
    await store.run(
      `INSERT INTO cve_intel (cve_id, severity, kev_listed, kev_due_date)
       VALUES ('CVE-2026-7','critical',true,'2026-08-17')`);

    const items = await assembleItems(store);
    const got = items.find((x) => x.id === i.id);
    assert.strictEqual(got.cvssVector, WORST);
    assert.strictEqual(got.cve.kevDueDate, '2026-08-17');
  } finally { await cleanup(); }
});

// --- Playbook materialization ---

test('recomputeProfile materializes a playbook for an act_now item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','FortiOS RCE','CVE-2026-20',$2, now() - interval '2 days') RETURNING id`,
      [s.id, WORST]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [i.id]);
    await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-20')", [i.id]);
    await store.run(
      `INSERT INTO cve_intel (cve_id, severity, kev_listed, patch_url)
       VALUES ('CVE-2026-20','critical',true,'https://example.com/patch')`);
    const p = await createProfile(store, {
      ...PROFILE_INPUT,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });

    await recomputeProfile(store, p.id);

    const rel = await store.get('SELECT tier FROM item_relevance WHERE item_id=$1 AND profile_id=$2', [i.id, p.id]);
    assert.strictEqual(rel.tier, 'act_now');
    const row = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [i.id, p.id, p.profile_version]);
    const keys = row.steps.map((st) => st.key);
    assert.ok(keys.includes('confirm'));
    assert.ok(keys.includes('patch'));
    assert.strictEqual(row.steps.find((st) => st.key === 'patch').link, 'https://example.com/patch');
  } finally { await cleanup(); }
});

test('a low-tier item gets no item_playbooks row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { domId } = await seed(store);
    // domId lands on watch by default (followed domain, at floor, recent) — push it to low by
    // dropping the followed domain from the profile.
    const p = await createProfile(store, { ...PROFILE_INPUT, threatDomains: [] });

    await recomputeProfile(store, p.id);

    const rel = await store.get('SELECT tier FROM item_relevance WHERE item_id=$1 AND profile_id=$2', [domId, p.id]);
    assert.strictEqual(rel.tier, 'low');
    const row = await store.get(
      'SELECT 1 FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [domId, p.id]);
    assert.strictEqual(row, undefined);
  } finally { await cleanup(); }
});

test('a watch-tier item with no CVE signal at all gets no item_playbooks row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { domId } = await seed(store);
    // domId is a news item with a followed domain and no CVE/CVSS anywhere — it reaches watch
    // through domainMatch, but there is nothing for a playbook to be about.
    const p = await createProfile(store, PROFILE_INPUT);

    await recomputeProfile(store, p.id);

    const rel = await store.get('SELECT tier FROM item_relevance WHERE item_id=$1 AND profile_id=$2', [domId, p.id]);
    assert.strictEqual(rel.tier, 'watch');
    const row = await store.get('SELECT 1 FROM item_playbooks WHERE item_id=$1 AND profile_id=$2', [domId, p.id]);
    assert.strictEqual(row, undefined);
  } finally { await cleanup(); }
});

test('a profile edit regenerates the playbook at the new version and leaves the old one in place', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','t','CVE-2026-21',$2, now() - interval '1 days') RETURNING id`, [s.id, WORST]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [i.id]);
    await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-21')", [i.id]);
    await store.run(`INSERT INTO cve_intel (cve_id, severity, kev_listed) VALUES ('CVE-2026-21','critical',true)`);
    const p = await createProfile(store, {
      ...PROFILE_INPUT, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });
    await recomputeProfile(store, p.id);

    await updateProfile(store, p.id, {
      ...PROFILE_INPUT, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internal' }],
    });
    await recomputeProfile(store, p.id);

    const v1 = await store.get(
      'SELECT 1 FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=1', [i.id, p.id]);
    assert.ok(v1, 'the version-1 playbook survives');
    const v2 = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=2', [i.id, p.id]);
    // internal exposure: no longer act_now, no longer carries a restrict step.
    assert.ok(!v2.steps.some((st) => st.key === 'restrict'));
  } finally { await cleanup(); }
});

test('the confirm step states the affected version range when cve_intel carries one for the matched product', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S','json_api',true) RETURNING id");
    const i = await store.get(
      `INSERT INTO items (source_id, category, title, external_id, cvss_vector, published_at)
       VALUES ($1,'cve','FortiOS RCE','CVE-2026-30',$2, now() - interval '2 days') RETURNING id`,
      [s.id, WORST]);
    await store.run("INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')", [i.id]);
    await store.run("INSERT INTO item_cves (item_id, cve_id) VALUES ($1,'CVE-2026-30')", [i.id]);
    await store.run(
      `INSERT INTO cve_intel (cve_id, severity, kev_listed, affected_versions)
       VALUES ('CVE-2026-30','critical',true,$1)`,
      [JSON.stringify([{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5' }])]);
    const p = await createProfile(store, {
      ...PROFILE_INPUT,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT steps FROM item_playbooks WHERE item_id=$1 AND profile_id=$2 AND profile_version=$3',
      [i.id, p.id, p.profile_version]);
    const confirm = row.steps.find((st) => st.key === 'confirm');
    assert.match(confirm.detail, /before 7\.4\.5/);
  } finally { await cleanup(); }
});

test('recomputeProfile loads attack_mitigations once per call, not once per item', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('S5','json_api',true) RETURNING id");
    for (let i = 0; i < 3; i += 1) {
      const item = await store.get(
        `INSERT INTO items (source_id, category, title, external_id, severity, published_at)
         VALUES ($1,'ransomware','Victim ${i} (LockBit)','R-${i}','medium', now() - interval '1 days') RETURNING id`,
        [src.id]);
      await store.run("INSERT INTO item_domains (item_id, domain) VALUES ($1,'ransomware')", [item.id]);
      await store.run("INSERT INTO item_actors (item_id, actor) VALUES ($1,'LockBit')", [item.id]);
    }
    await store.run(
      `INSERT INTO attack_mitigations (subject_type, subject_name, mitigation_id, mitigation_name, mitigation_url, technique_count, synced_at)
       VALUES ('actor','LockBit','M1053','Data Backup','https://attack.mitre.org/mitigations/M1053/',7, now())`);

    const profile = await createProfile(store, {
      name: 'AttackMitProfile', sector: 'finance', vendors: [], products: [],
      threatDomains: ['ransomware'], severityFloor: 'medium', assets: [],
    });

    let attackMitigationsQueryCount = 0;
    const countingStore = {
      ...store,
      all: (sql, params) => {
        if (sql.includes('FROM attack_mitigations')) attackMitigationsQueryCount += 1;
        return store.all(sql, params);
      },
    };

    await recomputeProfile(countingStore, profile.id);
    assert.strictEqual(attackMitigationsQueryCount, 1,
      'attack_mitigations must be loaded once per recompute call, not once per item');

    const rows = await store.all(
      'SELECT steps FROM item_playbooks WHERE profile_id = $1 ORDER BY item_id', [profile.id]);
    assert.ok(rows.length > 0);
    for (const row2 of rows) assert.ok(row2.steps.some((s) => s.key === 'ransomware:attack-mitigation'));
  } finally { await cleanup(); }
});
