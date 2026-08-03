# Impact Indicator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the match-level relevance verdict with a consequence-level one that states who could attack, what they would get, how urgent it is, and why it applies to this user.

**Architecture:** A new pure module `server/consequence.js` turns a CVSS vector, an asset exposure flag and a curated product-to-role map into four nullable fact slots. Those slots are materialized into `item_relevance.consequence` by the existing deterministic recompute pass, then read by the API, the prose prompt and a new impact panel. The model's only job stays rewording; it cannot add a fact or change a tier.

**Tech Stack:** Node 22, Express 4, PostgreSQL 16 via `server/store.js` (`pg`, `$1` placeholders, no ORM), `node:test` for backend tests, Angular 19 standalone components with signals, vitest + `tsc --noEmit` for frontend tests.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-03-impact-indicator-design.md`. Read it before Task 1.
- All schema changes are additive. No existing column is dropped or repurposed.
- No authentication is added. Profiles remain personas behind the loopback bind.
- No CPE version-range matching. `server/cpe.js` is not modified.
- Backfill scripts follow the repo's inverted default: **a bare invocation writes, `--dry-run` previews.**
- Adapters never write to the database directly. Pure logic lives in its own module with its own tests.
- Backend tests use isolated databases from `server/test-helpers.js` (`makeTempDb`), never the `db.js` singleton.
- Every new curated slug in `asset_roles.js` must be verified against `item_cpes` with its reference count recorded in a comment. A slug matching nothing is worse than an omission.
- Missing data yields a `null` slot, never a guessed value.
- `SCAFFOLD_RE` and `BREACH_CLAIM_RE` in `relevance_prose.js` are load-bearing and must not be weakened.
- Exposure literals are exactly `'internet' | 'internal' | 'unknown'`.
- Tier literals are exactly `'act_now' | 'watch' | 'low' | 'not_yours'`.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `server/asset_roles.js` | Curated product-slug → plain-English role map. Pure. |
| `server/asset_roles.test.js` | Slug hygiene tests. |
| `server/consequence.js` | CVSS vector + exposure + role + KEV/EPSS → four fact slots. Pure. |
| `server/consequence.test.js` | Table-driven slot tests. |
| `server/backfill-cvss-vector.js` | Re-derives `items.cvss_vector` from `raw_json`. |
| `server/backfill-cvss-vector.test.js` | Idempotence and dry-run tests. |
| `frontend-v4/src/app/ui/impact-panel.component.ts` | The four-block impact section. |

**Modified:**

| Path | Change |
|---|---|
| `server/db.js` | `profile_assets` table, `items.cvss_vector`, `item_relevance.consequence`, migration seed. |
| `server/profiles.js` | Asset validation, read and write. |
| `server/relevance_score.js` | Ladder v2: `assetHit` / `legacyHit`, exposure gate. |
| `server/relevance.js` | Join `cvss_vector`, materialize `consequence`. |
| `server/relevance_prose.js` | Prompt and template built from slots. |
| `server/index.js` | Expose `consequence` and `exposure`; accept `assets` on profile write. |
| `frontend-v4/src/app/core/models.ts` | `Consequence`, `ConsequenceSlot`, `ProfileAsset` types. |
| `frontend-v4/src/app/core/relevance.ts` | Tier labels, sub-lines, slot accessors. |
| `frontend-v4/src/app/ui/relevance-chip.component.ts` | Sub-line. |
| `frontend-v4/src/app/pages/intel/item-detail.component.ts` | Swap the relevance panel for the impact panel. |
| `frontend-v4/src/app/pages/onboarding/survey.component.ts` | Exposure step. |

---

### Task 1: Schema — `profile_assets`, `cvss_vector`, `consequence`

**Files:**
- Modify: `server/db.js` (inside `applySchema`, after the `profiles` table and beside the existing `ALTER TABLE items ADD COLUMN IF NOT EXISTS` lines)
- Test: `server/schema.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces: table `profile_assets(profile_id INT, vendor TEXT, product TEXT, exposure TEXT)`; columns `items.cvss_vector TEXT` and `item_relevance.consequence JSONB`.

- [ ] **Step 1: Write the failing test**

Append to `server/schema.test.js`:

```js
test('profile_assets exists with an exposure check constraint', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      `INSERT INTO profiles (name, sector) VALUES ('t','finance') RETURNING id`);
    await store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortios','internet')`, [p.id]);
    await assert.rejects(() => store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortiproxy','sometimes')`, [p.id]));
  } finally { await cleanup(); }
});

test('profile_assets cascades when its profile is deleted', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await store.get(
      `INSERT INTO profiles (name, sector) VALUES ('t','finance') RETURNING id`);
    await store.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       VALUES ($1,'fortinet','fortios','internet')`, [p.id]);
    await store.run('DELETE FROM profiles WHERE id = $1', [p.id]);
    const rows = await store.all('SELECT * FROM profile_assets');
    assert.strictEqual(rows.length, 0);
  } finally { await cleanup(); }
});

test('items.cvss_vector and item_relevance.consequence exist', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const cols = await store.all(
      `SELECT table_name, column_name FROM information_schema.columns
        WHERE (table_name='items' AND column_name='cvss_vector')
           OR (table_name='item_relevance' AND column_name='consequence')`);
    assert.strictEqual(cols.length, 2);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/schema.test.js`
Expected: FAIL — `relation "profile_assets" does not exist`.

- [ ] **Step 3: Add the schema**

In `server/db.js`, inside `applySchema`, immediately after the `profiles` table definition:

```sql
    -- Precise tech-stack rows. profiles.vendors/products are retained for backward
    -- compatibility and keep feeding the `low` tier; only a profile_assets row can earn
    -- act_now, because a vendor-level claim ("we use Microsoft software") is not evidence of
    -- exposure to a specific flaw.
    --
    -- exposure is the crossing that turns a CVSS vector into a personal statement: AV:N on an
    -- internet-facing asset means anyone, on an internal one it means anyone already inside.
    CREATE TABLE IF NOT EXISTS profile_assets (
      profile_id INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      vendor     TEXT NOT NULL,
      product    TEXT NOT NULL,
      exposure   TEXT NOT NULL DEFAULT 'unknown'
                 CHECK (exposure IN ('internet','internal','unknown')),
      UNIQUE(profile_id, vendor, product)
    );
    CREATE INDEX IF NOT EXISTS idx_profile_assets_product ON profile_assets(vendor, product);
```

Then beside the existing `ALTER TABLE items ADD COLUMN IF NOT EXISTS` lines at the end:

```sql
    ALTER TABLE items ADD COLUMN IF NOT EXISTS cvss_vector TEXT;
    -- Deterministic consequence slots, materialized by the same pure pass that writes `tier`.
    -- Nullable: rows written before this column existed carry NULL until the next recompute.
    ALTER TABLE item_relevance ADD COLUMN IF NOT EXISTS consequence JSONB;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/schema.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/db.js server/schema.test.js
git commit -m "feat(impact): add profile_assets, items.cvss_vector and item_relevance.consequence"
```

---

### Task 2: Migrate existing `products[]` into `profile_assets`

**Files:**
- Modify: `server/db.js` (end of `applySchema`)
- Test: `server/schema.test.js`

**Interfaces:**
- Consumes: `profile_assets` from Task 1.
- Produces: every pre-existing profile has `profile_assets` rows at `exposure='unknown'`.

Where a product slug appears under several vendors in `item_cpes`, one row is inserted per distinct vendor — the profile never recorded which vendor it meant, and dropping the ambiguous ones would silently lose assets.

- [ ] **Step 1: Write the failing test**

Append to `server/schema.test.js`:

```js
test('applySchema seeds profile_assets from legacy products[] at unknown exposure', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      `INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id`);
    const i = await store.get(
      `INSERT INTO items (source_id, external_id, title) VALUES ($1,'e1','t') RETURNING id`, [s.id]);
    await store.run(
      `INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')`,
      [i.id]);
    await store.run(
      `INSERT INTO profiles (name, sector, products) VALUES ('legacy','finance','{fortios,ghost}')`);

    await applySchema(store);   // idempotent re-apply performs the seed

    const rows = await store.all('SELECT vendor, product, exposure FROM profile_assets');
    assert.deepStrictEqual(rows, [
      { vendor: 'fortinet', product: 'fortios', exposure: 'unknown' },
    ]);
  } finally { await cleanup(); }
});
```

Note: `ghost` matches no `item_cpes` row and must be skipped — storing it would store a value that can never match.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/schema.test.js`
Expected: FAIL — `rows` is `[]`.

- [ ] **Step 3: Add the seed**

At the end of `applySchema` in `server/db.js`, after the `ALTER TABLE` lines:

```sql
    -- One-time migration, expressed idempotently so a re-apply is a no-op. Every profile
    -- created before profile_assets existed keeps its act_now lane: its products[] entries
    -- become assets at 'unknown' exposure, which the ladder still allows to reach act_now.
    -- The vendor is recovered by joining item_cpes; a slug appearing under several vendors
    -- yields one row per vendor, because the profile never said which it meant.
    INSERT INTO profile_assets (profile_id, vendor, product, exposure)
    SELECT DISTINCT p.id, c.vendor, c.product, 'unknown'
      FROM profiles p
      JOIN LATERAL unnest(p.products) AS prod(slug) ON true
      JOIN item_cpes c ON c.product = prod.slug
    ON CONFLICT (profile_id, vendor, product) DO NOTHING;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/schema.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/db.js server/schema.test.js
git commit -m "feat(impact): seed profile_assets from legacy products[] on schema apply"
```

---

### Task 3: `backfill-cvss-vector.js`

**Files:**
- Create: `server/backfill-cvss-vector.js`
- Create: `server/backfill-cvss-vector.test.js`

**Interfaces:**
- Consumes: `items.cvss_vector` from Task 1; `parseVector` from `server/cvss.js`.
- Produces: `backfill(store, { dryRun, batchSize }) -> { scanned, changed, skipped }`, and `vectorFromRaw(raw) -> string | null`.

NVD stores vectors under `metrics.cvssMetricV31[].cvssData.vectorString`, with `cvssMetricV30` and `cvssMetricV2` as fallbacks. v3.1 is preferred, then v3.0. v2 is not stored: `cvss.js` recognises but does not score it, and `consequence.js` reads v3 metric names only.

- [ ] **Step 1: Write the failing test**

Create `server/backfill-cvss-vector.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { backfill, vectorFromRaw } = require('./backfill-cvss-vector');

test('vectorFromRaw prefers v3.1 over v3.0', () => {
  const raw = {
    metrics: {
      cvssMetricV30: [{ cvssData: { vectorString: 'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L' } }],
      cvssMetricV31: [{ cvssData: { vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }],
    },
  };
  assert.strictEqual(vectorFromRaw(raw), 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('vectorFromRaw ignores v2-only records', () => {
  assert.strictEqual(vectorFromRaw({ metrics: { cvssMetricV2: [{ cvssData: { vectorString: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' } }] } }), null);
});

test('vectorFromRaw returns null for a malformed vector', () => {
  assert.strictEqual(vectorFromRaw({ metrics: { cvssMetricV31: [{ cvssData: { vectorString: 'nonsense' } }] } }), null);
});

async function seed(store) {
  const s = await store.get(
    `INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id`);
  const raw = JSON.stringify({
    metrics: { cvssMetricV31: [{ cvssData: { vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] },
  });
  return store.get(
    `INSERT INTO items (source_id, external_id, title, raw_json) VALUES ($1,'e1','t',$2) RETURNING id`,
    [s.id, raw]);
}

test('backfill --dry-run reports the change but writes nothing', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const r = await backfill(store, { dryRun: true });
    assert.strictEqual(r.changed, 1);
    const row = await store.get('SELECT cvss_vector FROM items LIMIT 1');
    assert.strictEqual(row.cvss_vector, null);
  } finally { await cleanup(); }
});

test('backfill writes the vector and a second run is a no-op', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seed(store);
    const first = await backfill(store);
    assert.strictEqual(first.changed, 1);
    const row = await store.get('SELECT cvss_vector FROM items LIMIT 1');
    assert.strictEqual(row.cvss_vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

    const second = await backfill(store);
    assert.strictEqual(second.changed, 0);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/backfill-cvss-vector.test.js`
Expected: FAIL — `Cannot find module './backfill-cvss-vector'`.

- [ ] **Step 3: Write the implementation**

Create `server/backfill-cvss-vector.js`:

```js
// Re-derives items.cvss_vector from raw_json. Idempotent, no network — raw_json preserves the
// untouched upstream record, so the vector is recomputable at any time.
//
// writeItem's ON CONFLICT upsert only reaches rows a source is still actively returning, so
// this is the only path that populates the existing corpus.
//
// Note the inverted default, matching the other backfills in this directory: a bare
// invocation WRITES. Pass --dry-run to preview.
const { parseVector } = require('./cvss');

// v3.1 first, then v3.0. v2 is deliberately absent: cvss.js recognises but does not score it,
// and consequence.js reads v3 metric names (PR, UI, S) that a v2 vector does not carry.
const KEYS = ['cvssMetricV31', 'cvssMetricV30'];

function vectorFromRaw(raw) {
  if (!raw || typeof raw !== 'object' || !raw.metrics) return null;
  for (const key of KEYS) {
    const entries = raw.metrics[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const vector = entry && entry.cvssData && entry.cvssData.vectorString;
      // parseVector is the gate: an unparseable string is not stored, so every value in the
      // column is one consequence.js can actually read.
      if (typeof vector === 'string' && parseVector(vector)) return vector;
    }
  }
  return null;
}

async function backfill(store, { dryRun = false, batchSize = 500 } = {}) {
  let offset = 0;
  let scanned = 0;
  let changed = 0;
  let skipped = 0;

  for (;;) {
    const rows = await store.all(
      `SELECT id, raw_json, cvss_vector FROM items
        WHERE raw_json IS NOT NULL ORDER BY id LIMIT $1 OFFSET $2`,
      [batchSize, offset]);
    if (!rows.length) break;

    for (const row of rows) {
      scanned += 1;
      let raw;
      try { raw = JSON.parse(row.raw_json); } catch { skipped += 1; continue; }
      const vector = vectorFromRaw(raw);
      if (!vector || vector === row.cvss_vector) { skipped += 1; continue; }

      changed += 1;
      if (dryRun) continue;
      await store.run('UPDATE items SET cvss_vector = $1 WHERE id = $2', [vector, row.id]);
    }
    offset += rows.length;
  }

  return { scanned, changed, skipped };
}

module.exports = { backfill, vectorFromRaw };

if (require.main === module) {
  const store = require('./db');
  const dryRun = process.argv.includes('--dry-run');
  backfill(store, { dryRun })
    .then((r) => { console.log(dryRun ? 'dry run:' : 'wrote:', r); return store.close(); })
    .catch((e) => { console.error(e); process.exit(1); });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/backfill-cvss-vector.test.js`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add server/backfill-cvss-vector.js server/backfill-cvss-vector.test.js
git commit -m "feat(impact): backfill items.cvss_vector from raw_json"
```

---

### Task 4: `asset_roles.js`

**Files:**
- Create: `server/asset_roles.js`
- Create: `server/asset_roles.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces: `roleFor(vendor, product) -> string | null`, `ROLES` (the raw map, exported for tests only).

- [ ] **Step 1: Verify every slug against the corpus first**

This step is mandatory before writing the map — a slug matching nothing makes coverage look richer than it is, the rule `sector_profiles.js` already follows.

Run:

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -c "
SELECT vendor, product, count(*)::int AS refs
  FROM item_cpes GROUP BY vendor, product ORDER BY refs DESC LIMIT 40;"
```

Record the counts. Only slugs appearing in that output go into the map, each with its count in a comment. Drop any slug from the draft below that the query does not confirm, and add high-count ones it reveals.

- [ ] **Step 2: Write the failing test**

Create `server/asset_roles.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { roleFor, ROLES } = require('./asset_roles');

const SLUG_RE = /^[a-z0-9][a-z0-9._-]*$/;

test('every key is a vendor/product pair of valid CPE slugs', () => {
  for (const key of Object.keys(ROLES)) {
    const parts = key.split('/');
    assert.strictEqual(parts.length, 2, `malformed key: ${key}`);
    for (const p of parts) assert.ok(SLUG_RE.test(p), `not a slug: ${p} in ${key}`);
  }
});

test('every role is non-empty prose addressed to the reader', () => {
  for (const [key, text] of Object.entries(ROLES)) {
    assert.ok(text.length > 3, `role too short for ${key}`);
    assert.ok(!text.endsWith('.'), `role is a fragment, not a sentence: ${key}`);
  }
});

test('roleFor returns the mapped role', () => {
  assert.strictEqual(roleFor('fortinet', 'fortios'), 'your VPN and firewall');
});

test('roleFor is null for an unmapped product', () => {
  assert.strictEqual(roleFor('acme', 'nothing'), null);
});

test('roleFor is null for missing input rather than throwing', () => {
  assert.strictEqual(roleFor(null, null), null);
  assert.strictEqual(roleFor('fortinet', undefined), null);
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `node --test server/asset_roles.test.js`
Expected: FAIL — `Cannot find module './asset_roles'`.

- [ ] **Step 4: Write the implementation**

Create `server/asset_roles.js`. Replace the reference counts below with the real ones from Step 1, and delete any pair that query did not confirm:

```js
// Pure product -> plain-English role map. It answers "what does this thing hold or do for me",
// which is the noun the consequence sentence needs: "read, change and shut down YOUR COMPANY
// EMAIL" says something; "read, change and shut down exchange_server" does not.
//
// Same discipline as sector_profiles.js: every pair here was verified against item_cpes before
// being added, with its reference count recorded. A slug that matches nothing is worse than an
// omission — it makes coverage look richer than it is while describing no real item.
//
// Reference counts measured 2026-08-03 against item_cpes. UPDATE THESE from Step 1 of the plan
// task before committing; the numbers below are the shape, not the measurement.
const ROLES = {
  'microsoft/windows':          'the computers your staff use',
  'microsoft/exchange_server':  'your company email',
  'microsoft/office':           'the documents your staff open',
  'fortinet/fortios':           'your VPN and firewall',
  'cisco/ios':                  'your network equipment',
  'oracle/mysql':               'a database your systems rely on',
  'apache/http_server':         'your public website',
  'linux/linux_kernel':         'your servers',
  'mozilla/firefox':            'the browser your staff use',
  'google/chrome':              'the browser your staff use',
};

// Vendor and product are the lowercase CPE fields, so the key is built the same way
// item_cpes stores them. Anything unmapped yields null and the caller names the product
// directly rather than inventing a role for it.
function roleFor(vendor, product) {
  if (typeof vendor !== 'string' || typeof product !== 'string') return null;
  return ROLES[`${vendor}/${product}`] || null;
}

module.exports = { roleFor, ROLES };
```

- [ ] **Step 5: Run test to verify it passes**

Run: `node --test server/asset_roles.test.js`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add server/asset_roles.js server/asset_roles.test.js
git commit -m "feat(impact): add verified product-to-role map"
```

---

### Task 5: `consequence.js`

**Files:**
- Create: `server/consequence.js`
- Create: `server/consequence.test.js`

**Interfaces:**
- Consumes: `roleFor` from Task 4; `parseVector` from `server/cvss.js`.
- Produces: `buildConsequence({ vector, exposure, vendor, product, kevListed, kevDueDate, epssScore }) -> { reach, impact, role, urgency }` where each slot is `null` or `{ text, from }`, and `urgency` additionally carries `due: string | null`. Also exports `EPSS_URGENT_THRESHOLD = 0.5`.

`parseVector` returns an object keyed by CVSS abbreviation (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`). Confirm its exact return shape by reading `server/cvss.js` before writing the implementation, and adapt the property access if it differs.

- [ ] **Step 1: Write the failing test**

Create `server/consequence.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { buildConsequence, EPSS_URGENT_THRESHOLD } = require('./consequence');

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N';
const NO_IMPACT = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';

const base = (over = {}) => buildConsequence({
  vector: WORST, exposure: 'unknown', vendor: 'fortinet', product: 'fortios',
  kevListed: false, kevDueDate: null, epssScore: null, ...over,
});

// --- reach: AV crossed with exposure ---

test('AV:N on an internet-facing asset reaches anyone on the internet', () => {
  assert.match(base({ exposure: 'internet' }).reach.text, /anyone on the internet/);
});

test('AV:N on an internal asset reaches only what is already inside', () => {
  assert.match(base({ exposure: 'internal' }).reach.text, /already inside your network/);
});

test('AV:N with unknown exposure stays non-committal', () => {
  assert.match(base({ exposure: 'unknown' }).reach.text, /can reach it over the network/);
});

test('AV:L is about machine access regardless of exposure', () => {
  assert.match(base({ vector: LOCAL, exposure: 'internet' }).reach.text, /already has access to that machine/);
});

test('PR:N adds the no-password clause', () => {
  assert.match(base().reach.text, /with no password/);
});

test('PR:H says admin rights are required', () => {
  assert.match(base({ vector: LOCAL }).reach.text, /only with admin rights/);
});

test('UI:R adds the click clause', () => {
  assert.match(base({ vector: LOCAL }).reach.text, /clicks or opens something/);
});

test('reach records the metrics it came from', () => {
  assert.strictEqual(base({ exposure: 'internet' }).reach.from, 'AV:N/PR:N/UI:N + exposure=internet');
});

// --- impact: C/I/A ---

test('C:H I:H A:H reads as read, change and shut down', () => {
  assert.strictEqual(base().impact.text, 'read, change and shut down');
});

test('a low metric is rendered as partly', () => {
  assert.strictEqual(base({ vector: LOCAL }).impact.text, 'partly read');
});

test('all impact metrics None yields a null slot, not "no impact"', () => {
  assert.strictEqual(base({ vector: NO_IMPACT }).impact, null);
});

// --- role ---

test('a mapped product yields its role', () => {
  assert.strictEqual(base().role.text, 'your VPN and firewall');
});

test('an unmapped product yields a null role', () => {
  assert.strictEqual(base({ vendor: 'acme', product: 'nothing' }).role, null);
});

// --- urgency ---

test('KEV beats EPSS and carries the due date', () => {
  const u = base({ kevListed: true, kevDueDate: '2026-08-17', epssScore: 0.9 }).urgency;
  assert.match(u.text, /already used in real attacks/);
  assert.strictEqual(u.due, '2026-08-17');
  assert.strictEqual(u.from, 'KEV');
});

test('EPSS at the threshold is urgent, with no due date', () => {
  const u = base({ epssScore: EPSS_URGENT_THRESHOLD }).urgency;
  assert.match(u.text, /likely to be attacked soon/);
  assert.strictEqual(u.due, null);
});

test('EPSS below the threshold yields a null slot rather than filler', () => {
  assert.strictEqual(base({ epssScore: 0.4 }).urgency, null);
});

// --- missing data ---

test('no vector yields null reach and impact but keeps role and urgency', () => {
  const c = base({ vector: null, kevListed: true, kevDueDate: '2026-08-17' });
  assert.strictEqual(c.reach, null);
  assert.strictEqual(c.impact, null);
  assert.strictEqual(c.role.text, 'your VPN and firewall');
  assert.strictEqual(c.urgency.due, '2026-08-17');
});

test('a v4-only vector is unreadable and yields null reach and impact', () => {
  const c = base({ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H' });
  assert.strictEqual(c.reach, null);
  assert.strictEqual(c.impact, null);
});

test('a non-CVE item with no asset yields four null slots', () => {
  const c = buildConsequence({ vector: null, exposure: 'unknown', vendor: null, product: null,
    kevListed: false, kevDueDate: null, epssScore: null });
  assert.deepStrictEqual(c, { reach: null, impact: null, role: null, urgency: null });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/consequence.test.js`
Expected: FAIL — `Cannot find module './consequence'`.

- [ ] **Step 3: Write the implementation**

Create `server/consequence.js`:

```js
// Turns a CVSS vector, an asset's exposure and a product role into four plain-English fact
// slots. Pure: no I/O, no model, no database.
//
// This is the module that answers "how does this affect me". The tier says how much to care;
// these slots say what would actually happen. Both the model prompt and the template fallback
// are built from the same slots, so a rejected model output degrades to a sentence that is
// still specific.
//
// Every slot is independently nullable and carries `from`, the metrics it was derived from.
// Missing data is a null slot, never a guess — the same posture as confidence = NULL.
const { parseVector } = require('./cvss');
const { roleFor } = require('./asset_roles');

// Conservative on purpose. EPSS is a probability of exploitation in the next 30 days, and this
// threshold decides whether a user is told to hurry. Tune it against the quality.eval.json
// holdout method rather than by feel.
const EPSS_URGENT_THRESHOLD = 0.5;

// AV crossed with exposure. This crossing is the entire reason exposure is collected: AV:N
// alone is a property of the flaw, AV:N on an internet-facing asset is a statement about the
// reader.
function reachText(av, exposure) {
  if (av === 'N') {
    if (exposure === 'internet') return 'anyone on the internet';
    if (exposure === 'internal') return 'anyone already inside your network';
    return 'anyone who can reach it over the network';
  }
  if (av === 'A') return 'someone on the same network';
  if (av === 'L') return 'someone who already has access to that machine';
  if (av === 'P') return 'someone standing at the machine';
  return null;
}

const PRIVILEGE = { N: 'with no password', L: 'with any ordinary account', H: 'only with admin rights' };

function buildReach(metrics, exposure) {
  const who = reachText(metrics.AV, exposure);
  if (!who) return null;
  const parts = [who];
  if (PRIVILEGE[metrics.PR]) parts.push(PRIVILEGE[metrics.PR]);
  if (metrics.UI === 'R') parts.push('if a person clicks or opens something');
  return {
    text: parts.join(', '),
    from: `AV:${metrics.AV}/PR:${metrics.PR}/UI:${metrics.UI} + exposure=${exposure}`,
  };
}

const VERBS = { C: 'read', I: 'change', A: 'shut down' };

function joinList(values) {
  if (values.length === 1) return values[0];
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`;
}

// A :L metric is a real but partial effect. Rendering it as the full verb would overstate the
// consequence, and dropping it would understate it.
function buildImpact(metrics) {
  const parts = [];
  const from = [];
  for (const key of ['C', 'I', 'A']) {
    const value = metrics[key];
    if (value === 'H') { parts.push(VERBS[key]); from.push(`${key}:H`); }
    else if (value === 'L') { parts.push(`partly ${VERBS[key]}`); from.push(`${key}:L`); }
  }
  // All three None. That is an absent slot, not the claim "no impact" — a vector can be
  // scoped-changed or otherwise carry effects these three metrics do not express.
  if (!parts.length) return null;
  return { text: joinList(parts), from: from.join('/') };
}

function buildUrgency(kevListed, kevDueDate, epssScore) {
  if (kevListed) {
    return { text: 'already used in real attacks', due: kevDueDate || null, from: 'KEV' };
  }
  if (epssScore != null && Number(epssScore) >= EPSS_URGENT_THRESHOLD) {
    return { text: 'likely to be attacked soon', due: null, from: `EPSS>=${EPSS_URGENT_THRESHOLD}` };
  }
  // Not urgent. No filler text — an absent slot reads as "nothing to say here", which is true.
  return null;
}

function buildConsequence({
  vector, exposure = 'unknown', vendor, product, kevListed = false, kevDueDate = null, epssScore = null,
} = {}) {
  // parseVector returns null for anything it cannot read, including v4 vectors, which is
  // exactly the behaviour wanted here: no metrics means no reach and no impact claim.
  const metrics = vector ? parseVector(vector) : null;
  const role = roleFor(vendor, product);

  return {
    reach: metrics ? buildReach(metrics, exposure) : null,
    impact: metrics ? buildImpact(metrics) : null,
    role: role ? { text: role, from: `asset_roles: ${vendor}/${product}` } : null,
    urgency: buildUrgency(kevListed, kevDueDate, epssScore),
  };
}

module.exports = { buildConsequence, EPSS_URGENT_THRESHOLD };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/consequence.test.js`
Expected: PASS, 19 tests.

If `parseVector` returns a different shape than `{ AV, PR, UI, C, I, A }`, adapt the property access in `buildReach` / `buildImpact` — do not change the tests.

- [ ] **Step 5: Commit**

```bash
git add server/consequence.js server/consequence.test.js
git commit -m "feat(impact): add the pure consequence engine"
```

---

### Task 6: Profile assets — validation, read, write

**Files:**
- Modify: `server/profiles.js`
- Test: `server/profiles.test.js`

**Interfaces:**
- Consumes: `profile_assets` from Task 1.
- Produces: `validateProfile` accepts `assets: [{ product, exposure, vendor? }]` and returns them on `value.assets`; `getProfile` and `listProfiles` attach `assets` to each row; `createProfile` / `updateProfile` persist them, resolving an omitted vendor from `item_cpes`.

**`vendor` is optional on input.** The frontend has no vendor to send: `CpeFacet` is `{ value, refs }` and the survey's `products` signal is a bare `string[]`. So the server resolves it the same way the Task 2 migration does — join `item_cpes` on the product slug, and insert one row per distinct vendor when a slug appears under several. A slug matching no `item_cpes` row is skipped.

- [ ] **Step 1: Write the failing test**

Append to `server/profiles.test.js`:

```js
const ASSET = { vendor: 'fortinet', product: 'fortios', exposure: 'internet' };

test('validateProfile accepts well-formed assets', () => {
  const r = validateProfile({ ...VALID, assets: [ASSET] });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.value.assets, [ASSET]);
});

test('validateProfile defaults a missing exposure to unknown', () => {
  const r = validateProfile({ ...VALID, assets: [{ vendor: 'fortinet', product: 'fortios' }] });
  assert.strictEqual(r.value.assets[0].exposure, 'unknown');
});

test('validateProfile lowercases asset slugs', () => {
  const r = validateProfile({ ...VALID, assets: [{ vendor: 'FORTINET', product: 'FortiOS' }] });
  assert.deepStrictEqual(r.value.assets[0], { vendor: 'fortinet', product: 'fortios', exposure: 'unknown' });
});

test('validateProfile rejects an unknown exposure', () => {
  const r = validateProfile({ ...VALID, assets: [{ ...ASSET, exposure: 'sometimes' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /exposure/);
});

test('validateProfile rejects an asset with a non-slug product', () => {
  const r = validateProfile({ ...VALID, assets: [{ vendor: 'fortinet', product: 'Forti OS!' }] });
  assert.strictEqual(r.ok, false);
});

test('validateProfile accepts an asset with no vendor — the server resolves it', () => {
  const r = validateProfile({ ...VALID, assets: [{ product: 'fortios', exposure: 'internet' }] });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.value.assets[0], { vendor: null, product: 'fortios', exposure: 'internet' });
});

test('createProfile resolves an omitted vendor from item_cpes', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      `INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id`);
    const i = await store.get(
      `INSERT INTO items (source_id, external_id, title) VALUES ($1,'e1','t') RETURNING id`, [s.id]);
    await store.run(
      `INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')`, [i.id]);

    const created = await createProfile(store, {
      ...VALID, assets: [{ product: 'fortios', exposure: 'internet' }] });
    const read = await getProfile(store, created.id);
    assert.deepStrictEqual(read.assets,
      [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }]);
  } finally { await cleanup(); }
});

test('an asset whose product matches no item_cpes row is dropped, not stored', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, {
      ...VALID, assets: [{ product: 'ghost', exposure: 'internet' }] });
    const read = await getProfile(store, created.id);
    assert.deepStrictEqual(read.assets, []);
  } finally { await cleanup(); }
});

test('validateProfile deduplicates assets by vendor and product', () => {
  const r = validateProfile({ ...VALID, assets: [ASSET, { ...ASSET, exposure: 'internal' }] });
  assert.strictEqual(r.value.assets.length, 1);
});

test('createProfile persists assets and getProfile returns them', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID, assets: [ASSET] });
    const read = await getProfile(store, created.id);
    assert.deepStrictEqual(read.assets, [ASSET]);
  } finally { await cleanup(); }
});

test('updateProfile replaces the asset set and bumps profile_version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID, assets: [ASSET] });
    const updated = await updateProfile(store, created.id, {
      ...VALID, assets: [{ vendor: 'microsoft', product: 'windows', exposure: 'internal' }],
    });
    assert.strictEqual(updated.profile_version, created.profile_version + 1);
    const read = await getProfile(store, created.id);
    assert.deepStrictEqual(read.assets,
      [{ vendor: 'microsoft', product: 'windows', exposure: 'internal' }]);
  } finally { await cleanup(); }
});

test('listProfiles attaches assets to every row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await createProfile(store, { ...VALID, assets: [ASSET] });
    const rows = await listProfiles(store);
    assert.deepStrictEqual(rows[0].assets, [ASSET]);
  } finally { await cleanup(); }
});

test('a profile saved without assets reads back an empty array, never undefined', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, VALID);
    const read = await getProfile(store, created.id);
    assert.deepStrictEqual(read.assets, []);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/profiles.test.js`
Expected: FAIL — `r.value.assets` is `undefined`.

- [ ] **Step 3: Write the implementation**

In `server/profiles.js`, add after `slugList`:

```js
const EXPOSURES = ['internet', 'internal', 'unknown'];

// Assets are the precision path: only these can earn act_now, because a vendor-level claim is
// not evidence of exposure to a specific flaw. Same slug rule as vendors/products — a value
// that cannot match an item_cpes row is a value that would never match anything.
function assetList(input) {
  if (input == null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'assets must be an array' };
  const out = [];
  const seen = new Set();
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: 'asset entries must be objects' };
    // vendor is optional: the client has no vendor to send, so writeAssets resolves it from
    // item_cpes. When it IS supplied it still has to be a real slug.
    const vendor = raw.vendor == null || raw.vendor === ''
      ? null
      : String(raw.vendor).trim().toLowerCase();
    const product = typeof raw.product === 'string' ? raw.product.trim().toLowerCase() : '';
    if (vendor !== null && !SLUG_RE.test(vendor)) return { ok: false, error: `asset vendor is not a valid slug: ${raw.vendor}` };
    if (!SLUG_RE.test(product)) return { ok: false, error: `asset product is not a valid slug: ${raw.product}` };
    // An unanswered exposure is 'unknown', which is honest. It is never assumed to be internal:
    // that would silently demote an actively-exploited flaw on a survey question the user skipped.
    const exposure = raw.exposure == null ? 'unknown' : raw.exposure;
    if (!EXPOSURES.includes(exposure)) return { ok: false, error: `unknown exposure: ${raw.exposure}` };
    const key = `${vendor}/${product}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ vendor, product, exposure });
  }
  return { ok: true, value: out };
}
```

In `validateProfile`, before the return:

```js
  const assets = assetList(input.assets);
  if (!assets.ok) return assets;
```

and add `assets: assets.value` to the returned `value` object.

Add an asset loader and use it in every read:

```js
// Assets travel with the profile everywhere, because scoreRelevance needs them on the same
// object it already receives. An assetless profile reads back [], never undefined — callers
// should not have to distinguish "no assets" from "not loaded".
async function attachAssets(store, rows) {
  if (!rows.length) return rows;
  const ids = rows.map((r) => r.id);
  const assets = await store.all(
    `SELECT profile_id, vendor, product, exposure FROM profile_assets
      WHERE profile_id = ANY($1) ORDER BY vendor, product`, [ids]);
  const byProfile = new Map(ids.map((id) => [id, []]));
  for (const a of assets) {
    byProfile.get(a.profile_id).push({ vendor: a.vendor, product: a.product, exposure: a.exposure });
  }
  for (const row of rows) row.assets = byProfile.get(row.id) || [];
  return rows;
}

// Replaces the whole asset set. A null vendor is resolved from item_cpes with the same rule the
// Task 2 migration uses: one row per distinct vendor carrying that product slug, and a slug that
// matches nothing is dropped rather than stored as a value that can never match.
async function writeAssets(t, profileId, assets) {
  await t.run('DELETE FROM profile_assets WHERE profile_id = $1', [profileId]);
  for (const a of assets) {
    if (a.vendor) {
      await t.run(
        `INSERT INTO profile_assets (profile_id, vendor, product, exposure) VALUES ($1,$2,$3,$4)
         ON CONFLICT (profile_id, vendor, product) DO NOTHING`,
        [profileId, a.vendor, a.product, a.exposure]);
      continue;
    }
    await t.run(
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       SELECT DISTINCT $1, c.vendor, c.product, $3 FROM item_cpes c WHERE c.product = $2
       ON CONFLICT (profile_id, vendor, product) DO NOTHING`,
      [profileId, a.product, a.exposure]);
  }
}
```

Wrap `createProfile` and `updateProfile` in `store.tx` so the profile row and its assets are written together, calling `writeAssets` inside; and pass their results plus `listProfiles` / `getProfile` results through `attachAssets`. `getProfile` attaches to a single-element array and returns `rows[0]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/profiles.test.js`
Expected: PASS, all existing tests plus 10 new.

- [ ] **Step 5: Commit**

```bash
git add server/profiles.js server/profiles.test.js
git commit -m "feat(impact): profiles carry assets with an exposure flag"
```

---

### Task 7: Ladder v2

**Files:**
- Modify: `server/relevance_score.js`
- Test: `server/relevance_score.test.js`

**Interfaces:**
- Consumes: `profile.assets` from Task 6.
- Produces: `scoreRelevance(profile, item, now)` unchanged in signature, now returning `{ tier, score, matches, exposure }` where `exposure` is the matched asset's flag (`'unknown'` when nothing matched).

- [ ] **Step 1: Write the failing test**

Append to `server/relevance_score.test.js`:

```js
const ASSET_PROFILE = { ...PROFILE, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }] };
const cpe = (vendor, product) => ({ vendor, product });
const kevItem = (over = {}) => item({ cve: { kevListed: true, severity: 'critical', cvssScore: 9.8, epssScore: null }, ...over });

test('ladder v2: an internet-facing asset on a KEV CVE is act_now', () => {
  const r = scoreRelevance(ASSET_PROFILE, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW);
  assert.strictEqual(r.tier, 'act_now');
  assert.strictEqual(r.exposure, 'internet');
});

test('ladder v2: the same flaw on an internal-only asset is watch, not act_now', () => {
  const profile = { ...PROFILE, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internal' }] };
  const r = scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW);
  assert.strictEqual(r.tier, 'watch');
});

test('ladder v2: unknown exposure still reaches act_now', () => {
  const profile = { ...PROFILE, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'unknown' }] };
  assert.strictEqual(scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW).tier, 'act_now');
});

test('ladder v2: a vendor-only match never exceeds low, even on a KEV CVE', () => {
  const profile = { vendors: ['microsoft'], products: [], threat_domains: [], sector: 'finance',
    severity_floor: 'medium', assets: [] };
  const r = scoreRelevance(profile, kevItem({ cpes: [cpe('microsoft', 'windows')] }), NOW);
  assert.strictEqual(r.tier, 'low');
});

test('ladder v2: a legacy products[] match with no asset row never exceeds low', () => {
  const profile = { ...PROFILE, assets: [] };
  const r = scoreRelevance(profile, kevItem({ cpes: [cpe('fortinet', 'fortios')] }), NOW);
  assert.strictEqual(r.tier, 'low');
});

test('ladder v2: an asset match alone, with nothing severe or recent, is watch', () => {
  const r = scoreRelevance(ASSET_PROFILE, item({ cpes: [cpe('fortinet', 'fortios')], publishedAt: OLD }), NOW);
  assert.strictEqual(r.tier, 'watch');
});

test('ladder v2: exposure is unknown when no asset matched', () => {
  assert.strictEqual(scoreRelevance(ASSET_PROFILE, item(), NOW).exposure, 'unknown');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/relevance_score.test.js`
Expected: FAIL — the vendor-only case returns `act_now`, and `r.exposure` is `undefined`.

- [ ] **Step 3: Write the implementation**

In `server/relevance_score.js`, replace the match-derivation block and the ladder:

```js
  // Two signals of very different strength. An asset row is a specific claim ("we run FortiOS");
  // a vendors[]/products[] entry is the legacy, unqualified one. Only the first can be urgent —
  // 'microsoft' matches 7519 items, so letting it reach act_now is what made the verdict noise.
  const profAssets = profile.assets || [];
  const assetHits = cpes.filter((c) => profAssets.some((a) => a.vendor === c.vendor && a.product === c.product));
  const assetHit = assetHits.length > 0;

  const legacyHits = cpes.filter((c) => profProducts.includes(c.product) || profVendors.includes(c.vendor));
  const legacyHit = legacyHits.length > 0;

  // The strongest exposure among matched assets decides the rung: an internet-facing instance
  // is the one that matters even if the same product also runs internally.
  const EXPOSURE_RANK = { internet: 2, unknown: 1, internal: 0 };
  const exposure = assetHits.reduce((worst, c) => {
    const a = profAssets.find((x) => x.vendor === c.vendor && x.product === c.product);
    return EXPOSURE_RANK[a.exposure] > EXPOSURE_RANK[worst] ? a.exposure : worst;
  }, 'internal');
```

Guard the `reduce` seed: when `assetHits` is empty the result must be `'unknown'`, not `'internal'`. Write it as:

```js
  const exposure = assetHit ? assetHits.reduce(/* as above */, 'internal') : 'unknown';
```

Emit matches from `assetHits` for the `product` kind and from `legacyHits` for `vendor`, then replace the ladder:

```js
  let tier;
  if (assetHit && exposure !== 'internal' && (kev || atLeastHigh) && recent) tier = 'act_now';
  else if (assetHit && (kev || atLeastHigh) && recent) tier = 'watch';
  else if (assetHit) tier = 'watch';
  else if (domainMatch && atFloor && recent) tier = 'watch';
  else if (sectorMatch && recent) tier = 'watch';
  else if (legacyHit || domainMatch || atFloor) tier = 'low';
  else tier = 'not_yours';
```

Change the score weights so `assetHits` carries the 5 and `legacyHits` the 3, and return `exposure` alongside `tier`, `score` and `matches`.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/relevance_score.test.js`
Expected: PASS. Existing tests that asserted `act_now` from a bare `products[]` match will now fail — update those to add an `assets` entry, since the change in their outcome is the point of this task.

- [ ] **Step 5: Commit**

```bash
git add server/relevance_score.js server/relevance_score.test.js
git commit -m "feat(impact): ladder v2 — vendor matches can no longer be urgent"
```

---

### Task 8: Materialize `consequence` in the recompute pass

**Files:**
- Modify: `server/relevance.js`
- Test: `server/relevance.test.js`

**Interfaces:**
- Consumes: `buildConsequence` (Task 5), `scoreRelevance` returning `exposure` (Task 7), `items.cvss_vector` (Tasks 1 and 3).
- Produces: `item_relevance.consequence` populated on every row written by `recomputeProfile`.

`assembleItems` must additionally select `i.cvss_vector` and `ci.kev_due_date`. Read `server/db.js` for the actual `cve_intel` due-date column name before writing this — if the KEV due date is not stored, pass `null` and open a follow-up rather than inventing a column.

- [ ] **Step 1: Write the failing test**

Append to `server/relevance.test.js`:

```js
test('recomputeProfile materializes consequence slots', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      `INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id`);
    const i = await store.get(
      `INSERT INTO items (source_id, external_id, title, cvss_vector, published_at)
       VALUES ($1,'e1','t','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', now()) RETURNING id`, [s.id]);
    await store.run(
      `INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a','fortinet','fortios')`, [i.id]);
    const p = await createProfile(store, {
      name: 'p', sector: 'finance', vendors: [], products: [], threatDomains: [],
      severityFloor: 'medium', assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }],
    });

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2', [i.id, p.id]);
    assert.match(row.consequence.reach.text, /anyone on the internet/);
    assert.strictEqual(row.consequence.impact.text, 'read, change and shut down');
    assert.strictEqual(row.consequence.role.text, 'your VPN and firewall');
  } finally { await cleanup(); }
});

test('an item with no vector still gets a consequence object with null slots', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const s = await store.get(
      `INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id`);
    const i = await store.get(
      `INSERT INTO items (source_id, external_id, title) VALUES ($1,'e1','t') RETURNING id`, [s.id]);
    const p = await createProfile(store, {
      name: 'p', sector: 'finance', vendors: [], products: [], threatDomains: [], severityFloor: 'medium',
    });

    await recomputeProfile(store, p.id);

    const row = await store.get(
      'SELECT consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2', [i.id, p.id]);
    assert.deepStrictEqual(row.consequence,
      { reach: null, impact: null, role: null, urgency: null, exposure: 'unknown' });
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/relevance.test.js`
Expected: FAIL — `row.consequence` is `null`.

- [ ] **Step 3: Write the implementation**

In `assembleItems`, add `i.cvss_vector` and the KEV due-date column to the `SELECT`, and map them onto each item as `cvssVector` and `cve.kevDueDate`.

In `recomputeProfile`, inside the item loop:

```js
  for (const item of items) {
    const { tier, score, matches, exposure } = scoreRelevance(profile, item, now);
    tiers[tier] += 1;

    // Deterministic, pure and cheap, so it is materialized in the same pass rather than
    // recomputed on every read. It cannot affect `tier` — that was decided on the line above.
    // The matched asset is the one whose exposure the scorer selected; its vendor/product give
    // the role lookup something to key on.
    const asset = (profile.assets || []).find((a) => a.exposure === exposure
      && (item.cpes || []).some((c) => c.vendor === a.vendor && c.product === a.product));
    const consequence = buildConsequence({
      vector: item.cvssVector,
      exposure,
      vendor: asset ? asset.vendor : null,
      product: asset ? asset.product : null,
      kevListed: !!(item.cve && item.cve.kevListed),
      kevDueDate: item.cve ? item.cve.kevDueDate : null,
      epssScore: item.cve ? item.cve.epssScore : null,
    });

    // exposure rides along inside the stored JSON so the read path never has to recover it by
    // parsing a `from` string. buildConsequence itself stays a pure four-slot function.
    values.push([profile.id, item.id, profile.profile_version, tier, score,
      JSON.stringify(matches), JSON.stringify({ ...consequence, exposure })]);
  }
```

Update the batch insert: 7 params per row now, so change `INSERT_BATCH` reasoning in its comment (7 × 1000 = 7000 params, still far inside Postgres's 65535 cap), add `consequence` to the column list, and add a seventh `$n::jsonb` placeholder to the tuple template.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/relevance.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/relevance.js server/relevance.test.js
git commit -m "feat(impact): materialize consequence slots in the recompute pass"
```

---

### Task 9: Expose `consequence` and `exposure` through the API

**Files:**
- Modify: `server/index.js` (feed relevance select ~line 375-430; item detail ~line 468-477)
- Test: `server/api.test.js`
- Modify: `docs/API.md`

**Interfaces:**
- Consumes: `item_relevance.consequence` from Task 8.
- Produces: `relevance.consequence` and `relevance.exposure` on `GET /api/items` rows and `GET /api/items/:id`; `assets` accepted on `POST` / `PUT /api/profiles`.

- [ ] **Step 1: Write the failing test**

Append to `server/api.test.js`. It already defines `get(app, path)`, `send(app, method, path, body, headers)`, `seedRelevanceFixture(store)` (which creates a FortiOS item with a `fortinet/fortios` CPE row) and `REL_PROFILE` — reuse them rather than adding parallel helpers.

```js
test('GET /api/items/:id includes consequence slots for the active profile', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    const { hitId } = await seedRelevanceFixture(store);
    // seedRelevanceFixture's item has no vector — add one so reach and impact are derivable.
    await store.run(
      `UPDATE items SET cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' WHERE id = $1`,
      [hitId]);

    const created = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE,
      name: 'Consequence',
      assets: [{ product: 'fortios', exposure: 'internet' }],
    });
    assert.strictEqual(created.status, 201);
    // The route recomputes in the background; run it synchronously so the read is deterministic.
    await send(app, 'POST', `/api/profiles/${created.body.id}/relevance/recompute`, null);

    const res = await get(app, `/api/items/${hitId}?profileId=${created.body.id}`);
    assert.strictEqual(res.status, 200);
    assert.match(res.body.relevance.consequence.reach.text, /anyone on the internet/);
    assert.strictEqual(res.body.relevance.consequence.impact.text, 'read, change and shut down');
    assert.strictEqual(res.body.relevance.exposure, 'internet');
  } finally { await cleanup(); }
});

test('POST /api/profiles accepts assets and returns them resolved', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const app = createApp(store);
    await seedRelevanceFixture(store);
    const res = await send(app, 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'assets-ok',
      assets: [{ product: 'fortios', exposure: 'internet' }],
    });
    assert.strictEqual(res.status, 201);
    assert.deepStrictEqual(res.body.assets,
      [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }]);
  } finally { await cleanup(); }
});

test('POST /api/profiles rejects an unknown exposure with 400', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const res = await send(createApp(store), 'POST', '/api/profiles', {
      ...REL_PROFILE, name: 'assets-bad',
      assets: [{ product: 'fortios', exposure: 'sometimes' }],
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.body.error, /exposure/);
  } finally { await cleanup(); }
});

test('relevance is null when no profile is active', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const { hitId } = await seedRelevanceFixture(store);
    const res = await get(createApp(store), `/api/items/${hitId}`);
    assert.strictEqual(res.body.relevance, null);
  } finally { await cleanup(); }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/api.test.js`
Expected: FAIL — `res.body.relevance.consequence` is `undefined`.

- [ ] **Step 3: Write the implementation**

In the feed handler, extend `relSelect` in both branches:

```js
    let relSelect = 'NULL::text AS rel_tier, NULL::jsonb AS rel_matches, NULL::text AS rel_sentence, '
      + 'NULL::jsonb AS rel_consequence';
```

and in the profile branch:

```js
      relSelect = "COALESCE(ir.tier, 'not_yours') AS rel_tier, COALESCE(ir.matches, '[]'::jsonb) AS rel_matches, "
        + 'irp.sentence AS rel_sentence, ir.consequence AS rel_consequence';
```

In the row mapping loop:

`exposure` is read straight off the stored JSON — Task 8 writes it there as `{ ...consequence, exposure }`. Never parse it back out of a `from` string; that field is human-facing provenance, not a data channel.

```js
      // consequence is null for a row written before the column existed, or for an item the
      // recompute has not reached yet. The panel renders that as a stated gap, not a blank.
      row.relevance = profile
        ? {
          tier: row.rel_tier,
          matches: row.rel_matches,
          sentence: row.rel_sentence ?? null,
          consequence: row.rel_consequence ?? null,
          exposure: row.rel_consequence?.exposure ?? 'unknown',
        }
        : null;
      delete row.rel_consequence;
```

In `GET /api/items/:id`, add `consequence` to the `SELECT` and the assembled object:

```js
      const rel = await store.get(
        'SELECT tier, matches, consequence FROM item_relevance WHERE item_id = $1 AND profile_id = $2 AND profile_version = $3',
        [id, profile.id, profile.profile_version]);
      ...
      relevance = {
        tier: rel?.tier ?? 'not_yours',
        matches: rel?.matches ?? [],
        sentence: prose?.sentence ?? null,
        consequence: rel?.consequence ?? null,
        exposure: rel?.consequence?.exposure ?? 'unknown',
      };
```

Profile write already flows through `profiles.validateProfile`, so `assets` needs no route change — verify with the tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/api.test.js`
Expected: PASS.

- [ ] **Step 5: Document and commit**

Update `docs/API.md`: the `relevance` object on `GET /api/items` and `GET /api/items/:id` now carries `consequence` (four nullable slots plus `exposure`), and `POST`/`PUT /api/profiles` accept `assets`.

```bash
git add server/index.js server/api.test.js docs/API.md
git commit -m "feat(impact): expose consequence slots and asset exposure through the API"
```

---

### Task 10: Prose v2

**Files:**
- Modify: `server/relevance_prose.js`
- Test: `server/relevance_prose.test.js`

**Interfaces:**
- Consumes: `item_relevance.consequence` from Task 8.
- Produces: `buildPrompt(profile, item)` built from slots; new `templateSentence(consequence, matches) -> string`.

`SCAFFOLD_RE` and `BREACH_CLAIM_RE` are unchanged. The template fallback is the real win here — a rejected model output must still land on a specific sentence.

- [ ] **Step 1: Write the failing test**

Append to `server/relevance_prose.test.js`:

```js
const { templateSentence } = require('./relevance_prose');

const FULL = {
  reach: { text: 'anyone on the internet, with no password', from: 'x' },
  impact: { text: 'read, change and shut down', from: 'x' },
  role: { text: 'your company email', from: 'x' },
  urgency: { text: 'already used in real attacks', due: '2026-08-17', from: 'KEV' },
};

test('templateSentence names the reach, the impact and the role', () => {
  const s = templateSentence(FULL, []);
  assert.match(s, /anyone on the internet/);
  assert.match(s, /read, change and shut down/);
  assert.match(s, /your company email/);
});

test('templateSentence omits a null slot without leaving a gap', () => {
  const s = templateSentence({ ...FULL, urgency: null }, []);
  assert.ok(!/undefined|null/.test(s));
});

test('templateSentence falls back to the match sentence when every slot is null', () => {
  const s = templateSentence({ reach: null, impact: null, role: null, urgency: null },
    [{ kind: 'product', value: 'fortinet fortios' }]);
  assert.ok(s.length > 0);
  assert.ok(!/undefined/.test(s));
});

test('buildPrompt states the slot facts and never the raw kind:value pairs', () => {
  const p = buildPrompt({ sector: 'finance' },
    { title: 'Exchange flaw', summary: null, consequence: FULL, matches: [] });
  assert.match(p, /anyone on the internet/);
  assert.ok(!/"kind"/.test(p));
});

test('buildPrompt keeps the no-breach-claim instruction', () => {
  const p = buildPrompt({ sector: 'finance' },
    { title: 't', summary: null, consequence: FULL, matches: [] });
  assert.match(p, /never state or imply/i);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test server/relevance_prose.test.js`
Expected: FAIL — `templateSentence is not a function`.

- [ ] **Step 3: Write the implementation**

Add to `server/relevance_prose.js`:

```js
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// The deterministic sentence, now built from the consequence slots rather than from match
// key/value pairs. This is what a user reads whenever the model is unreachable or its output is
// rejected, so it has to stand on its own — "Matches your stack (microsoft windows)" did not.
function templateSentence(consequence, matches) {
  const c = consequence || {};
  const target = c.role ? c.role.text : 'this system';
  const parts = [];
  if (c.reach && c.impact) parts.push(`${cap(c.reach.text)} could ${c.impact.text} ${target}`);
  else if (c.reach) parts.push(`${cap(c.reach.text)} could reach ${target}`);
  else if (c.impact) parts.push(`This could ${c.impact.text} ${target}`);
  if (c.urgency) parts.push(`It is ${c.urgency.text}`);
  // Nothing derivable from the vector — fall back to the reason the verdict fired at all,
  // which is still better than silence.
  if (!parts.length) return describeMatches(matches);
  return `${parts.join('. ')}.`;
}
```

Export it alongside the existing names: `module.exports = { generateProse, buildPrompt, templateSentence, isUsableSentence, PROSE_TIERS };`

Replace `buildPrompt`'s `Facts:` line with the slot facts:

```js
    `Facts: ${factLines(item.consequence)}`,
```

where `factLines` renders the non-null slots as prose clauses (`who: ...`, `what: ...`, `how urgent: ...`), never as JSON — a small model shown key/value input copies it into the output, which is the failure the existing comment in this file records.

Extend the `pending` query in `generateProse` to select `ir.consequence`, and pass it through on each row.

In the worker, replace the `failed` path's silent skip with nothing else — the NOT EXISTS query already retries it on the next run. Behaviour unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test server/relevance_prose.test.js`
Expected: PASS, existing tests plus 5 new. All `SCAFFOLD_RE` / `BREACH_CLAIM_RE` cases must still pass untouched.

- [ ] **Step 5: Commit**

```bash
git add server/relevance_prose.js server/relevance_prose.test.js
git commit -m "feat(impact): build prose and its fallback from consequence slots"
```

---

### Task 11: Frontend types and presentation logic

**Files:**
- Modify: `frontend-v4/src/app/core/models.ts`
- Modify: `frontend-v4/src/app/core/relevance.ts`
- Test: `frontend-v4/src/app/core/relevance.spec.ts`

**Interfaces:**
- Consumes: the API shape from Task 9.
- Produces: types `ConsequenceSlot`, `Consequence`, `ProfileAsset`; functions `tierSubline(relevance) -> string | null`, `slotText(slot) -> string`, `hasConsequence(relevance) -> boolean`.

- [ ] **Step 1: Write the failing test**

Append to `frontend-v4/src/app/core/relevance.spec.ts`:

```ts
import { tierLabel, tierSubline, slotText, hasConsequence } from './relevance';

const rel = (over: any = {}) => ({ tier: 'act_now', matches: [], sentence: null, exposure: 'internet',
  consequence: { reach: { text: 'anyone on the internet', from: 'x' }, impact: null, role: null,
    urgency: { text: 'already used in real attacks', due: '2026-08-17', from: 'KEV' } }, ...over });

it('act_now uses the KEV due date as its sub-line when present', () => {
  expect(tierSubline(rel() as any)).toContain('Aug 17');
});

it('act_now without a due date falls back to a fixed window', () => {
  const r = rel({ consequence: { reach: null, impact: null, role: null,
    urgency: { text: 'likely to be attacked soon', due: null, from: 'EPSS>=0.5' } } });
  expect(tierSubline(r as any)).toBe('within 48 hours');
});

it('watch reads as a plan, not a vigil', () => {
  expect(tierLabel('watch')).toBe('Plan a fix');
  expect(tierSubline(rel({ tier: 'watch' }) as any)).toBe('this month');
});

it('low and not_yours have no sub-line', () => {
  expect(tierSubline(rel({ tier: 'low' }) as any)).toBeNull();
  expect(tierSubline(rel({ tier: 'not_yours' }) as any)).toBeNull();
});

it('slotText states the gap rather than rendering blank', () => {
  expect(slotText(null)).toBe('not stated in the source data');
  expect(slotText({ text: 'anyone on the internet', from: 'x' })).toBe('anyone on the internet');
});

it('hasConsequence is false when every slot is null', () => {
  expect(hasConsequence(rel({ consequence: { reach: null, impact: null, role: null, urgency: null } }) as any)).toBe(false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend-v4 && npx vitest run src/app/core/relevance.spec.ts`
Expected: FAIL — `tierSubline` is not exported.

- [ ] **Step 3: Write the implementation**

In `models.ts`:

```ts
// One consequence fact. `from` is the metrics it was derived from, shown in the UI so the claim
// is auditable rather than asserted.
export interface ConsequenceSlot { text: string; from: string; due?: string | null; }

// Every slot is independently nullable. A null slot means the source data did not say — it is
// rendered as a stated gap, never as a blank or a guess.
export interface Consequence {
  reach: ConsequenceSlot | null;
  impact: ConsequenceSlot | null;
  role: ConsequenceSlot | null;
  urgency: ConsequenceSlot | null;
  exposure?: 'internet' | 'internal' | 'unknown';
}

export interface ProfileAsset {
  vendor: string;
  product: string;
  exposure: 'internet' | 'internal' | 'unknown';
}
```

Add `consequence?: Consequence | null;` and `exposure?: string;` to `Relevance`, `assets: ProfileAsset[];` to `Profile`, and `assets: ProfileAsset[];` to `ProfilePayload`.

In `relevance.ts`, change `LABELS.watch` to `'Plan a fix'` and `LABELS.low` to `'Background'`, then add:

```ts
// Tiers state a deadline, not a mood. "Watch" told a reader nothing; a date or a window tells
// them when. The KEV due date is a real, externally-set deadline and always wins over the
// generic window.
export function tierSubline(relevance: Relevance | null | undefined): string | null {
  const tier = relevance?.tier;
  if (tier === 'act_now') {
    const due = relevance?.consequence?.urgency?.due;
    return due ? `fix by ${formatDue(due)}` : 'within 48 hours';
  }
  if (tier === 'watch') return 'this month';
  return null;
}

function formatDue(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// A missing slot is a fact about the source data, so it is stated rather than hidden. Blank
// space would read as "nothing to worry about", which is not what null means.
export function slotText(slot: ConsequenceSlot | null | undefined): string {
  return slot?.text ?? 'not stated in the source data';
}

export function hasConsequence(relevance: Relevance | null | undefined): boolean {
  const c = relevance?.consequence;
  return !!c && !!(c.reach || c.impact || c.role || c.urgency);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend-v4 && npx vitest run src/app/core/relevance.spec.ts && npx tsc --noEmit`
Expected: PASS, and no type errors.

- [ ] **Step 5: Commit**

```bash
git add frontend-v4/src/app/core/models.ts frontend-v4/src/app/core/relevance.ts frontend-v4/src/app/core/relevance.spec.ts
git commit -m "feat(impact): tier sub-lines and consequence slot accessors"
```

---

### Task 12: `tf-impact-panel` and the chip sub-line

**Files:**
- Create: `frontend-v4/src/app/ui/impact-panel.component.ts`
- Modify: `frontend-v4/src/app/ui/relevance-chip.component.ts`
- Modify: `frontend-v4/src/app/pages/intel/item-detail.component.ts:77-86`
- Test: `frontend-v4/src/app/ui/impact-panel.spec.ts`

**Interfaces:**
- Consumes: `tierLabel`, `tierSubline`, `slotText`, `hasConsequence`, `explanation`, `isModelWritten` from Task 11.
- Produces: `<tf-impact-panel [relevance]="rel" />`.

- [ ] **Step 1: Write the failing test**

Create `frontend-v4/src/app/ui/impact-panel.spec.ts`, following the existing component-spec style in this directory:

```ts
import { TestBed } from '@angular/core/testing';
import { ImpactPanelComponent } from './impact-panel.component';

const full = {
  tier: 'act_now', matches: [], sentence: null, exposure: 'internet',
  consequence: {
    reach: { text: 'anyone on the internet, with no password', from: 'AV:N/PR:N/UI:N + exposure=internet' },
    impact: { text: 'read, change and shut down', from: 'C:H/I:H/A:H' },
    role: { text: 'your company email', from: 'asset_roles: microsoft/exchange_server' },
    urgency: { text: 'already used in real attacks', due: '2026-08-17', from: 'KEV' },
  },
};

function render(relevance: any) {
  const f = TestBed.createComponent(ImpactPanelComponent);
  f.componentInstance.relevance = relevance;
  f.detectChanges();
  return f.nativeElement.textContent as string;
}

it('renders all four blocks', () => {
  const text = render(full);
  expect(text).toContain('anyone on the internet');
  expect(text).toContain('read, change and shut down');
  expect(text).toContain('your company email');
  expect(text).toContain('already used in real attacks');
});

it('states the gap for a null slot instead of rendering blank', () => {
  const text = render({ ...full, consequence: { ...full.consequence, reach: null } });
  expect(text).toContain('not stated in the source data');
});

it('renders without throwing when every slot is null', () => {
  const text = render({ ...full, consequence: { reach: null, impact: null, role: null, urgency: null } });
  expect(text).toContain('not stated in the source data');
});

it('renders nothing when relevance is null', () => {
  expect(render(null).trim()).toBe('');
});

it('prompts for the exposure answer when it is unknown', () => {
  const text = render({ ...full, exposure: 'unknown' });
  expect(text).toContain('not told us');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend-v4 && npx vitest run src/app/ui/impact-panel.spec.ts`
Expected: FAIL — cannot resolve `./impact-panel.component`.

- [ ] **Step 3: Write the component**

Create `frontend-v4/src/app/ui/impact-panel.component.ts`:

```ts
import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { tierLabel, tierSubline, slotText, explanation, isModelWritten } from '../core/relevance';
import type { Relevance } from '../core/models';

// "How does this affect you" as a real section, not a tooltip. Four labelled blocks so a
// missing fact reads as a visible gap rather than as silence — the same rule the README applies
// to a NULL confidence.
//
// Severity says how bad this is in general. This says what it would do to this reader.
@Component({
  selector: 'tf-impact-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (relevance; as rel) {
      <section class="impact">
        <header>
          <h3>How this affects you</h3>
          <span class="tier">{{ label }}@if (subline) {<span class="sub"> · {{ subline }}</span>}</span>
        </header>
        <dl>
          <div><dt>Who could do it</dt><dd>{{ text(rel.consequence?.reach) }}</dd></div>
          <div><dt>What they'd get</dt><dd>{{ text(rel.consequence?.impact) }}</dd></div>
          <div><dt>What that is</dt><dd>{{ text(rel.consequence?.role) }}</dd></div>
          <div><dt>How urgent</dt><dd>{{ text(rel.consequence?.urgency) }}</dd></div>
          <div>
            <dt>Why you</dt>
            <dd>
              {{ explanation(rel) }}
              @if (isModelWritten(rel)) {
                <span class="ai-tag" title="Written by a local model — the tier itself is decided by deterministic rules, not the model">AI-generated</span>
              }
            </dd>
          </div>
        </dl>
        @if (rel.exposure === 'unknown') {
          <p class="gap">You have not told us whether this is reachable from the internet, so this
            assumes the worst. Answer it in your profile to sharpen the verdict.</p>
        }
      </section>
    }
  `,
  styles: [`
    .impact dl { display: grid; gap: 8px; }
    .impact div { display: grid; grid-template-columns: 160px 1fr; gap: 12px; }
    dt { color: var(--ink-2); font-size: var(--fs-xs); }
    .gap { color: var(--ink-2); font-size: var(--fs-xs); margin-top: 12px; }
  `],
})
export class ImpactPanelComponent {
  @Input() relevance: Relevance | null = null;

  get label() { return tierLabel(this.relevance?.tier); }
  get subline() { return tierSubline(this.relevance); }
  text = slotText;
  explanation = explanation;
  isModelWritten = isModelWritten;
}
```

- [ ] **Step 4: Wire it into the detail page and the chip**

In `item-detail.component.ts`, replace lines 77-86 (the `Relevance to you` panel) with:

```html
      @if (d.relevance; as rel) {
        <tf-impact-panel [relevance]="rel" />
      }
```

and swap the import and `imports:` entry from the old panel usage to `ImpactPanelComponent`.

In `relevance-chip.component.ts`, add the sub-line inside the chip:

```html
      >{{ label }}@if (subline) { <span class="sub">· {{ subline }}</span> }</span>
```

with `get subline() { return tierSubline(this.relevance); }` and a `.sub { opacity: .75; font-weight: 400; }` style rule.

- [ ] **Step 5: Run the tests**

Run: `cd frontend-v4 && npx vitest run && npx tsc --noEmit`
Expected: PASS, no type errors.

- [ ] **Step 6: Commit**

```bash
git add frontend-v4/src/app/ui/impact-panel.component.ts frontend-v4/src/app/ui/impact-panel.spec.ts frontend-v4/src/app/ui/relevance-chip.component.ts frontend-v4/src/app/pages/intel/item-detail.component.ts
git commit -m "feat(impact): add the impact panel and tier sub-lines to the chip"
```

---

### Task 13: Onboarding exposure step

**Files:**
- Modify: `frontend-v4/src/app/pages/onboarding/survey.component.ts`
- Test: `frontend-v4/src/app/pages/onboarding/survey.spec.ts` (create if absent, following the spec style used elsewhere in the app)

**Interfaces:**
- Consumes: `ProfileAsset` from Task 11; `ProfilePayload.assets`.
- Produces: the survey submits `assets: [{ product, exposure }]` alongside `products`.

**The client sends no vendor.** `CpeFacet` is `{ value, refs }` and the survey's `products` signal is a `string[]` of product slugs — there is no vendor anywhere on this page. Task 6's `writeAssets` resolves it server-side from `item_cpes`. Do not add a vendor lookup here.

The component keeps its existing four steps and signals (`step`, `sector`, `vendors`, `products`, `threatDomains`, `kind`, `term`, `facets`); this adds a fifth step and one signal. Read the component before editing and follow its `signal()` / `@if (step() === n)` structure exactly.

- [ ] **Step 1: Write the failing test**

Create `frontend-v4/src/app/pages/onboarding/survey.spec.ts`:

```ts
import { TestBed } from '@angular/core/testing';
import { SurveyComponent } from './survey.component';
import { ApiService } from '../../core/api.service';

// The survey's only outbound call is the profile POST, so a stub that records its payload is
// the whole test double needed.
function setup() {
  const sent: any[] = [];
  const api = {
    listSectors: () => Promise.resolve([]),
    listDomains: () => Promise.resolve([]),
    createProfile: (p: any) => { sent.push(p); return Promise.resolve({ id: 1, ...p }); },
  };
  TestBed.configureTestingModule({
    imports: [SurveyComponent],
    providers: [{ provide: ApiService, useValue: api }],
  });
  const f = TestBed.createComponent(SurveyComponent);
  return { f, c: f.componentInstance as any, sent };
}

it('submits one asset per chosen product, defaulting exposure to unknown', async () => {
  const { c, sent } = setup();
  c.name = 'Test';
  c.sector.set({ slug: 'finance', label: 'Finance', recommendation: {} });
  c.products.set(['fortios']);
  c.syncAssets();
  await c.submit();
  expect(sent[0].assets).toEqual([{ product: 'fortios', exposure: 'unknown' }]);
});

it('carries the chosen exposure through to the payload', async () => {
  const { c, sent } = setup();
  c.name = 'Test';
  c.sector.set({ slug: 'finance', label: 'Finance', recommendation: {} });
  c.products.set(['fortios']);
  c.syncAssets();
  c.setExposure('fortios', 'internet');
  await c.submit();
  expect(sent[0].assets).toEqual([{ product: 'fortios', exposure: 'internet' }]);
});

it('still submits products[] so the legacy low tier keeps working', async () => {
  const { c, sent } = setup();
  c.name = 'Test';
  c.sector.set({ slug: 'finance', label: 'Finance', recommendation: {} });
  c.products.set(['fortios']);
  c.syncAssets();
  await c.submit();
  expect(sent[0].products).toContain('fortios');
});

it('dropping a product drops its asset', async () => {
  const { c } = setup();
  c.products.set(['fortios', 'windows']);
  c.syncAssets();
  c.products.set(['fortios']);
  c.syncAssets();
  expect(c.assets().map((a: any) => a.product)).toEqual(['fortios']);
});
```

Adjust the `ApiService` stub's method names to whatever `frontend-v4/src/app/core/api.service.ts` actually exposes — read it first. The assertions on `sent[0]` do not change.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend-v4 && npx vitest run src/app/pages/onboarding/survey.spec.ts`
Expected: FAIL — `payload.assets` is `undefined`.

- [ ] **Step 3: Add the state**

Add to the component class, beside the existing signals:

```ts
  // One row per chosen product. Kept in sync with products() rather than derived from it,
  // because the exposure answer has to survive the user going back and forth between steps.
  readonly assets = signal<{ product: string; exposure: 'internet' | 'internal' | 'unknown' }[]>([]);

  // Called when leaving the tech step. Adds a row for each newly chosen product at 'unknown',
  // drops rows for products no longer selected, and preserves every answer already given.
  syncAssets() {
    const chosen = this.products();
    const existing = new Map(this.assets().map((a) => [a.product, a.exposure]));
    this.assets.set(chosen.map((product) => ({
      product,
      exposure: existing.get(product) ?? 'unknown',
    })));
  }

  setExposure(product: string, exposure: 'internet' | 'internal' | 'unknown') {
    this.assets.update((rows) => rows.map((a) => (a.product === product ? { ...a, exposure } : a)));
  }
```

Call `syncAssets()` from the buttons that leave the tech step (`step.set(4)` in both the recommended and customize branches) so the list is populated before the new step renders.

Add `assets: this.assets()` to the payload built in `submit()`. Leave `products` exactly as it is — the legacy array still feeds the `low` tier for anything the asset path misses.

- [ ] **Step 4: Add the step UI**

Insert a new step between the current tech step (3) and interests, renumbering the later step and extending `stepLabels` to `['Sector', 'Recommended', 'Tech', 'Exposure', 'Interests']`:

```html
      @if (step() === 4) {
        <fieldset>
          <legend>Can each of these be reached from the internet?</legend>
          <p class="hint">Not sure is a fine answer — it is treated as the worst case, which is
            safer than a guess.</p>
          @for (a of assets(); track a.product) {
            <div class="row">
              <span>{{ a.product }}</span>
              <label><input type="radio" [name]="a.product" value="internet"
                [checked]="a.exposure === 'internet'" (change)="setExposure(a.product, 'internet')" /> Yes</label>
              <label><input type="radio" [name]="a.product" value="internal"
                [checked]="a.exposure === 'internal'" (change)="setExposure(a.product, 'internal')" /> No</label>
              <label><input type="radio" [name]="a.product" value="unknown"
                [checked]="a.exposure === 'unknown'" (change)="setExposure(a.product, 'unknown')" /> Not sure</label>
            </div>
          }
          @if (!assets().length) {
            <p class="hint">No products selected — nothing to answer here.</p>
          }
          <button type="button" class="primary" (click)="step.set(5)">Continue</button>
          <button type="button" class="ghost" (click)="step.set(3)">Back</button>
        </fieldset>
      }
```

Renumber the existing interests step from `4` to `5`, including its Back button target.

- [ ] **Step 5: Run the tests**

Run: `cd frontend-v4 && npx vitest run && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add frontend-v4/src/app/pages/onboarding/survey.component.ts frontend-v4/src/app/pages/onboarding/survey.spec.ts
git commit -m "feat(impact): ask whether each asset is reachable from the internet"
```

---

### Task 14: Full verification and backfill run

**Files:** none modified — this task proves the work.

- [ ] **Step 1: Run the whole backend suite**

Run: `npm test`
Expected: PASS. Investigate any failure rather than adjusting the assertion.

- [ ] **Step 2: Run the whole frontend suite**

Run: `cd frontend-v4 && npm test`
Expected: PASS (`tsc --noEmit` plus vitest).

- [ ] **Step 3: Preview the vector backfill against the real database**

Run: `node server/backfill-cvss-vector.js --dry-run`
Expected: a `changed` count in the low thousands. If it reports 0, the metric key names in `vectorFromRaw` do not match what the NVD adapter actually stores — inspect one `raw_json` before proceeding.

- [ ] **Step 4: Run the backfill and recompute**

```bash
node server/backfill-cvss-vector.js
curl -s -X POST http://localhost:4173/api/profiles/1/relevance/recompute
```

- [ ] **Step 5: Confirm the slots landed**

```bash
docker exec -e PGPASSWORD=postgres threatflow-pg16 psql -U postgres -d threatflow -X -c "
SELECT count(*) FILTER (WHERE consequence->'reach' <> 'null'::jsonb) AS with_reach,
       count(*) FILTER (WHERE consequence->'impact' <> 'null'::jsonb) AS with_impact,
       count(*) AS total
  FROM item_relevance WHERE tier IN ('act_now','watch');"
```

Expected: `with_reach` and `with_impact` are a substantial fraction of `total`. A near-zero result means the vector backfill or the `assembleItems` join is wrong — fix it before shipping, since the whole feature reads as "not stated in the source data" otherwise.

- [ ] **Step 6: Look at the actual page**

Start both servers, open an `act_now` item, and read the panel. The sentence has to make sense to someone who does not know what CVSS is. If it does not, that is a real finding — record it before moving to Spec B.

- [ ] **Step 7: Commit any fixes**

```bash
git add -A
git commit -m "fix(impact): corrections found during end-to-end verification"
```

---

## Notes for Spec B

Spec B (remediation playbooks) consumes, unchanged: `items.cvss_vector`, `asset_roles.roleFor`, `profile_assets.exposure`, and `item_relevance.consequence`. Its `item_playbooks` table was named but deliberately not created here. Measured grounding coverage as of 2026-08-03: 104 items via KEV `requiredAction`, 1,542 via NVD `Patch` references, 2,577 via `Vendor Advisory`, out of 11,149 items.
