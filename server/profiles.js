// Profile CRUD and validation. No HTTP here — index.js owns status codes.
//
// Profiles are personas, not accounts: there is no password, no session, and no security
// boundary between them. Anyone reaching the API can select any profile. The loopback bind
// in index.js is what keeps that safe.
const { isSector } = require('./sector_profiles');
const { isDomain } = require('./domains');
const { SEVERITIES } = require('./cvss');

// item_cpes.vendor/product are lowercase CPE fields: letters, digits, dot, underscore, hyphen.
// Anything else cannot match a row, so storing it would be storing a value that never matches.
const SLUG_RE = /^[a-z0-9][a-z0-9._-]*$/;

function slugList(input, label) {
  if (input == null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: `${label} must be an array` };
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return { ok: false, error: `${label} entries must be strings` };
    const v = raw.trim().toLowerCase();
    if (!SLUG_RE.test(v)) return { ok: false, error: `${label} entry is not a valid slug: ${raw}` };
    if (!out.includes(v)) out.push(v);
  }
  return { ok: true, value: out };
}

const EXPOSURES = ['internet', 'internal', 'unknown'];

// Assets are the precision path: only these can earn act_now, because a vendor-level claim
// ("we use Microsoft software") is not evidence of exposure to a specific flaw.
//
// vendor is optional. The client has none to send — CpeFacet is { value, refs } and the
// survey's product step is a bare string[] — so writeAssets resolves it from item_cpes, the
// same way the schema migration does. When a vendor IS supplied it still has to be a slug.
function assetList(input) {
  if (input == null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'assets must be an array' };
  const out = [];
  const seen = new Set();
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return { ok: false, error: 'asset entries must be objects' };
    const vendor = raw.vendor == null || raw.vendor === ''
      ? null
      : String(raw.vendor).trim().toLowerCase();
    const product = typeof raw.product === 'string' ? raw.product.trim().toLowerCase() : '';
    if (vendor !== null && !SLUG_RE.test(vendor)) {
      return { ok: false, error: `asset vendor is not a valid slug: ${raw.vendor}` };
    }
    if (!SLUG_RE.test(product)) {
      return { ok: false, error: `asset product is not a valid slug: ${raw.product}` };
    }
    // An unanswered exposure is 'unknown', which is honest. It is never assumed to be
    // 'internal': that would silently demote an actively-exploited flaw on the strength of a
    // survey question the user skipped.
    const exposure = raw.exposure == null ? 'unknown' : raw.exposure;
    if (!EXPOSURES.includes(exposure)) return { ok: false, error: `unknown exposure: ${raw.exposure}` };
    const key = `${vendor}/${product}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ vendor, product, exposure });
  }
  return { ok: true, value: out };
}

function validateProfile(input = {}) {
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name) return { ok: false, error: 'name is required' };

  if (!isSector(input.sector)) return { ok: false, error: `unknown sector: ${input.sector}` };

  const vendors = slugList(input.vendors, 'vendor');
  if (!vendors.ok) return vendors;
  const products = slugList(input.products, 'product');
  if (!products.ok) return products;

  const domains = input.threatDomains == null ? [] : input.threatDomains;
  if (!Array.isArray(domains)) return { ok: false, error: 'threatDomains must be an array' };
  const threatDomains = [];
  for (const d of domains) {
    if (!isDomain(d)) return { ok: false, error: `unknown threat domain: ${d}` };
    if (!threatDomains.includes(d)) threatDomains.push(d);
  }

  const severityFloor = input.severityFloor == null ? 'medium' : input.severityFloor;
  if (!SEVERITIES.includes(severityFloor)) {
    return { ok: false, error: `unknown severity floor: ${severityFloor}` };
  }

  const region = typeof input.region === 'string' && input.region.trim() ? input.region.trim() : null;

  const assets = assetList(input.assets);
  if (!assets.ok) return assets;

  return {
    ok: true,
    value: { name, sector: input.sector, vendors: vendors.value, products: products.value, threatDomains, region, severityFloor, assets: assets.value },
  };
}

// Assets travel with the profile everywhere, because scoreRelevance needs them on the same
// object it already receives. An assetless profile reads back [], never undefined — callers
// should not have to tell "no assets" apart from "not loaded".
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
// schema migration uses: one row per distinct vendor carrying that product slug, and a slug
// matching nothing is dropped rather than stored as a value that can never match an item.
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
      // Casts are required: in an INSERT...SELECT Postgres cannot infer a bare parameter's
      // type from the target column.
      `INSERT INTO profile_assets (profile_id, vendor, product, exposure)
       SELECT DISTINCT $1::int, c.vendor, c.product, $3::text FROM item_cpes c WHERE c.product = $2
       ON CONFLICT (profile_id, vendor, product) DO NOTHING`,
      [profileId, a.product, a.exposure]);
  }
}

async function createProfile(store, input) {
  const v = validateProfile(input);
  if (!v.ok) throw new Error(v.error);
  const p = v.value;
  try {
    // One transaction: a profile whose assets failed to write would score as if the user had
    // never entered them, which is worse than the write failing outright.
    const row = await store.tx(async (t) => {
      const created = await t.get(
        `INSERT INTO profiles (name, sector, vendors, products, threat_domains, region, severity_floor)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [p.name, p.sector, p.vendors, p.products, p.threatDomains, p.region, p.severityFloor]);
      await writeAssets(t, created.id, p.assets);
      return created;
    });
    return (await attachAssets(store, [row]))[0];
  } catch (e) {
    // 23505 is unique_violation. Surfacing the raw Postgres text would leak the constraint name.
    if (e && e.code === '23505') throw new Error('name already exists');
    throw e;
  }
}

async function listProfiles(store) {
  return attachAssets(store, await store.all('SELECT * FROM profiles ORDER BY id DESC'));
}

async function getProfile(store, id) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  const row = await store.get('SELECT * FROM profiles WHERE id = $1', [n]);
  if (!row) return null;
  return (await attachAssets(store, [row]))[0];
}

// Every save bumps profile_version — it is Phase 2's cache key for entity relevance, so an
// edit must invalidate cached verdicts even when the content happens to be unchanged.
async function updateProfile(store, id, input) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  const v = validateProfile(input);
  if (!v.ok) throw new Error(v.error);
  const p = v.value;
  try {
    const row = await store.tx(async (t) => {
      const updated = await t.get(
        `UPDATE profiles SET name=$1, sector=$2, vendors=$3, products=$4, threat_domains=$5,
                region=$6, severity_floor=$7, profile_version=profile_version+1, updated_at=now()
           WHERE id=$8 RETURNING *`,
        [p.name, p.sector, p.vendors, p.products, p.threatDomains, p.region, p.severityFloor, n]);
      if (!updated) return null;
      await writeAssets(t, updated.id, p.assets);
      return updated;
    });
    if (!row) return null;
    return (await attachAssets(store, [row]))[0];
  } catch (e) {
    if (e && e.code === '23505') throw new Error('name already exists');
    throw e;
  }
}

async function deleteProfile(store, id) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return false;
  const row = await store.get('DELETE FROM profiles WHERE id = $1 RETURNING id', [n]);
  return !!row;
}

module.exports = { validateProfile, createProfile, listProfiles, getProfile, updateProfile, deleteProfile };
