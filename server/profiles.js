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

  return {
    ok: true,
    value: { name, sector: input.sector, vendors: vendors.value, products: products.value, threatDomains, region, severityFloor },
  };
}

async function createProfile(store, input) {
  const v = validateProfile(input);
  if (!v.ok) throw new Error(v.error);
  const p = v.value;
  try {
    return await store.get(
      `INSERT INTO profiles (name, sector, vendors, products, threat_domains, region, severity_floor)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [p.name, p.sector, p.vendors, p.products, p.threatDomains, p.region, p.severityFloor]);
  } catch (e) {
    // 23505 is unique_violation. Surfacing the raw Postgres text would leak the constraint name.
    if (e && e.code === '23505') throw new Error('name already exists');
    throw e;
  }
}

async function listProfiles(store) {
  return store.all('SELECT * FROM profiles ORDER BY id DESC');
}

async function getProfile(store, id) {
  const n = Number(id);
  if (!Number.isInteger(n) || n <= 0) return null;
  return (await store.get('SELECT * FROM profiles WHERE id = $1', [n])) || null;
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
    return (await store.get(
      `UPDATE profiles SET name=$1, sector=$2, vendors=$3, products=$4, threat_domains=$5,
              region=$6, severity_floor=$7, profile_version=profile_version+1, updated_at=now()
         WHERE id=$8 RETURNING *`,
      [p.name, p.sector, p.vendors, p.products, p.threatDomains, p.region, p.severityFloor, n])) || null;
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
