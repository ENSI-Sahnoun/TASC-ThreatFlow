const test = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const {
  validateProfile, createProfile, listProfiles, getProfile, updateProfile, deleteProfile,
} = require('./profiles');

const VALID = {
  name: 'Acme Bank',
  sector: 'finance',
  vendors: ['microsoft', 'oracle'],
  products: ['windows_10'],
  threatDomains: ['financial', 'ransomware'],
  region: 'EU',
  severityFloor: 'medium',
};

test('validateProfile accepts a well-formed profile', () => {
  const r = validateProfile(VALID);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.value.name, 'Acme Bank');
  assert.deepStrictEqual(r.value.vendors, ['microsoft', 'oracle']);
});

test('validateProfile lowercases vendor and product slugs', () => {
  const r = validateProfile({ ...VALID, vendors: ['Microsoft', 'ORACLE'], products: ['Windows_10'] });
  assert.deepStrictEqual(r.value.vendors, ['microsoft', 'oracle']);
  assert.deepStrictEqual(r.value.products, ['windows_10']);
});

test('validateProfile de-duplicates slugs', () => {
  const r = validateProfile({ ...VALID, vendors: ['microsoft', 'Microsoft', 'oracle'] });
  assert.deepStrictEqual(r.value.vendors, ['microsoft', 'oracle']);
});

test('validateProfile rejects an unknown sector', () => {
  const r = validateProfile({ ...VALID, sector: 'space-mining' });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /sector/);
});

// A domain slug that does not exist would silently match nothing in Phase 2.
test('validateProfile rejects an unknown threat domain', () => {
  const r = validateProfile({ ...VALID, threatDomains: ['ransomware', 'not-a-domain'] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /domain/);
});

test('validateProfile rejects an invalid severity floor', () => {
  const r = validateProfile({ ...VALID, severityFloor: 'extremely-bad' });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /severity/);
});

test('validateProfile rejects a missing or blank name', () => {
  assert.strictEqual(validateProfile({ ...VALID, name: '' }).ok, false);
  assert.strictEqual(validateProfile({ ...VALID, name: '   ' }).ok, false);
  assert.strictEqual(validateProfile({ ...VALID, name: undefined }).ok, false);
});

test('validateProfile rejects vendor entries that are not slug-shaped', () => {
  const r = validateProfile({ ...VALID, vendors: ['micro soft'] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /vendor/);
});

test('validateProfile defaults optional fields rather than failing', () => {
  const r = validateProfile({ name: 'Bare', sector: 'other' });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.value.vendors, []);
  assert.deepStrictEqual(r.value.products, []);
  assert.deepStrictEqual(r.value.threatDomains, []);
  assert.strictEqual(r.value.region, null);
  assert.strictEqual(r.value.severityFloor, 'medium');
});

test('createProfile persists and returns the row with version 1', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await createProfile(store, VALID);
    assert.ok(p.id > 0);
    assert.strictEqual(p.profile_version, 1);
    assert.strictEqual(p.sector, 'finance');
    assert.deepStrictEqual(p.vendors, ['microsoft', 'oracle']);
    assert.deepStrictEqual(p.threat_domains, ['financial', 'ransomware']);
  } finally { await cleanup(); }
});

test('createProfile rejects a duplicate name', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await createProfile(store, VALID);
    await assert.rejects(() => createProfile(store, VALID), /name already exists/);
  } finally { await cleanup(); }
});

test('listProfiles returns all profiles newest first', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await createProfile(store, VALID);
    await createProfile(store, { ...VALID, name: 'Second' });
    const rows = await listProfiles(store);
    assert.strictEqual(rows.length, 2);
    assert.deepStrictEqual(rows.map((r) => r.name), ['Second', 'Acme Bank']);
  } finally { await cleanup(); }
});

test('getProfile returns null for an unknown or malformed id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    assert.strictEqual(await getProfile(store, 999), null);
    assert.strictEqual(await getProfile(store, 'abc'), null);
    assert.strictEqual(await getProfile(store, -1), null);
  } finally { await cleanup(); }
});

// profile_version is Phase 2's cache key: a saved edit must invalidate cached verdicts.
test('updateProfile bumps profile_version on every save', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await createProfile(store, VALID);
    const v2 = await updateProfile(store, p.id, { ...VALID, vendors: ['microsoft'] });
    assert.strictEqual(v2.profile_version, 2);
    const v3 = await updateProfile(store, p.id, { ...VALID, vendors: ['microsoft'] });
    assert.strictEqual(v3.profile_version, 3, 'version bumps even when the content is identical');
  } finally { await cleanup(); }
});

test('updateProfile returns null for an unknown id', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    assert.strictEqual(await updateProfile(store, 999, VALID), null);
  } finally { await cleanup(); }
});

test('deleteProfile removes the row and reports whether it existed', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const p = await createProfile(store, VALID);
    assert.strictEqual(await deleteProfile(store, p.id), true);
    assert.strictEqual(await getProfile(store, p.id), null);
    assert.strictEqual(await deleteProfile(store, p.id), false);
  } finally { await cleanup(); }
});

// --- Assets (Spec A) ---

const ASSET = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };

async function seedCpe(store, vendor, product) {
  const s = await store.get(
    "INSERT INTO sources (name, url, fetch_kind) VALUES ('s','http://x','rss') RETURNING id");
  const i = await store.get(
    "INSERT INTO items (source_id, external_id, title, category) VALUES ($1,$2,'t','cve') RETURNING id",
    [s.id, `e-${vendor}-${product}`]);
  await store.run(
    "INSERT INTO item_cpes (item_id, part, vendor, product) VALUES ($1,'a',$2,$3)",
    [i.id, vendor, product]);
}

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
  assert.deepStrictEqual(r.value.assets[0],
    { vendor: 'fortinet', product: 'fortios', exposure: 'unknown', version: null, versionState: 'unset' });
});

test('validateProfile rejects an unknown exposure', () => {
  const r = validateProfile({ ...VALID, assets: [{ ...ASSET, exposure: 'sometimes' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /exposure/);
});

test('validateProfile rejects an asset with a non-slug product', () => {
  assert.strictEqual(validateProfile({ ...VALID, assets: [{ vendor: 'fortinet', product: 'Forti OS!' }] }).ok, false);
});

test('validateProfile rejects a non-array assets value', () => {
  assert.strictEqual(validateProfile({ ...VALID, assets: 'fortios' }).ok, false);
});

test('validateProfile deduplicates assets by vendor and product', () => {
  const r = validateProfile({ ...VALID, assets: [ASSET, { ...ASSET, exposure: 'internal' }] });
  assert.strictEqual(r.value.assets.length, 1);
});

// The client has no vendor to send: CpeFacet is { value, refs } and the survey's products
// signal is a bare string[]. The server resolves it from item_cpes instead.
test('validateProfile accepts an asset with no vendor', () => {
  const r = validateProfile({ ...VALID, assets: [{ product: 'fortios', exposure: 'internet' }] });
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.value.assets[0],
    { vendor: null, product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' });
});

// --- Assets: version / versionState (Spec A, foundation) ---

test('validateProfile defaults version to null and versionState to unset', () => {
  const r = validateProfile({ ...VALID, assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet' }] });
  assert.strictEqual(r.value.assets[0].version, null);
  assert.strictEqual(r.value.assets[0].versionState, 'unset');
});

test('validateProfile accepts a well-formed version and versionState', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.5', versionState: 'known' }] });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.value.assets[0].version, '7.4.5');
  assert.strictEqual(r.value.assets[0].versionState, 'known');
});

test('validateProfile trims a version string', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: ' 7.4.5 ', versionState: 'known' }] });
  assert.strictEqual(r.value.assets[0].version, '7.4.5');
});

test('validateProfile rejects a version containing whitespace', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: '7.4 5', versionState: 'known' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /version/);
});

test('validateProfile rejects a version over 64 characters', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', version: 'x'.repeat(65), versionState: 'known' }] });
  assert.strictEqual(r.ok, false);
});

test('validateProfile rejects an unknown versionState', () => {
  const r = validateProfile({ ...VALID,
    assets: [{ vendor: 'fortinet', product: 'fortios', versionState: 'maybe' }] });
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /version state/);
});

test('createProfile persists version and versionState through writeAssets/attachAssets', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID,
      assets: [{ vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.5', versionState: 'known' }] });
    const got = await getProfile(store, created.id);
    assert.strictEqual(got.assets[0].version, '7.4.5');
    assert.strictEqual(got.assets[0].versionState, 'known');
  } finally { await cleanup(); }
});

test('versionState "unknown" (asked, declined) round-trips with a null version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID,
      assets: [{ vendor: 'fortinet', product: 'fortios', versionState: 'unknown' }] });
    const got = await getProfile(store, created.id);
    assert.strictEqual(got.assets[0].version, null);
    assert.strictEqual(got.assets[0].versionState, 'unknown');
  } finally { await cleanup(); }
});

test('createProfile persists assets and getProfile returns them', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID, assets: [ASSET] });
    assert.deepStrictEqual((await getProfile(store, created.id)).assets, [ASSET]);
  } finally { await cleanup(); }
});

test('createProfile resolves an omitted vendor from item_cpes', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpe(store, 'fortinet', 'fortios');
    const created = await createProfile(store, {
      ...VALID, assets: [{ product: 'fortios', exposure: 'internet' }] });
    assert.deepStrictEqual((await getProfile(store, created.id)).assets, [ASSET]);
  } finally { await cleanup(); }
});

test('a product under several vendors resolves to one asset per vendor', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await seedCpe(store, 'acme', 'router_os');
    await seedCpe(store, 'globex', 'router_os');
    const created = await createProfile(store, {
      ...VALID, assets: [{ product: 'router_os', exposure: 'internal' }] });
    const got = await getProfile(store, created.id);
    assert.deepStrictEqual(got.assets.map((a) => a.vendor), ['acme', 'globex']);
  } finally { await cleanup(); }
});

test('an asset whose product matches no item_cpes row is dropped, not stored', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, {
      ...VALID, assets: [{ product: 'ghost', exposure: 'internet' }] });
    assert.deepStrictEqual((await getProfile(store, created.id)).assets, []);
  } finally { await cleanup(); }
});

test('updateProfile replaces the asset set and bumps profile_version', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID, assets: [ASSET] });
    const updated = await updateProfile(store, created.id, {
      ...VALID, assets: [{ vendor: 'microsoft', product: 'windows', exposure: 'internal' }] });
    assert.strictEqual(updated.profile_version, created.profile_version + 1);
    assert.deepStrictEqual((await getProfile(store, created.id)).assets,
      [{ vendor: 'microsoft', product: 'windows', exposure: 'internal', version: null, versionState: 'unset' }]);
  } finally { await cleanup(); }
});

test('updateProfile with no assets clears them', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, { ...VALID, assets: [ASSET] });
    await updateProfile(store, created.id, { ...VALID });
    assert.deepStrictEqual((await getProfile(store, created.id)).assets, []);
  } finally { await cleanup(); }
});

test('listProfiles attaches assets to every row', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    await createProfile(store, { ...VALID, assets: [ASSET] });
    await createProfile(store, { ...VALID, name: 'Second' });
    const rows = await listProfiles(store);
    const byName = Object.fromEntries(rows.map((r) => [r.name, r.assets]));
    assert.deepStrictEqual(byName['Acme Bank'], [ASSET]);
    assert.deepStrictEqual(byName.Second, []);
  } finally { await cleanup(); }
});

test('a profile saved without assets reads back an empty array, never undefined', async () => {
  const { store, cleanup } = await makeTempDb();
  try {
    const created = await createProfile(store, VALID);
    assert.deepStrictEqual((await getProfile(store, created.id)).assets, []);
  } finally { await cleanup(); }
});
