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
