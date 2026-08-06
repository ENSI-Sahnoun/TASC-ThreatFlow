const test = require('node:test');
const assert = require('node:assert');
const { fetchStixBundle, objectsByType, isRevoked } = require('./attack_stix');

function stubRequest(body, status = 200) {
  return async () => ({ status, headers: {}, body: JSON.stringify(body) });
}

test('fetchStixBundle returns the parsed bundle on a 200', async () => {
  const bundle = await fetchStixBundle(stubRequest({ objects: [{ type: 'intrusion-set', id: 'x' }] }));
  assert.deepStrictEqual(bundle.objects, [{ type: 'intrusion-set', id: 'x' }]);
});

test('fetchStixBundle throws on a non-2xx status', async () => {
  await assert.rejects(fetchStixBundle(stubRequest({}, 500)), /HTTP 500/);
});

test('fetchStixBundle throws on unparseable JSON', async () => {
  await assert.rejects(
    fetchStixBundle(async () => ({ status: 200, headers: {}, body: 'not json' })),
    /not valid JSON/);
});

test('fetchStixBundle throws when the bundle has no objects[]', async () => {
  await assert.rejects(fetchStixBundle(stubRequest({ spec_version: '2.1' })), /no objects/);
});

test('isRevoked is true for revoked or deprecated objects', () => {
  assert.strictEqual(isRevoked({ revoked: true }), true);
  assert.strictEqual(isRevoked({ x_mitre_deprecated: true }), true);
  assert.strictEqual(isRevoked({}), false);
});

test('objectsByType filters by type and excludes revoked when asked', () => {
  const bundle = {
    objects: [
      { type: 'intrusion-set', id: 'a' },
      { type: 'intrusion-set', id: 'b', revoked: true },
      { type: 'malware', id: 'c' },
    ],
  };
  assert.deepStrictEqual(objectsByType(bundle, 'intrusion-set').map((o) => o.id), ['a', 'b']);
  assert.deepStrictEqual(
    objectsByType(bundle, 'intrusion-set', { excludeRevoked: true }).map((o) => o.id), ['a']);
});
