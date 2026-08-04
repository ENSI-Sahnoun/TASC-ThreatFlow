const test = require('node:test');
const assert = require('node:assert');
const { fixTarget, remediationFor } = require('./remediation');
const { buildPlaybook } = require('./playbook');

// --- fixTarget: the ladder ---

test('fixTarget: endExcluding produces a version target', () => {
  assert.deepStrictEqual(fixTarget({ endExcluding: '7.4.5' }, {}), { kind: 'version', value: '7.4.5' });
});

test('fixTarget: falls back to patchUrl when there is no endExcluding', () => {
  assert.deepStrictEqual(
    fixTarget({ endIncluding: '2.4.1' }, { patchUrl: 'https://example.com/patch' }),
    { kind: 'patch', value: 'https://example.com/patch' });
});

test('fixTarget: a patch wins over an advisory when both exist', () => {
  assert.deepStrictEqual(
    fixTarget(null, { patchUrl: 'https://example.com/patch', advisoryUrl: 'https://example.com/advisory' }),
    { kind: 'patch', value: 'https://example.com/patch' });
});

test('fixTarget: falls back to advisoryUrl when there is no patch', () => {
  assert.deepStrictEqual(
    fixTarget(null, { advisoryUrl: 'https://example.com/advisory' }),
    { kind: 'advisory', value: 'https://example.com/advisory' });
});

test('fixTarget: none when nothing is available', () => {
  assert.deepStrictEqual(fixTarget(null, {}), { kind: 'none' });
  assert.deepStrictEqual(fixTarget(null, null), { kind: 'none' });
});

// The fabrication guard: neither endIncluding nor pinned may ever produce kind: 'version',
// because neither names a fixed version — asserted directly, not just implied by the ladder
// order above.
test('fixTarget: an endIncluding-only entry never produces kind version', () => {
  const r = fixTarget({ endIncluding: '2.4.1' }, {});
  assert.notStrictEqual(r.kind, 'version');
});

test('fixTarget: a pinned-only entry never produces kind version', () => {
  const r = fixTarget({ pinned: '4.2.1' }, {});
  assert.notStrictEqual(r.kind, 'version');
});

// --- remediationFor ---

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N';
const NO_BOUNDS = { startIncluding: null, startExcluding: null, endIncluding: null, endExcluding: null, pinned: null };

test('remediationFor: kind none still surfaces restrict/rotate mitigations when the vector supports them', () => {
  const steps = buildPlaybook({ vector: WORST, exposure: 'internet', vendor: 'fortinet', product: 'fortios' });
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };
  const r = remediationFor(asset, [], {}, steps);
  assert.strictEqual(r.fix.kind, 'none');
  assert.ok(r.mitigations.some((s) => s.key === 'restrict'));
  assert.ok(r.mitigations.some((s) => s.key === 'rotate'));
  assert.ok(r.mitigations.every((s) => s.key === 'restrict' || s.key === 'rotate'));
});

test('remediationFor: mitigations is empty when the vector does not support restrict or rotate', () => {
  const steps = buildPlaybook({ vector: LOCAL, exposure: 'internal', vendor: 'fortinet', product: 'fortios' });
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internal', version: null, versionState: 'unset' };
  const r = remediationFor(asset, [], {}, steps);
  assert.deepStrictEqual(r.mitigations, []);
});

test('remediationFor: a known version inside a bounded range reports affected and the fix version', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'affected');
  assert.strictEqual(r.installed, '7.4.0');
  assert.strictEqual(r.versionState, 'known');
  assert.strictEqual(r.fix.kind, 'version');
  assert.strictEqual(r.fix.value, '7.4.5');
});

test('remediationFor: an unset version reports unknown status even against a bounded entry', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: null, versionState: 'unset' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'unknown');
  assert.strictEqual(r.installed, null);
});

test('remediationFor: a version above a bounded range reports not_covered', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '8.0.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5', ...NO_BOUNDS, endExcluding: '7.4.5' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'not_covered');
});

test('remediationFor: no entry for this vendor/product reports unknown, not an absent field', () => {
  const asset = { vendor: 'fortinet', product: 'fortios', exposure: 'internet', version: '7.4.0', versionState: 'known' };
  const affectedVersions = [{ vendor: 'microsoft', product: 'windows_11_24h2', text: 'before X', ...NO_BOUNDS, endExcluding: 'X' }];
  const r = remediationFor(asset, affectedVersions, {}, []);
  assert.strictEqual(r.status, 'unknown');
  assert.strictEqual(r.entry, null);
});
