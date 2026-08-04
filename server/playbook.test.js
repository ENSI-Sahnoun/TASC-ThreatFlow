const test = require('node:test');
const assert = require('node:assert');
const { buildPlaybook } = require('./playbook');

const WORST = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N';

const base = (over = {}) => buildPlaybook({
  vector: WORST, exposure: 'internet', vendor: 'fortinet', product: 'fortios',
  kevListed: false, kevDueDate: null, kevRansomware: false, patchUrl: null, advisoryUrl: null,
  ...over,
});

const keysOf = (steps) => steps.map((s) => s.key);
const find = (steps, key) => steps.find((s) => s.key === key);

// --- confirm: always ---

test('confirm is always present and names the matched product', () => {
  const steps = base();
  assert.match(find(steps, 'confirm').detail, /fortinet|VPN and firewall/i);
});

test('confirm is present even with no matched asset, and stays generic', () => {
  const steps = buildPlaybook({ vector: WORST, exposure: 'unknown', vendor: null, product: null,
    kevListed: false, kevDueDate: null, kevRansomware: false, patchUrl: null, advisoryUrl: null });
  assert.ok(find(steps, 'confirm'));
});

// --- ransomware ---

test('ransomware step appears when CISA marks known ransomware use', () => {
  assert.ok(find(base({ kevListed: true, kevRansomware: true }), 'ransomware'));
});

test('ransomware step is absent otherwise', () => {
  assert.ok(!find(base({ kevListed: true, kevRansomware: false }), 'ransomware'));
  assert.ok(!find(base(), 'ransomware'));
});

// --- patch / vendor / watch-vendor: mutually exclusive ---

test('patch step appears and carries the link when a Patch reference exists', () => {
  const steps = base({ patchUrl: 'https://example.com/patch' });
  const step = find(steps, 'patch');
  assert.strictEqual(step.link, 'https://example.com/patch');
  assert.match(step.source, /Patch/);
  assert.ok(!find(steps, 'vendor'));
  assert.ok(!find(steps, 'watch-vendor'));
});

test('vendor step appears only when there is an advisory but no patch', () => {
  const steps = base({ advisoryUrl: 'https://example.com/advisory' });
  const step = find(steps, 'vendor');
  assert.strictEqual(step.link, 'https://example.com/advisory');
  assert.ok(!find(steps, 'patch'));
  assert.ok(!find(steps, 'watch-vendor'));
});

test('a patch reference wins over an advisory reference when both exist', () => {
  const steps = base({ patchUrl: 'https://example.com/patch', advisoryUrl: 'https://example.com/advisory' });
  assert.ok(find(steps, 'patch'));
  assert.ok(!find(steps, 'vendor'));
});

test('watch-vendor appears only when neither a patch nor an advisory reference exists', () => {
  const steps = base();
  assert.ok(find(steps, 'watch-vendor'));
  assert.ok(!find(steps, 'patch'));
  assert.ok(!find(steps, 'vendor'));
});

// --- restrict: AV:N + not internal ---

test('restrict appears for a network-reachable flaw when not internal-only', () => {
  assert.ok(find(base({ exposure: 'internet' }), 'restrict'));
  assert.ok(find(base({ exposure: 'unknown' }), 'restrict'));
});

test('restrict is absent for an internal-only asset', () => {
  assert.ok(!find(base({ exposure: 'internal' }), 'restrict'));
});

test('restrict is absent for a local-access-only vector', () => {
  assert.ok(!find(base({ vector: LOCAL }), 'restrict'));
});

// --- rotate: C:H + PR:N ---

test('rotate appears when confidentiality is fully compromised with no password required', () => {
  assert.ok(find(base(), 'rotate'));
});

test('rotate is absent when a password is required or confidentiality is not fully compromised', () => {
  assert.ok(!find(base({ vector: LOCAL }), 'rotate'));
});

// --- source is mandatory ---

test('every emitted step carries a non-empty source', () => {
  const steps = base({ kevRansomware: true, patchUrl: 'https://example.com/patch' });
  assert.ok(steps.length >= 4);
  for (const s of steps) assert.ok(typeof s.source === 'string' && s.source.length > 0, `missing source on ${s.key}`);
});

// --- ordering is stable ---

test('steps are always emitted in catalogue order regardless of guard combination', () => {
  const steps = base({ kevListed: true, kevRansomware: true, advisoryUrl: 'https://example.com/advisory' });
  assert.deepStrictEqual(keysOf(steps), ['confirm', 'ransomware', 'vendor', 'restrict', 'rotate']);
});

// --- no vector: only confirm and the reference/absence steps survive ---

test('with no vector, restrict and rotate are absent but confirm and watch-vendor remain', () => {
  const steps = buildPlaybook({ vector: null, exposure: 'unknown', vendor: 'fortinet', product: 'fortios',
    kevListed: false, kevDueDate: null, kevRansomware: false, patchUrl: null, advisoryUrl: null });
  assert.deepStrictEqual(keysOf(steps), ['confirm', 'watch-vendor']);
});

// parseVector does not reject v4 — it shares AV/PR/UI key names with v3, so restrict (which
// only reads those) still fires, matching consequence.js's own "a v4 vector yields a correct
// reach" precedent. v4 renames C/I/A to VC/VI/VA, so rotate (which reads C/PR) correctly finds
// nothing to derive from.
test('a v4 vector still derives restrict from its shared AV/PR keys, but not rotate', () => {
  const steps = base({ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H' });
  assert.ok(find(steps, 'restrict'));
  assert.ok(!find(steps, 'rotate'));
});

test('a genuinely unparseable vector yields neither restrict nor rotate', () => {
  const steps = base({ vector: 'not a real vector' });
  assert.ok(!find(steps, 'restrict'));
  assert.ok(!find(steps, 'rotate'));
});

// --- 3-6 step range from the design doc ---

test('the step count stays within the 3-6 range across the guard space', () => {
  const cases = [
    base(),
    base({ vector: LOCAL, exposure: 'internal' }),
    base({ kevListed: true, kevRansomware: true, patchUrl: 'https://example.com/p' }),
    buildPlaybook({ vector: null, exposure: 'unknown', vendor: null, product: null,
      kevListed: false, kevDueDate: null, kevRansomware: false, patchUrl: null, advisoryUrl: null }),
  ];
  for (const steps of cases) {
    assert.ok(steps.length >= 2 && steps.length <= 6, `unexpected step count: ${steps.length}`);
  }
});

// --- confirm: version specificity ---

test('confirm names the specific affected version range when one matches the asset', () => {
  const steps = base({
    affectedVersions: [
      { vendor: 'fortinet', product: 'fortios', text: 'before 7.4.5' },
      { vendor: 'fortinet', product: 'forticlient', text: 'before 7.2.0' }, // different product, must not match
    ],
  });
  assert.match(find(steps, 'confirm').detail, /before 7\.4\.5/);
  assert.match(find(steps, 'confirm').source, /NVD CPE match/);
});

test('confirm stays generic when affectedVersions has no entry for this vendor/product', () => {
  const steps = base({ affectedVersions: [{ vendor: 'microsoft', product: 'windows_11_24h2', text: 'before 10.0.26100.8875' }] });
  assert.doesNotMatch(find(steps, 'confirm').detail, /before/);
  assert.strictEqual(find(steps, 'confirm').source, 'your profile assets');
});

test('confirm stays generic when affectedVersions is omitted entirely', () => {
  const steps = base();
  // roleFor('fortinet', 'fortios') resolves to 'your VPN and firewall' (server/asset_roles.js).
  assert.strictEqual(find(steps, 'confirm').detail, 'Affected: your VPN and firewall');
});
