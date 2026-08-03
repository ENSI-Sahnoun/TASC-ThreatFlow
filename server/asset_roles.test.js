const test = require('node:test');
const assert = require('node:assert');
const { roleFor, RULES } = require('./asset_roles');

const SLUG_RE = /^[a-z0-9][a-z0-9._-]*$/;

test('every rule names a vendor that is a valid CPE slug', () => {
  for (const r of RULES) assert.ok(SLUG_RE.test(r.vendor), `not a slug: ${r.vendor}`);
});

test('every rule carries a role and a measured reference count', () => {
  for (const r of RULES) {
    assert.ok(typeof r.role === 'string' && r.role.length > 3, `role too short: ${r.vendor}`);
    assert.ok(!r.role.endsWith('.'), `role is a fragment, not a sentence: ${r.role}`);
    assert.ok(Number.isInteger(r.refs) && r.refs > 0, `unmeasured rule: ${r.vendor}/${r.role}`);
  }
});

// Order is load-bearing: windows_server_* must be tested before the general windows_* rule,
// or every server would be described as a staff desktop.
test('a Windows server is a server, not a staff desktop', () => {
  assert.strictEqual(roleFor('microsoft', 'windows_server_2022'), 'your Windows servers');
  assert.strictEqual(roleFor('microsoft', 'windows_server_2025'), 'your Windows servers');
});

test('a Windows client is the machines staff use', () => {
  assert.strictEqual(roleFor('microsoft', 'windows_11_25h2'), 'the computers your staff use');
  assert.strictEqual(roleFor('microsoft', 'windows_10_22h2'), 'the computers your staff use');
  assert.strictEqual(roleFor('microsoft', 'windows'), 'the computers your staff use');
});

test('version-suffixed products resolve through their prefix', () => {
  assert.strictEqual(roleFor('microsoft', 'office_2021'), 'the documents your staff open');
  assert.strictEqual(roleFor('microsoft', 'office_2024'), 'the documents your staff open');
  assert.strictEqual(
    roleFor('microsoft', 'exchange_server_subscription_edition'), 'your company email');
});

test('mail, database, browser and network roles resolve', () => {
  assert.strictEqual(roleFor('microsoft', 'exchange_server'), 'your company email');
  assert.strictEqual(roleFor('oracle', 'mysql_server'), 'a database your systems rely on');
  assert.strictEqual(roleFor('google', 'chrome'), 'the browser your staff use');
  assert.strictEqual(roleFor('mozilla', 'firefox'), 'the browser your staff use');
  assert.strictEqual(roleFor('fortinet', 'fortios'), 'your VPN and firewall');
});

test('Linux distributions are servers', () => {
  assert.strictEqual(roleFor('linux', 'linux_kernel'), 'your servers');
  assert.strictEqual(roleFor('debian', 'debian_linux'), 'your servers');
  assert.strictEqual(roleFor('redhat', 'enterprise_linux'), 'your servers');
});

test('Apple desktop and mobile are told apart', () => {
  assert.strictEqual(roleFor('apple', 'macos'), 'the Macs your staff use');
  assert.strictEqual(roleFor('apple', 'iphone_os'), 'the phones and tablets your staff use');
  assert.strictEqual(roleFor('apple', 'ipados'), 'the phones and tablets your staff use');
});

// A vendor rule must never leak across vendors — 'chrome' from someone other than Google is
// not the browser we mean.
test('rules are scoped to their vendor', () => {
  assert.strictEqual(roleFor('acme', 'chrome'), null);
  assert.strictEqual(roleFor('acme', 'windows_11_25h2'), null);
});

test('an unmapped product yields null rather than an invented role', () => {
  assert.strictEqual(roleFor('openclaw', 'openclaw'), null);
  assert.strictEqual(roleFor('acme', 'nothing'), null);
});

test('roleFor tolerates missing input rather than throwing', () => {
  assert.strictEqual(roleFor(null, null), null);
  assert.strictEqual(roleFor('fortinet', undefined), null);
  assert.strictEqual(roleFor(undefined, 'fortios'), null);
});
