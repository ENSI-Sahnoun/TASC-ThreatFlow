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
  assert.match(base({ vector: LOCAL, exposure: 'internet' }).reach.text,
    /already has access to that machine/);
});

test('AV:A is the local network', () => {
  const v = 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  assert.match(base({ vector: v }).reach.text, /on the same network/);
});

test('AV:P requires being physically present', () => {
  const v = 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  assert.match(base({ vector: v }).reach.text, /standing at the machine/);
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

test('UI:N adds no click clause', () => {
  assert.ok(!/clicks or opens/.test(base().reach.text));
});

test('reach records the metrics it came from', () => {
  assert.strictEqual(base({ exposure: 'internet' }).reach.from,
    'AV:N/PR:N/UI:N + exposure=internet');
});

// --- impact: C/I/A ---

test('C:H I:H A:H reads as read, change and shut down', () => {
  assert.strictEqual(base().impact.text, 'read, change and shut down');
});

test('a single high metric needs no list punctuation', () => {
  const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
  assert.strictEqual(base({ vector: v }).impact.text, 'read');
});

test('two high metrics join with and', () => {
  const v = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H';
  assert.strictEqual(base({ vector: v }).impact.text, 'read and shut down');
});

test('a low metric is rendered as partly', () => {
  assert.strictEqual(base({ vector: LOCAL }).impact.text, 'partly read');
});

test('all impact metrics None yields a null slot, not "no impact"', () => {
  assert.strictEqual(base({ vector: NO_IMPACT }).impact, null);
});

test('impact records the metrics it came from', () => {
  assert.strictEqual(base().impact.from, 'C:H/I:H/A:H');
});

// --- role ---

test('a mapped product yields its role', () => {
  assert.strictEqual(base().role.text, 'your VPN and firewall');
  assert.strictEqual(base().role.from, 'asset_roles: fortinet/fortios');
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

test('KEV with no due date still reports the urgency', () => {
  const u = base({ kevListed: true }).urgency;
  assert.match(u.text, /already used in real attacks/);
  assert.strictEqual(u.due, null);
});

test('EPSS at the threshold is urgent, with no due date', () => {
  const u = base({ epssScore: EPSS_URGENT_THRESHOLD }).urgency;
  assert.match(u.text, /likely to be attacked soon/);
  assert.strictEqual(u.due, null);
});

test('EPSS below the threshold yields a null slot rather than filler', () => {
  assert.strictEqual(base({ epssScore: 0.4 }).urgency, null);
});

test('no urgency signal at all yields a null slot', () => {
  assert.strictEqual(base().urgency, null);
});

// --- missing data ---

test('no vector yields null reach and impact but keeps role and urgency', () => {
  const c = base({ vector: null, kevListed: true, kevDueDate: '2026-08-17' });
  assert.strictEqual(c.reach, null);
  assert.strictEqual(c.impact, null);
  assert.strictEqual(c.role.text, 'your VPN and firewall');
  assert.strictEqual(c.urgency.due, '2026-08-17');
});

// CVSS 4.0 keeps AV, PR and UI with identical names and meanings, and renames the impact
// metrics to VC/VI/VA. So reach is genuinely derivable from a v4 vector and impact is not —
// a half-populated panel that states the gap, which is the honest outcome.
//
// In practice this path is unreachable from the database: backfill-cvss-vector.js stores only
// v3.0/v3.1, so a v4-only item has vector = null and yields four null slots. The behaviour is
// pinned here anyway so a future decision to store v4 does not silently change the output.
test('a v4 vector yields a correct reach and no impact claim', () => {
  const c = base({ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H', exposure: 'internet' });
  assert.match(c.reach.text, /anyone on the internet, with no password/);
  assert.strictEqual(c.impact, null);
});

test('a non-CVE item with no asset yields four null slots', () => {
  const c = buildConsequence({
    vector: null, exposure: 'unknown', vendor: null, product: null,
    kevListed: false, kevDueDate: null, epssScore: null });
  assert.deepStrictEqual(c, { reach: null, impact: null, role: null, urgency: null });
});

test('buildConsequence called with no arguments does not throw', () => {
  assert.deepStrictEqual(buildConsequence(),
    { reach: null, impact: null, role: null, urgency: null });
});
