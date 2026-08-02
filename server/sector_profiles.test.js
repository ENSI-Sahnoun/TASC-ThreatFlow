const test = require('node:test');
const assert = require('node:assert');
const { SECTORS, recommendationFor, isSector } = require('./sector_profiles');
const { DOMAINS } = require('./domains');
const { SEVERITIES } = require('./cvss');

test('SECTORS lists ten sectors with unique slugs and labels', () => {
  assert.strictEqual(SECTORS.length, 10);
  assert.strictEqual(new Set(SECTORS.map((s) => s.slug)).size, 10);
  for (const s of SECTORS) {
    assert.ok(s.slug && /^[a-z][a-z0-9-]*$/.test(s.slug), `bad slug: ${s.slug}`);
    assert.ok(s.label && s.label.length > 2, `bad label for ${s.slug}`);
  }
});

// Guards against drift: a recommendation naming a domain that no longer exists would
// silently recommend nothing.
test('every recommended domain exists in the DOMAINS vocabulary', () => {
  const valid = new Set(DOMAINS.map((d) => d.slug));
  for (const s of SECTORS) {
    for (const d of recommendationFor(s.slug).threatDomains) {
      assert.ok(valid.has(d), `sector ${s.slug} recommends unknown domain ${d}`);
    }
  }
});

test('every recommended severity floor is a real severity', () => {
  for (const s of SECTORS) {
    assert.ok(SEVERITIES.includes(recommendationFor(s.slug).severityFloor),
      `sector ${s.slug} has an invalid severityFloor`);
  }
});

// Vendors are matched against item_cpes.vendor, which is lowercase CPE slugs.
test('every recommended vendor is a lowercase CPE-shaped slug', () => {
  for (const s of SECTORS) {
    for (const v of recommendationFor(s.slug).vendors) {
      assert.ok(/^[a-z0-9][a-z0-9._-]*$/.test(v), `sector ${s.slug} has non-slug vendor ${v}`);
    }
  }
});

test('every sector recommends at least one domain', () => {
  for (const s of SECTORS) {
    assert.ok(recommendationFor(s.slug).threatDomains.length > 0, `sector ${s.slug} recommends no domains`);
  }
});

// ICS/OT vendor coverage in item_cpes is thin (siemens 22 refs, rockwellautomation 4), so
// this sector must carry the ics-ot domain or it would surface nothing.
test('manufacturing-industrial recommends the ics-ot domain', () => {
  assert.ok(recommendationFor('manufacturing-industrial').threatDomains.includes('ics-ot'));
});

test('recommendationFor returns null for an unknown sector, never a default', () => {
  assert.strictEqual(recommendationFor('not-a-sector'), null);
  assert.strictEqual(recommendationFor(''), null);
  assert.strictEqual(recommendationFor(null), null);
});

test('recommendationFor returns a fresh copy each call', () => {
  const a = recommendationFor('finance');
  a.vendors.push('injected');
  assert.ok(!recommendationFor('finance').vendors.includes('injected'));
});

test('isSector accepts known slugs and rejects everything else', () => {
  assert.strictEqual(isSector('finance'), true);
  assert.strictEqual(isSector('nope'), false);
  assert.strictEqual(isSector(undefined), false);
});
