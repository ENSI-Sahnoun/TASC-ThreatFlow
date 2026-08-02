const test = require('node:test');
const assert = require('node:assert');
const abuseCh = require('./abuse_ch');

test('abuse_ch flattens object-of-arrays (ThreatFox shape)', async () => {
  const body = JSON.stringify({ '123': [{ ioc_value: 'evil.test', ioc_type: 'domain', malware_printable: 'ClearFake', first_seen: '2026-01-01', threat_type: 'payload_delivery' }] });
  const source = { category: 'Malware / C2', enrichHints: { iocField: 'ioc_value', iocTypeField: 'ioc_type', familyField: 'malware_printable' } };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body }) };
  const items = await abuseCh.fetch(source, ctx);
  assert.strictEqual(items.length, 1);
  assert.strictEqual(items[0].native.iocs[0].value, 'evil.test');
  assert.strictEqual(items[0].native.iocs[0].type, 'domain');
  assert.deepStrictEqual(items[0].native.malwareFamilies, ['ClearFake']);
});

test('abuse_ch composes a per-record summary from confidence/status/tags/reporter', async () => {
  const body = JSON.stringify({
    '123': [{
      ioc_value: '1.2.3.4:443', ioc_type: 'ip:port', malware_printable: 'Cobalt Strike',
      threat_type: 'botnet_cc', confidence_level: 100, tags: 'CobaltStrike,SomeAS',
      reporter: 'drb_ra', first_seen_utc: '2021-09-18 17:39:24', last_seen_utc: '2026-07-30 12:43:58',
    }],
  });
  const source = { category: 'Malware / C2', enrichHints: { iocField: 'ioc_value', iocTypeField: 'ioc_type', familyField: 'malware_printable' } };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body }) };
  const items = await abuseCh.fetch(source, ctx);
  assert.match(items[0].summary, /Botnet C2/);
  assert.match(items[0].summary, /confidence 100%/);
  assert.match(items[0].summary, /reported by drb_ra/);
  assert.match(items[0].summary, /last seen 2026-07-30/);
});

test('abuse_ch detable rejects an HTML auth wall', async () => {
  const source = { category: 'Malware / C2', enrichHints: {} };
  const ctx = { request: async () => ({ status: 200, headers: { 'content-type': 'text/html' }, body: '<html>login</html>' }) };
  await assert.rejects(() => abuseCh.fetch(source, ctx), /needs Auth-Key|not valid JSON/);
});
