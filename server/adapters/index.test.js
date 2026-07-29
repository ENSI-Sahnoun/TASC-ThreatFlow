const test = require('node:test');
const assert = require('node:assert');
const { ADAPTERS, getAdapter } = require('./index');

test('registry covers all kinds', () => {
  for (const k of ['rss','text_feed','json_api','abuse_ch','osv','misp_feed','kev','epss','nvd_cve','ransomware_live','feodo']) {
    assert.ok(ADAPTERS[k] && typeof ADAPTERS[k].fetch === 'function', `has ${k}`);
  }
});

test('getAdapter throws on unknown kind', () => {
  assert.throws(() => getAdapter('nope'), /unknown adapter/);
});
