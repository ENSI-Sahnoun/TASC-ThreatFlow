const test = require('node:test');
const assert = require('node:assert');
const { parseCpe, cpesFromRaw } = require('./cpe');

test('parseCpe extracts part/vendor/product from a 2.3 string', () => {
  assert.deepStrictEqual(
    parseCpe('cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*'),
    { part: 'a', vendor: 'fortinet', product: 'fortios' });
});

test('parseCpe handles os and hardware parts', () => {
  assert.deepStrictEqual(
    parseCpe('cpe:2.3:o:ibm:aix:*:*:*:*:*:*:*:*'),
    { part: 'o', vendor: 'ibm', product: 'aix' });
});

test('parseCpe keeps vendor/product punctuation intact', () => {
  assert.deepStrictEqual(
    parseCpe('cpe:2.3:a:t._hauck:jana_web_server:1.0:*:*:*:*:*:*:*'),
    { part: 'a', vendor: 't._hauck', product: 'jana_web_server' });
});

// A wildcard vendor or product carries no matchable signal. Writing it would let a profile
// with vendor '*' match every item.
test('parseCpe rejects wildcard and empty vendor/product', () => {
  assert.strictEqual(parseCpe('cpe:2.3:a:*:fortios:*:*:*:*:*:*:*:*'), null);
  assert.strictEqual(parseCpe('cpe:2.3:a:fortinet:-:*:*:*:*:*:*:*:*'), null);
});

test('parseCpe rejects malformed input without throwing', () => {
  for (const bad of [null, undefined, 42, '', 'not a cpe', 'cpe:2.2:a:v:p', 'cpe:2.3:x:v:p:*:*:*:*:*:*:*', 'cpe:2.3:a:onlyvendor']) {
    assert.strictEqual(parseCpe(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test('cpesFromRaw walks configurations and de-duplicates across versions', () => {
  const raw = {
    configurations: [{
      nodes: [{
        cpeMatch: [
          { criteria: 'cpe:2.3:a:fortinet:fortios:7.0.1:*:*:*:*:*:*:*' },
          { criteria: 'cpe:2.3:a:fortinet:fortios:7.0.2:*:*:*:*:*:*:*' },
          { criteria: 'cpe:2.3:o:fortinet:fortiosos:*:*:*:*:*:*:*:*' },
        ],
      }],
    }],
  };
  assert.deepStrictEqual(cpesFromRaw(raw), [
    { part: 'a', vendor: 'fortinet', product: 'fortios' },
    { part: 'o', vendor: 'fortinet', product: 'fortiosos' },
  ]);
});

test('cpesFromRaw returns [] for absent or malformed structures', () => {
  for (const bad of [null, undefined, {}, { configurations: null }, { configurations: [{}] }, { configurations: [{ nodes: [{ cpeMatch: [{}] }] }] }]) {
    assert.deepStrictEqual(cpesFromRaw(bad), []);
  }
});
