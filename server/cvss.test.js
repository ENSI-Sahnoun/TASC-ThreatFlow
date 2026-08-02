const { test } = require('node:test');
const assert = require('node:assert');
const { parseVector, scoreFromVector, severityFromScore, canonicalSeverity, SEVERITIES } = require('./cvss');

test('parseVector reads a v3.1 vector', () => {
  const p = parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.strictEqual(p.version, '3.1');
  assert.strictEqual(p.metrics.AV, 'N');
  assert.strictEqual(p.metrics.S, 'U');
  assert.strictEqual(parseVector('nonsense'), null);
  assert.strictEqual(parseVector(null), null);
});

test('scoreFromVector matches published CVSS v3.1 base scores', () => {
  assert.strictEqual(scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.strictEqual(scoreFromVector('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
  assert.strictEqual(scoreFromVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'), 9.0);
  assert.strictEqual(scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('severityFromScore uses the standard bands', () => {
  assert.strictEqual(severityFromScore(9.8), 'critical');
  assert.strictEqual(severityFromScore(7.0), 'high');
  assert.strictEqual(severityFromScore(4.0), 'medium');
  assert.strictEqual(severityFromScore(0.1), 'low');
  assert.strictEqual(severityFromScore(0), 'none');
  assert.strictEqual(severityFromScore(null), null);
});

test('canonicalSeverity maps vendor words and rejects blobs', () => {
  assert.strictEqual(canonicalSeverity('important'), 'high');
  assert.strictEqual(canonicalSeverity('Moderate'), 'medium');
  assert.strictEqual(canonicalSeverity('CRITICAL'), 'critical');
  // the exact shape currently polluting the column
  assert.strictEqual(canonicalSeverity('{"{\\"type\\":\\"CVSS_V3\\",\\"score\\":\\"CVSS:3.1/AV:N\\"}"}'), 'unknown');
  assert.strictEqual(canonicalSeverity(['a', 'b']), 'unknown');
  assert.strictEqual(canonicalSeverity(null), 'unknown');
  for (const s of SEVERITIES) assert.strictEqual(canonicalSeverity(s), s);
});

const { metricFromNvd } = require('./cvss');

test('metricFromNvd prefers v3.1 over v3.0 over v2', () => {
  const metrics = {
    cvssMetricV2:  [{ cvssData: { baseScore: 5.0 }, baseSeverity: 'MEDIUM' }],
    cvssMetricV30: [{ cvssData: { baseScore: 8.1, baseSeverity: 'HIGH' } }],
    cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }],
  };
  assert.deepStrictEqual(metricFromNvd(metrics), { score: 9.8, severity: 'critical', version: '3.1' });

  delete metrics.cvssMetricV31;
  assert.deepStrictEqual(metricFromNvd(metrics), { score: 8.1, severity: 'high', version: '3.0' });
});

// v2 puts baseSeverity on the metric object, NOT inside cvssData. Reading cvssData.baseSeverity
// is why 9,812 rows ended up with severity NULL.
test('metricFromNvd reads v2 baseSeverity from the metric object', () => {
  assert.deepStrictEqual(
    metricFromNvd({ cvssMetricV2: [{ cvssData: { baseScore: 5.0 }, baseSeverity: 'MEDIUM' }] }),
    { score: 5.0, severity: 'medium', version: '2.0' });
});

test('metricFromNvd falls back to the version-appropriate band when the label is absent', () => {
  assert.deepStrictEqual(
    metricFromNvd({ cvssMetricV2: [{ cvssData: { baseScore: 9.3 } }] }),
    { score: 9.3, severity: 'high', version: '2.0' });   // v2 has no 'critical'
  assert.deepStrictEqual(
    metricFromNvd({ cvssMetricV31: [{ cvssData: { baseScore: 9.3 } }] }),
    { score: 9.3, severity: 'critical', version: '3.1' });
});

test('metricFromNvd returns null for absent or unscored metrics', () => {
  for (const bad of [null, undefined, {}, { cvssMetricV31: [] }, { cvssMetricV31: [{ cvssData: {} }] }]) {
    assert.strictEqual(metricFromNvd(bad), null);
  }
});

test('severityFromScore applies v2 bands only when asked', () => {
  assert.strictEqual(severityFromScore(9.3, '2.0'), 'high');
  assert.strictEqual(severityFromScore(6.9, '2.0'), 'medium');
  assert.strictEqual(severityFromScore(3.9, '2.0'), 'low');
  assert.strictEqual(severityFromScore(0, '2.0'), 'none');
  // Default and explicit v3 keep the existing four bands.
  assert.strictEqual(severityFromScore(9.3), 'critical');
  assert.strictEqual(severityFromScore(9.3, '3.1'), 'critical');
});
