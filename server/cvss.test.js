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
