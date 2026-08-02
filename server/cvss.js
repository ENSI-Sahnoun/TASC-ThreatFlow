// Pure CVSS handling. v3.0/v3.1 vectors are parsed and scored in full. v2 vectors are
// recognised but not scored locally. v4.0 vectors are NOT scored locally — when a feed
// supplies only a v4 vector we fall back to its own label, because a wrong CVSS number is
// worse than an absent one.

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unknown'];

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

const VENDOR_SEVERITY = {
  critical: 'critical',
  high: 'high', important: 'high', severe: 'high',
  medium: 'medium', moderate: 'medium',
  low: 'low', minor: 'low',
  none: 'none', informational: 'none', info: 'none', negligible: 'none',
};

function parseVector(vector) {
  if (typeof vector !== 'string') return null;
  const s = vector.trim();
  const m = s.match(/^CVSS:(\d\.\d)\/(.+)$/i);
  if (!m) return null;
  const metrics = {};
  for (const part of m[2].split('/')) {
    const [k, v] = part.split(':');
    if (k && v) metrics[k.toUpperCase()] = v.toUpperCase();
  }
  return { version: m[1], metrics };
}

// CVSS 3.1 spec roundup: round to 1 decimal, always upward, guarding float representation.
function roundUp1(n) {
  const i = Math.round(n * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function baseScore(metrics) {
  if (!metrics) return null;
  const { AV, AC, PR, UI, S, C, I, A } = metrics;
  if (![AV, AC, PR, UI, S, C, I, A].every(Boolean)) return null;
  const scopeChanged = S === 'C';
  const av = W.AV[AV], ac = W.AC[AC], ui = W.UI[UI];
  const pr = (scopeChanged ? W.PR_C : W.PR_U)[PR];
  const c = W.CIA[C], i = W.CIA[I], a = W.CIA[A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;

  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp1(raw);
}

function scoreFromVector(vector) {
  const parsed = parseVector(vector);
  if (!parsed) return null;
  if (!parsed.version.startsWith('3')) return null;
  return baseScore(parsed.metrics);
}

// CVSS v2 has no 'critical' band: 7.0-10 high, 4.0-6.9 medium, 0.1-3.9 low.
// v2 and v3 scores are never renormalized into each other — a v2 9.3 is 'high', not 'critical'.
function severityFromScoreV2(score) {
  if (score == null || Number.isNaN(Number(score))) return null;
  const n = Number(score);
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n > 0) return 'low';
  return 'none';
}

function severityFromScore(score, version) {
  if (String(version || '').startsWith('2')) return severityFromScoreV2(score);
  if (score == null || Number.isNaN(Number(score))) return null;
  const n = Number(score);
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  if (n > 0) return 'low';
  return 'none';
}

// NVD emits metrics keyed by version. Priority is newest-first; v2 is last because it is
// what NVD's 1990s-2000s backlog carries and is the least precise.
const NVD_METRIC_PRIORITY = [
  { key: 'cvssMetricV31', version: '3.1' },
  { key: 'cvssMetricV30', version: '3.0' },
  { key: 'cvssMetricV2',  version: '2.0' },
];

function metricFromNvd(metrics) {
  if (!metrics || typeof metrics !== 'object') return null;
  for (const { key, version } of NVD_METRIC_PRIORITY) {
    const entry = Array.isArray(metrics[key]) ? metrics[key][0] : null;
    if (!entry) continue;
    const data = entry.cvssData || {};
    const score = data.baseScore;
    if (typeof score !== 'number' || Number.isNaN(score)) continue;
    // v3 nests baseSeverity inside cvssData; v2 places it on the metric object.
    const rawLabel = version === '2.0' ? entry.baseSeverity : data.baseSeverity;
    const labelled = rawLabel != null ? canonicalSeverity(rawLabel) : null;
    const severity = (labelled && labelled !== 'unknown')
      ? labelled
      : severityFromScore(score, version);
    return { score, severity, version };
  }
  return null;
}

// Never lets a non-enum value through. Anything unrecognised — including the JSON blobs the
// OSV/Ubuntu adapters used to emit — becomes 'unknown'.
function canonicalSeverity(value) {
  if (typeof value !== 'string') return 'unknown';
  const key = value.trim().toLowerCase();
  return VENDOR_SEVERITY[key] || 'unknown';
}

module.exports = { parseVector, baseScore, scoreFromVector, severityFromScore, severityFromScoreV2, metricFromNvd, canonicalSeverity, SEVERITIES };
