// Pure CPE 2.3 parsing. Only part/vendor/product are kept — a profile expresses "we run
// FortiOS", not a version inventory, so version and the trailing fields are discarded.
// items.vendor is populated on <1% of rows; this is the real tech-stack signal.

const PARTS = new Set(['a', 'o', 'h']);

// Absent/any/N-A in CPE are '*' and '-'. Either carries no matchable signal.
function meaningful(field) {
  return typeof field === 'string' && field !== '' && field !== '*' && field !== '-';
}

function parseCpe(criteria) {
  if (typeof criteria !== 'string') return null;
  const fields = criteria.trim().split(':');
  // cpe : 2.3 : part : vendor : product : ...9 more
  if (fields.length < 5) return null;
  if (fields[0].toLowerCase() !== 'cpe' || fields[1] !== '2.3') return null;
  const part = fields[2].toLowerCase();
  if (!PARTS.has(part)) return null;
  const vendor = fields[3].toLowerCase();
  const product = fields[4].toLowerCase();
  if (!meaningful(vendor) || !meaningful(product)) return null;
  return { part, vendor, product };
}

function cpesFromRaw(raw) {
  if (!raw || typeof raw !== 'object') return [];
  const out = [];
  const seen = new Set();
  for (const config of raw.configurations || []) {
    for (const node of (config && config.nodes) || []) {
      for (const match of (node && node.cpeMatch) || []) {
        const parsed = parseCpe(match && match.criteria);
        if (!parsed) continue;
        const key = `${parsed.part}:${parsed.vendor}:${parsed.product}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(parsed);
      }
    }
  }
  return out;
}

module.exports = { parseCpe, cpesFromRaw };
