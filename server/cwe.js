// Pure CWE (weakness type) extraction from an NVD CVE object's raw_json. Same shape as
// server/cpe.js/cpesFromRaw -- no I/O, and the source data has been sitting in raw_json unused
// since the first sync.
const CWE_RE = /^CWE-\d+$/;

function cwesFromRaw(raw) {
  if (!raw || typeof raw !== 'object') return [];
  const out = new Set();
  for (const w of raw.weaknesses || []) {
    for (const d of (w && w.description) || []) {
      if (d && d.lang === 'en' && typeof d.value === 'string' && CWE_RE.test(d.value)) out.add(d.value);
    }
  }
  return [...out];
}

module.exports = { cwesFromRaw, CWE_RE };
