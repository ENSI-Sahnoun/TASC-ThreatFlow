const CANDIDATES = {
  cveField: ['cve', 'cveId', 'CVE', 'cve_id'],
  cvssField: ['cvss', 'cvssScore', 'cvss3_score', 'baseScore', 'cvss_score'],
  severityField: ['severity', 'baseSeverity', 'severity_level'],
  vendorField: ['vendor', 'vendorProject', 'publisher', 'vendor_project'],
  titleField: ['title', 'name', 'headline', 'subject', 'documentTitle', 'id'],
  idField: ['id', 'uuid', 'cveId', 'cve', 'name'],
};

function detectFields(record) {
  const out = { cveField: null, cvssField: null, severityField: null, vendorField: null, titleField: null, idField: null };
  if (!record || typeof record !== 'object') return out;
  const keysByLower = new Map(Object.keys(record).map((k) => [k.toLowerCase(), k]));
  for (const [outKey, candidates] of Object.entries(CANDIDATES)) {
    for (const candidate of candidates) {
      const actualKey = keysByLower.get(candidate.toLowerCase());
      if (actualKey !== undefined) {
        out[outKey] = actualKey;
        break;
      }
    }
  }
  return out;
}

module.exports = { detectFields };
