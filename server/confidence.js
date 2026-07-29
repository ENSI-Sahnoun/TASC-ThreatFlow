// Derived confidence. This is a HEURISTIC, never a vendor-supplied score, and the UI labels
// it as such. Two stages: the tier weight is known at ingest; the corroboration term is
// applied by the post-sync consolidation pass once it knows which sources agree.

const TIER_WEIGHTS = {
  'Government / CERT Advisory': 0.95,
  'Vendor Advisory': 0.9,
  'Vulnerability Intelligence': 0.9,
  'Data Breaches': 0.9,
  'Malware Research': 0.8,
  'Threat Intelligence': 0.75,
  'Malware / C2': 0.7,
  Ransomware: 0.7,
  Phishing: 0.65,
  'Cybersecurity News': 0.6,
  OSINT: 0.5,
};

const FLOOR = 0.5;
const CAP = 0.99;
const PER_CORROBORATION = 0.05;

function tierWeight(sourceCategory) {
  if (typeof sourceCategory !== 'string') return FLOOR;
  return TIER_WEIGHTS[sourceCategory.trim()] ?? FLOOR;
}

function computeConfidence(sourceCategory, corroboratingSources = 1) {
  const n = Number(corroboratingSources);
  const extra = Number.isFinite(n) && n > 1 ? n - 1 : 0;
  const raw = tierWeight(sourceCategory) + PER_CORROBORATION * extra;
  return Math.round(Math.min(CAP, raw) * 100) / 100;
}

module.exports = { tierWeight, computeConfidence, TIER_WEIGHTS };
