// The "Possible Threat" verdict: pure, no I/O, no model. Given a profile and one item, decide
// how much it should matter to that user and say why.
//
// A rule ladder rather than a weighted sum, because explainability is the whole feature — a rule
// yields a sentence ("you run FortiOS and it is being exploited"), a score of 87 does not. The
// numeric score exists only to order items *within* a tier and is never rendered.
const { severityFromScore } = require('./cvss');

const TIERS = ['act_now', 'watch', 'low', 'not_yours'];

// "Is this urgent now", which is a different question from queries.js's DEFAULT_MAX_AGE_DAYS
// (365) — "is this worth showing at all". A ten-month-old CVE belongs in the feed but must never
// reach act_now.
const SCORER_RECENT_DAYS = 90;

// Ordering for floor comparisons. 'unknown' is absent deliberately: an unverifiable severity is
// not evidence of one, so it can never satisfy a floor.
const SEVERITY_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function rank(sev) {
  return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, sev) ? SEVERITY_RANK[sev] : -1;
}

function meetsFloor(sev, floor) {
  const r = rank(sev);
  return r >= 0 && r >= rank(floor);
}

// cve_intel consolidates a CVE across every source that reported it, so it outranks the value a
// single item happened to carry. Falls back to the item's own fields for non-CVE content.
function effectiveSeverity(item) {
  const cve = item.cve;
  if (cve && cve.severity && rank(cve.severity) >= 0) return cve.severity;
  if (item.severity && rank(item.severity) >= 0) return item.severity;
  // No label, but a score and its version are enough to derive one — using the bands for that
  // version, never the other's.
  const score = cve && cve.cvssScore != null ? cve.cvssScore : item.cvssScore;
  if (score != null) return severityFromScore(score, item.cvssVersion);
  return null;
}

function effectiveScore(item) {
  const cve = item.cve;
  if (cve && cve.cvssScore != null) return Number(cve.cvssScore);
  return item.cvssScore != null ? Number(item.cvssScore) : null;
}

function ageDays(publishedAt, now) {
  if (!publishedAt) return null;
  const t = new Date(publishedAt).getTime();
  if (Number.isNaN(t)) return null;
  return (now.getTime() - t) / (24 * 60 * 60 * 1000);
}

function overlap(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || !a.length || !b.length) return [];
  const set = new Set(b);
  return a.filter((x) => set.has(x));
}

function scoreRelevance(profile, item, now = new Date()) {
  const matches = [];

  const profVendors = profile.vendors || [];
  const profProducts = profile.products || [];
  const profDomains = profile.threat_domains || [];
  const cpes = item.cpes || [];

  // A product hit is a much stronger claim than its vendor ("we run FortiOS" vs "we run
  // something by Fortinet"), so they are tracked separately and weighted differently.
  const productHits = cpes.filter((c) => profProducts.includes(c.product));
  const vendorHits = cpes.filter((c) => profVendors.includes(c.vendor) && !productHits.includes(c));
  const assetMatch = productHits.length > 0 || vendorHits.length > 0;

  const domainHits = overlap(item.domains || [], profDomains);
  const domainMatch = domainHits.length > 0;

  const kev = !!(item.cve && item.cve.kevListed);
  const severity = effectiveSeverity(item);
  const cvss = effectiveScore(item);
  const epss = item.cve && item.cve.epssScore != null ? Number(item.cve.epssScore) : null;

  const age = ageDays(item.publishedAt, now);
  // An undated item is unknown-age, not new — it passes the feed's age filter but must never
  // count as urgent.
  const recent = age != null && age <= SCORER_RECENT_DAYS;

  const sectorMatch = !!(item.industry && profile.sector && item.industry === profile.sector);

  for (const c of productHits) matches.push({ kind: 'product', value: `${c.vendor} ${c.product}` });
  for (const c of vendorHits) matches.push({ kind: 'vendor', value: c.vendor });
  for (const d of domainHits) matches.push({ kind: 'domain', value: d });
  if (kev) matches.push({ kind: 'kev', value: 'CISA KEV' });
  if (sectorMatch) matches.push({ kind: 'sector', value: item.industry });
  if (severity && rank(severity) >= 0) matches.push({ kind: 'severity', value: severity });

  const floor = profile.severity_floor || 'medium';
  const atLeastHigh = meetsFloor(severity, 'high');
  const atFloor = meetsFloor(severity, floor);

  let tier;
  if (assetMatch && (kev || atLeastHigh) && recent) tier = 'act_now';
  else if (assetMatch) tier = 'watch';
  else if (domainMatch && atFloor && recent) tier = 'watch';
  else if (sectorMatch && recent) tier = 'watch';
  else if (domainMatch || atFloor) tier = 'low';
  else tier = 'not_yours';

  // Tiebreak only, never rendered. Weights are deliberately coarse — this orders a list, it does
  // not quantify risk.
  let score = 0;
  score += productHits.length ? 5 : 0;
  score += vendorHits.length ? 3 : 0;
  score += kev ? 4 : 0;
  score += domainMatch ? 1 : 0;
  if (cvss != null) score += Math.max(0, Math.min(3, (cvss / 10) * 3));
  if (epss != null) score += Math.max(0, Math.min(2, epss * 2));
  if (recent) score += Math.max(0, Math.min(2, 2 * (1 - age / SCORER_RECENT_DAYS)));

  // Nothing matched, so there is nothing to explain — an empty list, not a list of non-reasons.
  return { tier, score, matches: tier === 'not_yours' ? [] : matches };
}

module.exports = { scoreRelevance, SCORER_RECENT_DAYS, TIERS };
