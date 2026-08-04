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

  // Two signals of very different strength. A profile_assets row is a specific claim ("we run
  // FortiOS, and it faces the internet"); a vendors[]/products[] entry is the legacy,
  // unqualified one. Only the first can be urgent — 'microsoft' matches 7519 item_cpes rows,
  // so letting it reach act_now is what made the verdict read as noise.
  const profAssets = profile.assets || [];
  const assetHits = cpes.filter((c) => profAssets.some((a) => a.vendor === c.vendor && a.product === c.product));
  const assetHit = assetHits.length > 0;

  const legacyHits = cpes.filter((c) => (profProducts.includes(c.product) || profVendors.includes(c.vendor))
    && !assetHits.includes(c));
  const legacyHit = legacyHits.length > 0;

  // An internet-facing instance is the one that matters even when the same product also runs
  // internally, so the strongest exposure among matched assets decides the rung.
  const EXPOSURE_RANK = { internet: 2, unknown: 1, internal: 0 };
  const exposure = assetHit
    ? assetHits.reduce((worst, c) => {
      const a = profAssets.find((x) => x.vendor === c.vendor && x.product === c.product);
      return EXPOSURE_RANK[a.exposure] > EXPOSURE_RANK[worst] ? a.exposure : worst;
    }, 'internal')
    : 'unknown';

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

  for (const c of assetHits) matches.push({ kind: 'product', value: `${c.vendor} ${c.product}` });
  for (const c of legacyHits) matches.push({ kind: 'vendor', value: c.vendor });
  for (const d of domainHits) matches.push({ kind: 'domain', value: d });
  if (kev) matches.push({ kind: 'kev', value: 'CISA KEV' });
  if (sectorMatch) matches.push({ kind: 'sector', value: item.industry });
  if (severity && rank(severity) >= 0) matches.push({ kind: 'severity', value: severity });

  const floor = profile.severity_floor || 'medium';
  const atLeastHigh = meetsFloor(severity, 'high');
  const atFloor = meetsFloor(severity, floor);

  let tier;
  // Ladder v3: act_now requires exploitation evidence, not just severity. Measured against the
  // verification profile, severity-alone promotion put 310 items on the top rung with only 1
  // carrying real evidence of exploitation — "act now" had stopped meaning anything. An
  // unanswered exposure still reaches act_now on a KEV item: only a positive "this is internal"
  // demotes it, and withholding urgency on an actively-exploited flaw because a survey question
  // was skipped would fail in the wrong direction.
  if (assetHit && exposure !== 'internal' && kev && recent) tier = 'act_now';
  else if (assetHit && (kev || atLeastHigh) && recent) tier = 'watch';
  else if (assetHit) tier = 'watch';
  else if (domainMatch && atFloor && recent) tier = 'watch';
  else if (sectorMatch && recent) tier = 'watch';
  else if (legacyHit || domainMatch || atFloor) tier = 'low';
  else tier = 'not_yours';

  // Tiebreak only, never rendered. Weights are deliberately coarse — this orders a list, it does
  // not quantify risk.
  let score = 0;
  score += assetHits.length ? 5 : 0;
  score += legacyHits.length ? 3 : 0;
  score += kev ? 4 : 0;
  score += domainMatch ? 1 : 0;
  if (cvss != null) score += Math.max(0, Math.min(3, (cvss / 10) * 3));
  if (epss != null) score += Math.max(0, Math.min(2, epss * 2));
  if (recent) score += Math.max(0, Math.min(2, 2 * (1 - age / SCORER_RECENT_DAYS)));

  // Nothing matched, so there is nothing to explain — an empty list, not a list of non-reasons.
  // `exposure` travels with the verdict because consequence.js needs the same value the rung
  // was decided on, not a second guess at it.
  return { tier, score, matches: tier === 'not_yours' ? [] : matches, exposure };
}

module.exports = { scoreRelevance, SCORER_RECENT_DAYS, TIERS };
