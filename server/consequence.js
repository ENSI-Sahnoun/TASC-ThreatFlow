// Turns a CVSS vector, an asset's exposure and a product role into four plain-English fact
// slots. Pure: no I/O, no model, no database.
//
// This is the module that answers "how does this affect me". The tier says how much to care;
// these slots say what would actually happen. Both the model prompt and the template fallback
// are built from the same slots, so a rejected model output degrades to a sentence that is
// still specific rather than to "Matches your stack (microsoft windows)".
//
// Every slot is independently nullable and carries `from`, the metrics it was derived from, so
// the claim is auditable rather than asserted. Missing data is a null slot, never a guess —
// the same posture the README applies to confidence = NULL.
const { parseVector } = require('./cvss');
const { roleFor } = require('./asset_roles');

// Conservative on purpose. EPSS is a probability of exploitation in the next 30 days, and this
// threshold decides whether a user is told to hurry. Tune it against the quality.eval.json
// holdout method rather than by feel.
const EPSS_URGENT_THRESHOLD = 0.5;

// AV crossed with exposure. This crossing is the entire reason exposure is collected: AV:N
// alone is a property of the flaw, AV:N on an internet-facing asset is a statement about the
// reader's own estate.
function reachText(av, exposure) {
  if (av === 'N') {
    if (exposure === 'internet') return 'anyone on the internet';
    if (exposure === 'internal') return 'anyone already inside your network';
    return 'anyone who can reach it over the network';
  }
  if (av === 'A') return 'someone on the same network';
  if (av === 'L') return 'someone who already has access to that machine';
  if (av === 'P') return 'someone standing at the machine';
  return null;
}

const PRIVILEGE = {
  N: 'with no password',
  L: 'with any ordinary account',
  H: 'only with admin rights',
};

function buildReach(metrics, exposure) {
  const who = reachText(metrics.AV, exposure);
  if (!who) return null;
  const parts = [who];
  if (PRIVILEGE[metrics.PR]) parts.push(PRIVILEGE[metrics.PR]);
  if (metrics.UI === 'R') parts.push('if a person clicks or opens something');
  return {
    text: parts.join(', '),
    from: `AV:${metrics.AV}/PR:${metrics.PR}/UI:${metrics.UI} + exposure=${exposure}`,
  };
}

const VERBS = { C: 'read', I: 'change', A: 'shut down' };

function joinList(values) {
  if (values.length === 1) return values[0];
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`;
}

// A :L metric is a real but partial effect. Rendering it as the full verb would overstate the
// consequence; dropping it would understate it.
function buildImpact(metrics) {
  const parts = [];
  const from = [];
  for (const key of ['C', 'I', 'A']) {
    const value = metrics[key];
    if (value === 'H') { parts.push(VERBS[key]); from.push(`${key}:H`); }
    else if (value === 'L') { parts.push(`partly ${VERBS[key]}`); from.push(`${key}:L`); }
  }
  // All three None. That is an absent slot, not the claim "no impact" — a scope-changed vector
  // can carry effects these three metrics do not express.
  if (!parts.length) return null;
  return { text: joinList(parts), from: from.join('/') };
}

function buildUrgency(kevListed, kevDueDate, epssScore) {
  if (kevListed) {
    return { text: 'already used in real attacks', due: kevDueDate || null, from: 'KEV' };
  }
  if (epssScore != null && Number(epssScore) >= EPSS_URGENT_THRESHOLD) {
    return { text: 'likely to be attacked soon', due: null, from: `EPSS>=${EPSS_URGENT_THRESHOLD}` };
  }
  // Not urgent. No filler text — an absent slot reads as "nothing to say here", which is true.
  return null;
}

function buildConsequence({
  vector, exposure = 'unknown', vendor, product,
  kevListed = false, kevDueDate = null, epssScore = null,
} = {}) {
  // parseVector returns { version, metrics } and null for anything it cannot read, including
  // v4 vectors — exactly the behaviour wanted here: no metrics means no reach or impact claim.
  const parsed = vector ? parseVector(vector) : null;
  const metrics = parsed ? parsed.metrics : null;
  const role = roleFor(vendor, product);

  return {
    reach: metrics ? buildReach(metrics, exposure) : null,
    impact: metrics ? buildImpact(metrics) : null,
    role: role ? { text: role, from: `asset_roles: ${vendor}/${product}` } : null,
    urgency: buildUrgency(kevListed, kevDueDate, epssScore),
  };
}

module.exports = { buildConsequence, EPSS_URGENT_THRESHOLD };
