// Deterministic story clustering. Three outlets covering one story should be one feed row.
// No ML: the signals are shared CVEs, shared actors/families, and title-token overlap.
// Deliberately conservative — clustering never destroys rows, it only groups them, but a
// wrong merge hides a real story, so the bar to merge is high.

const WINDOW_MS = 72 * 60 * 60 * 1000;
const JACCARD_THRESHOLD = 0.35;

// Terms that appear across most of this corpus and therefore carry no discriminating power.
// Tuning this list is a visible, tested change — not a hidden constant.
const STOPWORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'of', 'in', 'on', 'to', 'for', 'with', 'from', 'by', 'as', 'at', 'is', 'are', 'it',
  'new', 'security', 'attack', 'attacks', 'attackers', 'attacker', 'hackers', 'hacker', 'flaw', 'flaws', 'bug', 'bugs',
  'vulnerability', 'vulnerabilities', 'exploit', 'exploits', 'exploited', 'report', 'reports', 'researchers',
  'critical', 'update', 'updates', 'patch', 'patches', 'cyber', 'threat', 'threats', 'malware', 'campaign',
]);

function titleTokens(title) {
  const words = String(title || '').toLowerCase().replace(/[^a-z0-9\s-]/g, ' ').split(/[\s-]+/);
  return new Set(words.filter((w) => w.length > 2 && !STOPWORDS.has(w)));
}

function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let shared = 0;
  for (const v of a) if (b.has(v)) shared += 1;
  return shared / (a.size + b.size - shared);
}

function sameSet(a, b) {
  if (!a.length || a.length !== b.length) return false;
  const s = new Set(b);
  return a.every((v) => s.has(v));
}

function overlaps(a, b) {
  const s = new Set(b);
  return a.some((v) => s.has(v));
}

function timeOf(item) {
  const t = Date.parse(item.published_at);
  return Number.isNaN(t) ? 0 : t;
}

function itemsMatch(a, b) {
  if (Math.abs(timeOf(a) - timeOf(b)) > WINDOW_MS) return false;
  if (sameSet(a.cves || [], b.cves || [])) return true;
  const sharedEntity = overlaps(a.actors || [], b.actors || []) || overlaps(a.families || [], b.families || []);
  if (!sharedEntity) return false;
  const ta = a._tokens ?? titleTokens(a.title);
  const tb = b._tokens ?? titleTokens(b.title);
  return jaccard(ta, tb) >= JACCARD_THRESHOLD;
}

function clusterItems(items) {
  const prepared = items
    .map((it) => ({ ...it, _tokens: titleTokens(it.title) }))
    .sort((x, y) => timeOf(x) - timeOf(y));

  const clusters = [];
  for (const it of prepared) {
    const hit = clusters.find((c) => c.members.some((m) => itemsMatch(m, it)));
    if (hit) hit.members.push(it);
    else clusters.push({ members: [it] });
  }

  return clusters.map((c) => {
    const primary = c.members.reduce((best, m) =>
      (m.confidence ?? 0) > (best.confidence ?? 0) || ((m.confidence ?? 0) === (best.confidence ?? 0) && timeOf(m) < timeOf(best)) ? m : best);
    const times = c.members.map(timeOf).filter(Boolean).sort((x, y) => x - y);
    return {
      primaryItemId: primary.id,
      title: primary.title,
      itemIds: c.members.map((m) => m.id),
      sourceIds: [...new Set(c.members.map((m) => m.source_id))],
      firstSeen: times.length ? new Date(times[0]).toISOString() : null,
      lastSeen: times.length ? new Date(times[times.length - 1]).toISOString() : null,
    };
  });
}

module.exports = { titleTokens, jaccard, itemsMatch, clusterItems, STOPWORDS, JACCARD_THRESHOLD, WINDOW_MS };
