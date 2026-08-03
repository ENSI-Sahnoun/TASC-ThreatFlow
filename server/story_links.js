// Semantic story linking — the pure half. No database, no model calls, no I/O.
//
// `cluster.js` merges items into one story only on hard evidence (a shared CVE set, or a shared
// actor/family plus title overlap). That bar is deliberately high, because a wrong merge hides a
// story. The cost is that two write-ups of the same event which share no CVE and no dictionary
// entity stay separate rows with nothing connecting them.
//
// This module is the soft counterpart: it suggests that two SEPARATE clusters may be about the
// same thing, and nothing downstream is allowed to act on the suggestion. It never merges, never
// feeds `clusters.source_count`, and therefore never touches the corroboration bonus in
// `confidence.js`. A wrong edge here costs a bad suggestion link in the UI and nothing else.

const { WINDOW_MS } = require('./cluster');

// Measured against the live 72h window on 2026-08-03 with mxbai-embed-large, not assumed. The
// spec's original 0.82 was written before any vector had been computed and is too high: it finds
// one link in the whole window and misses both of the genuine same-story-two-outlets pairs the
// feature exists for.
//
// Over 820 prose pairs, everything at or above 0.69 was defensible on hand-check:
//
//   0.9895  USN-8620-3 / USN-8620-4 — the same Ubuntu advisory, two revisions
//   0.8369  "Anthropic Finds Its Own Models Hacked 3 Orgs" / "Anthropic says its AI hacked
//           real-world companies" — the same story in two outlets
//   0.7423  two different Chrome patching stories from the same week
//   0.6996  "Cyberattacks on Minnesota Water Systems" / "CISA warns of spike in attacks on water
//           systems as Minnesota incidents probed" — the same story in two outlets
//   0.6974  each of the two stories above paired with a comment piece on the same events
//   0.6965
//
// Then quality breaks, and the drop is the reason the constant sits where it does rather than at
// a rounder 0.70: 0.6838 pairs two unrelated fake-update campaigns, and 0.6672 pairs a story with
// a weekly roundup that merely mentions the same company. A threshold of 0.70 looks tidier and
// silently loses the Minnesota pair by four ten-thousandths.
//
// Note that unrelated security headlines sit around 0.55-0.65 with this model, not near zero —
// a threshold carried over from a different embedding model means nothing here.
const SIMILARITY_THRESHOLD = Number(process.env.STORY_LINK_THRESHOLD) || 0.69;

// How many links one cluster may show. Semantic similarity is not transitive in practice: a
// generic "Patch Tuesday roundup" cluster is mildly close to dozens of others, and without a cap
// it becomes a hub linking half the window to itself.
const MAX_LINKS_PER_CLUSTER = 5;

function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length || !a.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i += 1) {
    const x = a[i];
    const y = b[i];
    if (typeof x !== 'number' || typeof y !== 'number' || !Number.isFinite(x) || !Number.isFinite(y)) return 0;
    dot += x * y;
    normA += x * x;
    normB += y * y;
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

function timeOf(value) {
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/**
 * Pair clusters that are close in both time and meaning.
 *
 * @param clusters [{ id, embedding, firstSeen }] — embedding may be null (not embedded yet)
 * @returns [{ clusterAId, clusterBId, similarity }] with clusterAId < clusterBId, best first
 */
function linkCandidates(clusters, {
  threshold = SIMILARITY_THRESHOLD,
  windowMs = WINDOW_MS,
  maxPerCluster = MAX_LINKS_PER_CLUSTER,
} = {}) {
  const usable = (clusters || []).filter((c) => c && c.id != null && Array.isArray(c.embedding) && c.embedding.length);

  const pairs = [];
  for (let i = 0; i < usable.length; i += 1) {
    for (let j = i + 1; j < usable.length; j += 1) {
      const a = usable[i];
      const b = usable[j];
      if (a.id === b.id) continue;

      // Vectors of different lengths come from different embedding models and are not
      // comparable. Comparing them anyway would yield 0 from cosineSimilarity, which is
      // harmless, but skipping says why.
      if (a.embedding.length !== b.embedding.length) continue;

      // A cluster with no timestamp has an unknown position in time, not a position of zero —
      // treating a null as epoch would place it 56 years from everything and silently exclude it.
      // Unknown time is allowed to pair on meaning alone.
      const ta = timeOf(a.firstSeen);
      const tb = timeOf(b.firstSeen);
      if (ta !== null && tb !== null && Math.abs(ta - tb) > windowMs) continue;

      const similarity = cosineSimilarity(a.embedding, b.embedding);
      if (similarity < threshold) continue;

      const [lo, hi] = a.id < b.id ? [a.id, b.id] : [b.id, a.id];
      pairs.push({ clusterAId: lo, clusterBId: hi, similarity });
    }
  }

  pairs.sort((x, y) => y.similarity - x.similarity
    || x.clusterAId - y.clusterAId
    || x.clusterBId - y.clusterBId);

  if (!Number.isFinite(maxPerCluster) || maxPerCluster <= 0) return pairs;

  // Greedy cap, strongest pairs first, so a cluster keeps its best links rather than whichever
  // happened to be evaluated first.
  const used = new Map();
  const count = (id) => used.get(id) || 0;
  const kept = [];
  for (const p of pairs) {
    if (count(p.clusterAId) >= maxPerCluster || count(p.clusterBId) >= maxPerCluster) continue;
    used.set(p.clusterAId, count(p.clusterAId) + 1);
    used.set(p.clusterBId, count(p.clusterBId) + 1);
    kept.push(p);
  }
  return kept;
}

// The UI shows a label, never a raw float — a similarity of 0.87 means nothing to a reader, and
// printing it implies a precision the measurement does not have. The 0.9 boundary matches what
// the corpus does: only same-document pairs (an advisory and its own revision) reach it.
function similarityLabel(similarity) {
  return similarity >= 0.9 ? 'Likely related' : 'Possibly related';
}

module.exports = {
  cosineSimilarity,
  linkCandidates,
  similarityLabel,
  SIMILARITY_THRESHOLD,
  MAX_LINKS_PER_CLUSTER,
};
