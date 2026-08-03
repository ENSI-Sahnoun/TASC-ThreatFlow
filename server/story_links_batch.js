// Semantic story linking — the I/O half. Runs at the end of consolidate(), after
// rebuildClusters() has produced the current cluster set.
//
// Two phases, deliberately separate:
//
//   1. embedPending  — make sure every in-window cluster's primary item has a cached vector.
//                      This is the only phase that calls the model, and the only slow one.
//   2. rebuildLinks  — pure cosine over those vectors, then replace story_links.
//
// The embedding cache is keyed on item_id, not cluster id, because rebuildClusters() deletes and
// reinserts every cluster on each consolidation — cluster ids do not survive a sync, item ids do.
// Without that, every sync would re-pay for every embedding and story_links would be permanently
// empty on a fresh cluster set.
//
// Nothing here writes to clusters, cluster_items, items or confidence. A wrong similarity edge
// can only add a suggestion link in the UI.

const { embed, DEFAULT_EMBED_MODEL } = require('./lm_client');
const { linkCandidates, SIMILARITY_THRESHOLD, MAX_LINKS_PER_CLUSTER } = require('./story_links');
const { WINDOW_MS } = require('./cluster');

const CONCURRENCY = 3;
const MAX_EMBED_CHARS = 2000;

// Only prose stories are linkable, and this filter is not a nicety — it is the difference
// between the feature working and being pure noise.
//
// Measured on the live 72h window (296 clusters, 43,660 pairs): the top of the similarity
// distribution was entirely template-shaped bulk rows, because an embedding of
// "CVE-2024-23897" and "CVE-2024-21887" is a comparison of string shape, not of meaning. 1,246
// pairs scored >= 0.95 and not one was a related story:
//
//   0.998  bare CVE ids from KEV/EPSS/GHSA          (category 'cve')
//   0.860  "Attacking IP: <address>"                 (category 'ioc')
//   0.850  "Malicious vscode package: <name>"
//
// Ransomware.live rows are excluded for the same reason — every title is "Victim (group)", so
// unrelated victims of the same template pair highly. Restricting to narrative categories and
// requiring a title with whitespace (which drops the bare-identifier advisories) leaves 41 of
// 296 clusters, and those 41 are the only ones for which "related story" is even a question.
const LINKABLE_CATEGORIES = ['news', 'osint', 'malware', 'advisory'];

// Only clusters with a real first_seen are linked. An undated cluster has no position in time, so
// "related story within the 72h window" is not a question its data can answer — and there are
// ~1,600 of them (bulk indicator rows whose items carry no published_at), which would dominate
// the pair graph and generate links nothing could justify. linkCandidates() still tolerates a
// null firstSeen defensively; this query never produces one.
const WINDOW_SQL = `
  SELECT cl.id, cl.first_seen, cl.primary_item_id, i.title, i.summary, e.embedding, e.model
    FROM clusters cl
    JOIN items i ON i.id = cl.primary_item_id
    LEFT JOIN item_embeddings e ON e.item_id = cl.primary_item_id AND e.model = $2
   WHERE cl.first_seen > now() - ($1 || ' milliseconds')::interval
     AND i.category = ANY($3::text[])
     AND i.title ~ ' '`;

function embedText(row) {
  const title = String(row.title || '').trim();
  const summary = String(row.summary || '').trim();
  return `${title}\n${summary}`.trim().slice(0, MAX_EMBED_CHARS);
}

// Postgres returns a DOUBLE PRECISION[] as a JS array already; a driver that hands back the raw
// literal is handled rather than trusted, since a string here would silently become a
// zero-length "vector" and drop the cluster from linking with no error anywhere.
function toVector(value) {
  if (Array.isArray(value)) return value.map(Number).filter((n) => Number.isFinite(n));
  if (typeof value === 'string' && value.startsWith('{')) {
    const parsed = value.slice(1, -1).split(',').map(Number);
    return parsed.every((n) => Number.isFinite(n)) ? parsed : [];
  }
  return [];
}

async function embedPending(store, { embedFn = embed, model = DEFAULT_EMBED_MODEL, windowMs = WINDOW_MS, concurrency = CONCURRENCY, categories = LINKABLE_CATEGORIES } = {}) {
  const rows = await store.all(WINDOW_SQL, [String(windowMs), model, categories]);
  const pending = rows.filter((r) => !r.embedding && embedText(r));

  let written = 0;
  let failed = 0;
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= pending.length) return;
      const row = pending[i];

      const vector = await embedFn(embedText(row), { model });
      // Absence over fabrication: a failed embedding leaves no row, so the cluster is simply
      // absent from this pass's link graph and is retried on the next consolidation.
      if (!Array.isArray(vector) || !vector.length) { failed += 1; continue; }

      await store.run(
        `INSERT INTO item_embeddings (item_id, embedding, model) VALUES ($1,$2,$3)
         ON CONFLICT (item_id) DO UPDATE SET embedding = EXCLUDED.embedding, model = EXCLUDED.model, computed_at = now()`,
        [row.primary_item_id, vector, model]);
      written += 1;
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) || 1 }, worker));
  return { considered: rows.length, pending: pending.length, written, failed };
}

async function rebuildLinks(store, {
  model = DEFAULT_EMBED_MODEL,
  windowMs = WINDOW_MS,
  threshold = SIMILARITY_THRESHOLD,
  maxPerCluster = MAX_LINKS_PER_CLUSTER,
  categories = LINKABLE_CATEGORIES,
} = {}) {
  const rows = await store.all(WINDOW_SQL, [String(windowMs), model, categories]);
  const clusters = rows
    .filter((r) => r.embedding)
    .map((r) => ({ id: r.id, embedding: toVector(r.embedding), firstSeen: r.first_seen }));

  const links = linkCandidates(clusters, { threshold, windowMs, maxPerCluster });

  // Full replace, not a scoped delete. rebuildClusters() has already discarded every cluster id
  // this table referenced, so there is nothing older to preserve — the expensive part
  // (embeddings) is cached on items and survives regardless.
  await store.tx(async (t) => {
    await t.run('DELETE FROM story_links');
    for (const l of links) {
      await t.run(
        `INSERT INTO story_links (cluster_a_id, cluster_b_id, similarity, model) VALUES ($1,$2,$3,$4)
         ON CONFLICT (cluster_a_id, cluster_b_id) DO NOTHING`,
        [l.clusterAId, l.clusterBId, l.similarity, model]);
    }
  });

  return { embedded: clusters.length, links: links.length };
}

async function linkStories(store, opts = {}) {
  const embedded = await embedPending(store, opts);
  const linked = await rebuildLinks(store, opts);
  return { ...linked, embeddedNow: embedded.written, embedFailed: embedded.failed };
}

module.exports = { linkStories, embedPending, rebuildLinks, embedText, toVector, WINDOW_SQL, LINKABLE_CATEGORIES };
