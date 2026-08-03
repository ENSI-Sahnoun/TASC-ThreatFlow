const { test } = require('node:test');
const assert = require('node:assert');
const { makeTempDb } = require('./test-helpers');
const { linkStories, embedPending, rebuildLinks, embedText, toVector } = require('./story_links_batch');

const MODEL = 'test-embed';

async function withTestStore(fn) {
  const { store, cleanup } = await makeTempDb();
  try { await fn(store); } finally { await cleanup(); }
}

async function mkSource(store, name = 'Feed') {
  return store.get("INSERT INTO sources (name, category, fetch_kind, active) VALUES ($1,'News','rss',true) RETURNING id", [name]);
}

async function mkItem(store, sourceId, o = {}) {
  return store.get(
    `INSERT INTO items (source_id, category, title, summary, published_at)
     VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [sourceId, o.category || 'news', o.title || 'a story', o.summary || null,
     o.published_at || new Date().toISOString()]);
}

// A cluster whose first_seen defaults to now(), i.e. inside the linking window.
async function mkCluster(store, itemId, o = {}) {
  return store.get(
    `INSERT INTO clusters (primary_item_id, title, first_seen, source_count)
     VALUES ($1,$2,COALESCE($3, now()),1) RETURNING id`,
    [itemId, o.title || 'cluster', o.firstSeen || null]);
}

// Returns the same vector for every call unless told otherwise — enough to make two clusters
// identical, and it records what it was asked to embed.
function fakeEmbedder(vectorFor = () => [1, 0, 0]) {
  const calls = [];
  const fn = async (text) => { calls.push(text); return vectorFor(text, calls.length); };
  return { fn, calls };
}

test('embedPending embeds each in-window cluster primary exactly once and caches it', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id, { title: 'Ransomware hits a hospital', summary: 'Details.' });
    const b = await mkItem(store, src.id, { title: 'Second story', summary: 'More.' });
    await mkCluster(store, a.id);
    await mkCluster(store, b.id);

    const first = fakeEmbedder();
    const r1 = await embedPending(store, { embedFn: first.fn, model: MODEL });
    assert.strictEqual(r1.pending, 2);
    assert.strictEqual(r1.written, 2);
    assert.strictEqual(first.calls.length, 2);
    assert.match(first.calls.join('\n'), /Ransomware hits a hospital/);

    // Second run: everything is cached, so the model is never called again.
    const second = fakeEmbedder();
    const r2 = await embedPending(store, { embedFn: second.fn, model: MODEL });
    assert.strictEqual(r2.pending, 0);
    assert.strictEqual(second.calls.length, 0);

    const rows = await store.all('SELECT item_id, model FROM item_embeddings ORDER BY item_id');
    assert.strictEqual(rows.length, 2);
    assert.ok(rows.every((r) => r.model === MODEL));
  });
});

// Absence over fabrication: nothing is written, and the item stays pending for the next pass.
test('a failed embedding writes no row and is retried on the next run', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    await mkCluster(store, a.id);

    const failing = fakeEmbedder(() => null);
    const r1 = await embedPending(store, { embedFn: failing.fn, model: MODEL });
    assert.strictEqual(r1.written, 0);
    assert.strictEqual(r1.failed, 1);
    assert.strictEqual((await store.all('SELECT 1 FROM item_embeddings')).length, 0);

    const working = fakeEmbedder();
    const r2 = await embedPending(store, { embedFn: working.fn, model: MODEL });
    assert.strictEqual(r2.pending, 1, 'still pending after the failure');
    assert.strictEqual(r2.written, 1);
  });
});

// The embedding cache is keyed on item_id precisely so it survives rebuildClusters()'s
// DELETE + reinsert, which regenerates every cluster id on every consolidation.
test('embeddings survive a full cluster rebuild', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    const cluster = await mkCluster(store, a.id);

    const first = fakeEmbedder();
    await embedPending(store, { embedFn: first.fn, model: MODEL });

    // Simulate rebuildClusters(): every cluster row is deleted and reinserted with a new id.
    await store.run('DELETE FROM clusters');
    const rebuilt = await mkCluster(store, a.id);
    assert.notStrictEqual(rebuilt.id, cluster.id, 'the rebuild must produce a new cluster id');

    const second = fakeEmbedder();
    const r = await embedPending(store, { embedFn: second.fn, model: MODEL });
    assert.strictEqual(second.calls.length, 0, 'the cached vector must be reused');
    assert.strictEqual(r.pending, 0);
  });
});

// Vectors from different models have different dimensionality and different geometry.
test('changing the embedding model re-embeds rather than mixing vectors', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    await mkCluster(store, a.id);

    await embedPending(store, { embedFn: fakeEmbedder().fn, model: MODEL });
    const other = fakeEmbedder(() => [1, 0, 0, 0]);
    const r = await embedPending(store, { embedFn: other.fn, model: 'other-model' });
    assert.strictEqual(r.pending, 1);
    assert.strictEqual(other.calls.length, 1);

    const row = await store.get('SELECT model, embedding FROM item_embeddings WHERE item_id=$1', [a.id]);
    assert.strictEqual(row.model, 'other-model');
    assert.strictEqual(toVector(row.embedding).length, 4);
  });
});

test('rebuildLinks writes one canonical row per similar pair', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id, { title: 'story a' });
    const b = await mkItem(store, src.id, { title: 'story b' });
    const c = await mkItem(store, src.id, { title: 'story c' });
    const ca = await mkCluster(store, a.id);
    const cb = await mkCluster(store, b.id);
    await mkCluster(store, c.id);

    // a and b identical; c orthogonal to both.
    const vectors = new Map([['story a', [1, 0]], ['story b', [1, 0]], ['story c', [0, 1]]]);
    const embedder = fakeEmbedder((text) => vectors.get(text.trim()));
    await embedPending(store, { embedFn: embedder.fn, model: MODEL });

    const res = await rebuildLinks(store, { model: MODEL, threshold: 0.9 });
    assert.strictEqual(res.embedded, 3);
    assert.strictEqual(res.links, 1);

    const rows = await store.all('SELECT cluster_a_id, cluster_b_id, similarity, model FROM story_links');
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].cluster_a_id, Math.min(ca.id, cb.id));
    assert.strictEqual(rows[0].cluster_b_id, Math.max(ca.id, cb.id));
    assert.ok(rows[0].similarity > 0.99);
    assert.strictEqual(rows[0].model, MODEL);
  });
});

test('rebuildLinks is a full replace, so a link that no longer qualifies disappears', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id, { title: 'story a' });
    const b = await mkItem(store, src.id, { title: 'story b' });
    await mkCluster(store, a.id);
    await mkCluster(store, b.id);

    await embedPending(store, { embedFn: fakeEmbedder().fn, model: MODEL });
    await rebuildLinks(store, { model: MODEL, threshold: 0.9 });
    assert.strictEqual((await store.all('SELECT 1 FROM story_links')).length, 1);

    // Raise the bar above what these vectors can reach: the stale row must be gone.
    await rebuildLinks(store, { model: MODEL, threshold: 1.5 });
    assert.strictEqual((await store.all('SELECT 1 FROM story_links')).length, 0);
  });
});

test('clusters outside the window are neither embedded nor linked', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id, { title: 'a recent story' });
    const b = await mkItem(store, src.id, { title: 'an ancient story' });
    await mkCluster(store, a.id);
    await mkCluster(store, b.id, { firstSeen: '2020-01-01T00:00:00Z' });

    const embedder = fakeEmbedder();
    const r = await embedPending(store, { embedFn: embedder.fn, model: MODEL });
    assert.strictEqual(r.considered, 1);
    assert.strictEqual(embedder.calls.length, 1);
    assert.match(embedder.calls[0], /a recent story/);

    const res = await rebuildLinks(store, { model: MODEL, threshold: 0.9 });
    assert.strictEqual(res.links, 0);
  });
});

// An undated cluster cannot answer "related within 72h", and there are ~1,600 of them in the
// live corpus — they would dominate the graph.
test('clusters with no first_seen are excluded from the batch', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    await store.run('INSERT INTO clusters (primary_item_id, title, first_seen, source_count) VALUES ($1,$2,NULL,1)', [a.id, 'undated']);

    const embedder = fakeEmbedder();
    const r = await embedPending(store, { embedFn: embedder.fn, model: MODEL });
    assert.strictEqual(r.considered, 0);
    assert.strictEqual(embedder.calls.length, 0);
  });
});

// Bulk feed rows share a title template, so an embedding compares string shape rather than
// meaning: bare CVE ids pair at 0.99 and "Malicious vscode package: <name>" rows at 0.85, which
// swamped every real story in the measured window.
test('bulk indicator categories are never embedded or linked', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    for (const [category, title] of [
      ['cve', 'CVE-2026-17348 in some product'],
      ['ioc', 'Attacking IP: 185.81.68.110'],
      ['phishing', 'phishing url observed'],
      ['ransomware', 'Buck Knives (thegentlemen)'],
    ]) {
      const item = await mkItem(store, src.id, { category, title });
      await mkCluster(store, item.id);
    }

    const embedder = fakeEmbedder();
    const r = await embedPending(store, { embedFn: embedder.fn, model: MODEL });
    assert.strictEqual(r.considered, 0);
    assert.strictEqual(embedder.calls.length, 0);
  });
});

// A bare identifier carries no meaning to compare — "CVE-2024-23897" and "CVE-2024-21887"
// embed to a cosine of 0.998 purely because the strings look alike.
test('bare-identifier titles are excluded even in a linkable category', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    for (const title of ['CVE-2026-17348', 'CVE-2026-17566', 'EUVD-2026-51920']) {
      const item = await mkItem(store, src.id, { category: 'advisory', title });
      await mkCluster(store, item.id);
    }
    // Same category, but a real headline: this one is in scope.
    const prose = await mkItem(store, src.id, { category: 'advisory', title: 'USN-8620-3: Linux kernel vulnerabilities' });
    await mkCluster(store, prose.id);

    const embedder = fakeEmbedder();
    const r = await embedPending(store, { embedFn: embedder.fn, model: MODEL });
    assert.strictEqual(r.considered, 1);
    assert.strictEqual(embedder.calls.length, 1);
    assert.match(embedder.calls[0], /USN-8620-3/);
  });
});

test('linkStories runs both phases and reports what each did', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id, { title: 'story a' });
    const b = await mkItem(store, src.id, { title: 'story b' });
    await mkCluster(store, a.id);
    await mkCluster(store, b.id);

    const res = await linkStories(store, { embedFn: fakeEmbedder().fn, model: MODEL, threshold: 0.9 });
    assert.deepStrictEqual(res, { embedded: 2, links: 1, embeddedNow: 2, embedFailed: 0 });
  });
});

test('story_links rows disappear with their cluster', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    const b = await mkItem(store, src.id);
    await mkCluster(store, a.id);
    await mkCluster(store, b.id);
    await linkStories(store, { embedFn: fakeEmbedder().fn, model: MODEL, threshold: 0.9 });

    await store.run('DELETE FROM clusters');
    assert.strictEqual((await store.all('SELECT 1 FROM story_links')).length, 0);
    // The embeddings, keyed on items, are untouched.
    assert.strictEqual((await store.all('SELECT 1 FROM item_embeddings')).length, 2);
  });
});

// The CHECK constraint is the guarantee, not the ordering convention in linkCandidates.
test('the schema refuses a reversed or self-referential pair', async () => {
  await withTestStore(async (store) => {
    const src = await mkSource(store);
    const a = await mkItem(store, src.id);
    const b = await mkItem(store, src.id);
    const ca = await mkCluster(store, a.id);
    const cb = await mkCluster(store, b.id);
    const [lo, hi] = [Math.min(ca.id, cb.id), Math.max(ca.id, cb.id)];

    await assert.rejects(() => store.run(
      'INSERT INTO story_links (cluster_a_id, cluster_b_id, similarity, model) VALUES ($1,$2,0.9,$3)', [hi, lo, MODEL]));
    await assert.rejects(() => store.run(
      'INSERT INTO story_links (cluster_a_id, cluster_b_id, similarity, model) VALUES ($1,$1,0.9,$2)', [lo, MODEL]));
  });
});

test('embedText joins title and summary and bounds the length', () => {
  assert.strictEqual(embedText({ title: 'T', summary: 'S' }), 'T\nS');
  assert.strictEqual(embedText({ title: 'T', summary: null }), 'T');
  assert.strictEqual(embedText({ title: null, summary: null }), '');
  assert.ok(embedText({ title: 'x'.repeat(5000), summary: 'y' }).length <= 2000);
});

test('toVector accepts a driver array or a Postgres array literal', () => {
  assert.deepStrictEqual(toVector([1, 2.5, -3]), [1, 2.5, -3]);
  assert.deepStrictEqual(toVector('{1,2.5,-3}'), [1, 2.5, -3]);
  assert.deepStrictEqual(toVector(null), []);
  assert.deepStrictEqual(toVector('nonsense'), []);
});
