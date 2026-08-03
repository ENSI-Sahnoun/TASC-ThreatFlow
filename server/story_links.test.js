const test = require('node:test');
const assert = require('node:assert');
const { cosineSimilarity, linkCandidates, similarityLabel, SIMILARITY_THRESHOLD } = require('./story_links');
const { WINDOW_MS } = require('./cluster');

const iso = (msFromEpoch) => new Date(msFromEpoch).toISOString();
const BASE = Date.parse('2026-08-01T00:00:00Z');

test('cosineSimilarity on known vectors', () => {
  assert.strictEqual(cosineSimilarity([1, 0], [1, 0]), 1);
  assert.strictEqual(cosineSimilarity([1, 0], [0, 1]), 0);
  assert.strictEqual(cosineSimilarity([1, 0], [-1, 0]), -1);
  // Magnitude must not matter — only direction.
  assert.strictEqual(cosineSimilarity([3, 0], [7, 0]), 1);
  assert.ok(Math.abs(cosineSimilarity([1, 1], [1, 0]) - Math.SQRT1_2) < 1e-12);
});

// 0 rather than NaN or a throw: NaN compares false against every threshold, which would read as
// "nothing is related" instead of "this input was broken".
test('cosineSimilarity returns 0 for unusable input instead of NaN', () => {
  const cases = [
    [[1, 0], [1, 0, 0]],      // length mismatch
    [[0, 0], [1, 1]],         // zero magnitude
    [[], []],
    [[1, 0], null],
    [null, null],
    [[1, 'x'], [1, 2]],       // non-numeric
    [[1, NaN], [1, 2]],
    [[1, Infinity], [1, 2]],
  ];
  for (const [a, b] of cases) {
    const got = cosineSimilarity(a, b);
    assert.strictEqual(got, 0, `expected 0 for ${JSON.stringify([a, b])}, got ${got}`);
  }
});

test('linkCandidates pairs only clusters at or above the threshold', () => {
  const clusters = [
    { id: 1, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE) },       // identical → 1.0
    { id: 3, embedding: [0, 1], firstSeen: iso(BASE) },       // orthogonal → 0
  ];
  const links = linkCandidates(clusters, { threshold: 0.9 });
  assert.deepStrictEqual(links, [{ clusterAId: 1, clusterBId: 2, similarity: 1 }]);
});

test('linkCandidates emits one canonical row per pair with a < b', () => {
  const clusters = [
    { id: 9, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 4, embedding: [1, 0], firstSeen: iso(BASE) },
  ];
  const links = linkCandidates(clusters, { threshold: 0.5 });
  assert.strictEqual(links.length, 1);
  assert.strictEqual(links[0].clusterAId, 4);
  assert.strictEqual(links[0].clusterBId, 9);
});

test('linkCandidates respects the clustering window', () => {
  const inside = [
    { id: 1, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE + WINDOW_MS - 1000) },
  ];
  const outside = [
    { id: 1, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE + WINDOW_MS + 1000) },
  ];
  assert.strictEqual(linkCandidates(inside, { threshold: 0.5 }).length, 1);
  assert.strictEqual(linkCandidates(outside, { threshold: 0.5 }).length, 0);
});

// Unknown time is not time zero. Treating a null firstSeen as the epoch would place it decades
// from every other cluster and silently drop it.
test('linkCandidates lets a cluster with no timestamp pair on meaning alone', () => {
  const clusters = [
    { id: 1, embedding: [1, 0], firstSeen: null },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE) },
  ];
  assert.strictEqual(linkCandidates(clusters, { threshold: 0.5 }).length, 1);
});

test('linkCandidates skips clusters that have not been embedded yet', () => {
  const clusters = [
    { id: 1, embedding: null, firstSeen: iso(BASE) },
    { id: 2, embedding: [], firstSeen: iso(BASE) },
    { id: 3, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 4, embedding: [1, 0], firstSeen: iso(BASE) },
  ];
  const links = linkCandidates(clusters, { threshold: 0.5 });
  assert.deepStrictEqual(links, [{ clusterAId: 3, clusterBId: 4, similarity: 1 }]);
});

// Vectors of different lengths come from different embedding models and are not comparable.
test('linkCandidates never pairs vectors of different dimensionality', () => {
  const clusters = [
    { id: 1, embedding: [1, 0, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE) },
  ];
  assert.deepStrictEqual(linkCandidates(clusters, { threshold: 0.1 }), []);
});

test('linkCandidates returns the strongest pairs first', () => {
  const clusters = [
    { id: 1, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE) },           // 1.0 with 1
    { id: 3, embedding: [1, 0.5], firstSeen: iso(BASE) },         // ~0.894 with 1 and 2
  ];
  const links = linkCandidates(clusters, { threshold: 0.5, maxPerCluster: 0 });
  assert.strictEqual(links[0].similarity, 1);
  assert.ok(links[0].similarity >= links[1].similarity);
  assert.ok(links[1].similarity >= links[2].similarity);
});

// A generic cluster is mildly close to dozens of others; uncapped it becomes a hub that links
// half the window to itself.
test('linkCandidates caps links per cluster, keeping the strongest', () => {
  // Similarities here: hub-2 and hub-3 are 0.995, hub-4 is 0.816, and every pair among 2/3/4
  // ranks below 0.995 — so with a cap of 2 the hub must keep 2 and 3 and drop 4.
  const clusters = [
    { id: 1, embedding: [1, 0, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0.1, 0], firstSeen: iso(BASE) },
    { id: 3, embedding: [1, 0, 0.1], firstSeen: iso(BASE) },
    { id: 4, embedding: [1, 0.5, 0.5], firstSeen: iso(BASE) },
  ];
  const links = linkCandidates(clusters, { threshold: 0.5, maxPerCluster: 2 });
  const hubLinks = links.filter((l) => l.clusterAId === 1 || l.clusterBId === 1);
  assert.strictEqual(hubLinks.length, 2);
  assert.deepStrictEqual(hubLinks.map((l) => (l.clusterAId === 1 ? l.clusterBId : l.clusterAId)).sort(), [2, 3]);
  // The cap is per cluster, so no cluster anywhere in the result may exceed it.
  const counts = new Map();
  for (const l of links) {
    counts.set(l.clusterAId, (counts.get(l.clusterAId) || 0) + 1);
    counts.set(l.clusterBId, (counts.get(l.clusterBId) || 0) + 1);
  }
  for (const [id, n] of counts) assert.ok(n <= 2, `cluster ${id} kept ${n} links, cap was 2`);
});

test('linkCandidates handles an empty or single-cluster window', () => {
  assert.deepStrictEqual(linkCandidates([]), []);
  assert.deepStrictEqual(linkCandidates(null), []);
  assert.deepStrictEqual(linkCandidates([{ id: 1, embedding: [1, 0], firstSeen: iso(BASE) }]), []);
});

test('the default threshold is the one the module exports', () => {
  const clusters = [
    { id: 1, embedding: [1, 0], firstSeen: iso(BASE) },
    { id: 2, embedding: [1, 0], firstSeen: iso(BASE) },
  ];
  assert.ok(SIMILARITY_THRESHOLD > 0 && SIMILARITY_THRESHOLD <= 1);
  assert.strictEqual(linkCandidates(clusters).length, 1, 'a perfect match must clear the default');
});

test('similarityLabel never exposes a raw float', () => {
  assert.strictEqual(similarityLabel(0.95), 'Likely related');
  assert.strictEqual(similarityLabel(0.9), 'Likely related');
  assert.strictEqual(similarityLabel(0.87), 'Possibly related');
});
