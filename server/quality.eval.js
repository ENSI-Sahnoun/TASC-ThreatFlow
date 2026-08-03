// Reusable measurement harness for server/quality.js. Seeds a throwaway DB from the hand-labeled
// dataset in quality.eval.json, runs the real classifyQuality against it, and reports accuracy
// plus the one number that actually matters for a demote-only feature: how often a genuinely
// real `intel` item got misclassified (conservativeFailures).
const path = require('path');
const { classifyQuality, CLASSIFIED_CATEGORIES } = require('./quality');
const { makeTempDb } = require('./test-helpers');

const DATASET = require(path.join(__dirname, 'quality.eval.json'));

function loadSplit(split) {
  if (!DATASET[split]) throw new Error(`Unknown eval split: ${split}`);
  return DATASET[split];
}

async function runEval(split, opts = {}) {
  const items = loadSplit(split);
  const { store, cleanup } = await makeTempDb();
  try {
    const src = await store.get(
      "INSERT INTO sources (name, fetch_kind, active) VALUES ('eval','rss',true) RETURNING id");

    const byItemId = new Map();
    for (const it of items) {
      const row = await store.get(
        `INSERT INTO items (source_id, category, title, summary, external_id, published_at)
         VALUES ($1, $2, $3, $4, $5, now()) RETURNING id`,
        [src.id, CLASSIFIED_CATEGORIES[0], it.title, it.summary || null, String(it.id)]);
      byItemId.set(row.id, it.verdict);
    }

    await classifyQuality(store, opts);

    const rows = await store.all('SELECT item_id, verdict FROM item_quality');
    const confusion = {};
    let correct = 0;
    let conservativeFailures = 0;

    for (const row of rows) {
      const actual = byItemId.get(row.item_id);
      confusion[actual] = confusion[actual] || {};
      confusion[actual][row.verdict] = (confusion[actual][row.verdict] || 0) + 1;
      if (row.verdict === actual) correct += 1;
      if (actual === 'intel' && row.verdict !== 'intel') conservativeFailures += 1;
    }

    return {
      total: items.length,
      correct,
      accuracy: rows.length ? correct / items.length : 0,
      confusion,
      conservativeFailures,
    };
  } finally {
    await cleanup();
  }
}

module.exports = { runEval, loadSplit };
