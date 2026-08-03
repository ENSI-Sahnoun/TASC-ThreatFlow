const { syncSource, loadKevCveSet } = require('./fetchers');
const { consolidate } = require('./consolidate');
const { linkStories } = require('./story_links_batch');

// Sequential sync over many sources at 15-20s timeout each could take minutes; bounded
// concurrency (mirrors POST /api/sources/sync-all) keeps a scheduled tick fast.
const SYNC_CONCURRENCY = 8;
const MINUTE_MS = 60_000;
const DAY_MS = 24 * 60 * 60 * 1000;

async function syncMany(store, sources, configByName) {
  const kevCveSet = await loadKevCveSet(store);
  const results = new Array(sources.length);
  let next = 0;
  async function worker() {
    while (next < sources.length) {
      const i = next;
      next += 1;
      const source = sources[i];
      const result = await syncSource(source, { store, kevCveSet, configByName });
      results[i] = { id: source.id, name: source.name, ...result };
    }
  }
  await Promise.all(Array.from({ length: Math.min(SYNC_CONCURRENCY, sources.length) }, worker));
  return results;
}

// Runs the every-minute pass over every active source except Vulnetix, and a once-a-day pass
// over Vulnetix alone. Vulnetix is split out because its API 429s under the cadence the other
// 42 sources tolerate fine (see removed-sources-backup.csv history) — a shared per-tick "still
// running" guard keeps a slow tick from overlapping the next timer fire rather than piling up
// concurrent syncs against the same sources.
// Story links have to be rebuilt on every consolidation, not only after a manual sync-all:
// rebuildClusters() deletes and reinserts every cluster row, so the previous run's links were
// cascade-deleted with the ids they referenced. The embeddings themselves are cached against
// item ids and survive, so a tick that finds no new prose story calls the model zero times.
//
// Awaited but never allowed to throw — this is the only part of a scheduled tick that needs
// Ollama, and an unreachable model must cost suggestion links and nothing else.
async function linkStoriesQuietly(store) {
  try {
    await linkStories(store);
  } catch (err) {
    console.error('story linking failed:', err.message);
  }
}

function startScheduler(store, configByName) {
  let minuteRunning = false;
  let dailyRunning = false;

  async function runMinuteSync() {
    if (minuteRunning) return;
    minuteRunning = true;
    try {
      const sources = await store.all("SELECT * FROM sources WHERE active = true AND fetch_kind != 'vulnetix'");
      await syncMany(store, sources, configByName);
      await consolidate(store);
      await linkStoriesQuietly(store);
    } catch (err) {
      console.error('scheduled sync failed:', err);
    } finally {
      minuteRunning = false;
    }
  }

  async function runVulnetixSync() {
    if (dailyRunning) return;
    dailyRunning = true;
    try {
      const sources = await store.all("SELECT * FROM sources WHERE active = true AND fetch_kind = 'vulnetix'");
      if (sources.length) {
        await syncMany(store, sources, configByName);
        await consolidate(store);
        await linkStoriesQuietly(store);
      }
    } catch (err) {
      console.error('scheduled Vulnetix sync failed:', err);
    } finally {
      dailyRunning = false;
    }
  }

  runMinuteSync();
  runVulnetixSync();
  const minuteTimer = setInterval(runMinuteSync, MINUTE_MS);
  const dailyTimer = setInterval(runVulnetixSync, DAY_MS);

  return () => {
    clearInterval(minuteTimer);
    clearInterval(dailyTimer);
  };
}

module.exports = { startScheduler };
