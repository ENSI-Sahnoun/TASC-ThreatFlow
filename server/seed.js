const appStore = require('./db');
const { SOURCES } = require('./sources.config');

async function seedFromConfig(store = appStore) {
  const existing = new Set((await store.all('SELECT name FROM sources')).map((r) => r.name));
  const toInsert = SOURCES.filter((s) => !existing.has(s.name));
  await store.tx(async (t) => {
    for (const s of toInsert) {
      await t.run(
        `INSERT INTO sources (name, category, conn_type, fetch_kind, url, tier, notes, auth_required, request_body, active, is_custom)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)`,
        [
          s.name,
          s.category || null,
          s.kind,
          s.kind,
          s.url || null,
          s.tier || null,
          s.auth ? `NEEDS KEY: set env ${s.auth.env}` : null,
          s.auth ? s.auth.env : null,
          s.requestBody || null,
          !!s.active,
        ]
      );
    }
  });
  const total = (await store.get('SELECT COUNT(*)::int AS c FROM sources')).c;
  return { inserted: toInsert.length, total };
}

function configByName() {
  const map = {};
  for (const s of SOURCES) map[s.name] = s;
  return map;
}

module.exports = { seedFromConfig, configByName };
