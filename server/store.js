// Thin async data-access layer over node-postgres. Every DB call in the app goes through
// a store's all()/get()/run()/tx() — there is no synchronous DB path (unlike the former
// better-sqlite3 layer), so all callers await. Placeholders are Postgres-style ($1, $2).
const { Pool } = require('pg');

const DEFAULT_URL = 'postgres://postgres:postgres@127.0.0.1:55432/threatflow';

function makeApi(exec) {
  return {
    // rows
    async all(sql, params = []) { return (await exec(sql, params)).rows; },
    // first row or undefined
    async get(sql, params = []) { return (await exec(sql, params)).rows[0]; },
    // full pg result ({ rows, rowCount })
    async run(sql, params = []) { return exec(sql, params); },
  };
}

function createStore(connectionString = process.env.DATABASE_URL || DEFAULT_URL) {
  // max bumped above the default 10 so the bounded-concurrency sync-all (8 workers, each
  // holding a client for its transaction) plus incidental queries never starve the pool.
  const pool = new Pool({ connectionString, max: 20 });
  const base = makeApi((sql, params) => pool.query(sql, params));

  // Runs fn against a single pooled client wrapped in BEGIN/COMMIT (ROLLBACK on throw).
  async function tx(fn) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(makeApi((sql, params) => client.query(sql, params)));
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* connection already broken */ }
      throw err;
    } finally {
      client.release();
    }
  }

  return { ...base, tx, pool, connectionString, close: () => pool.end() };
}

module.exports = { createStore, DEFAULT_URL };
