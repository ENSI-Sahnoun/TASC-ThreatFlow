const { Client } = require('pg');
const { createStore, DEFAULT_URL } = require('./store');
const { applySchema } = require('./db');

// Maintenance connection target — the base dev database. CREATE/DROP DATABASE run against
// it while connected (you can create another database from any connection).
const ADMIN_URL = process.env.DATABASE_URL || DEFAULT_URL;

let counter = 0;

function urlWithDb(base, dbName) {
  const u = new URL(base);
  u.pathname = `/${dbName}`;
  return u.toString();
}

async function admin(sql) {
  const client = new Client({ connectionString: ADMIN_URL });
  await client.connect();
  try { await client.query(sql); } finally { await client.end(); }
}

// Creates a throwaway Postgres database with the full schema and returns a store bound to
// it. cleanup() closes the pool and drops the database. Each call is fully isolated, so
// tests never share state (the Postgres analog of the former per-test SQLite temp file).
async function makeTempDb() {
  counter += 1;
  const dbName = `threatflow_test_${process.pid}_${counter}`;
  await admin(`CREATE DATABASE ${dbName}`);
  const store = createStore(urlWithDb(ADMIN_URL, dbName));
  await applySchema(store);
  return {
    store,
    async cleanup() {
      await store.close();
      // FORCE (PG13+) terminates any lingering backends so the drop can't hang.
      await admin(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    },
  };
}

module.exports = { makeTempDb };
