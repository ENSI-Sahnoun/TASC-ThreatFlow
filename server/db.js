const { createStore } = require('./store');

// Default application store (DATABASE_URL or the local dev Postgres). Tests build their
// own isolated stores via test-helpers instead of using this singleton.
const store = createStore();

// Idempotent schema. Postgres enforces foreign keys unconditionally, so the ON DELETE
// CASCADE chain (sources -> items -> item_* children) is always live; there is no
// pragma to toggle and no orphan-sweep needed as there was under SQLite.
async function applySchema(s = store) {
  await s.run(`
    CREATE TABLE IF NOT EXISTS sources (
      id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      category TEXT,
      conn_type TEXT,
      fetch_kind TEXT NOT NULL,
      url TEXT,
      tier TEXT,
      notes TEXT,
      auth_required TEXT,
      api_key TEXT,
      active BOOLEAN NOT NULL DEFAULT false,
      is_custom BOOLEAN NOT NULL DEFAULT false,
      last_synced_at TIMESTAMPTZ,
      last_status TEXT,
      request_method TEXT NOT NULL DEFAULT 'GET',
      request_body TEXT,
      api_key_header TEXT NOT NULL DEFAULT 'Authorization',
      cve_field TEXT,
      cvss_field TEXT,
      severity_field TEXT,
      vendor_field TEXT,
      detected_mapping_json TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS items (
      id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      source_id INT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      title TEXT,
      summary TEXT,
      author TEXT,
      link TEXT,
      published_at TIMESTAMPTZ,
      fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      external_id TEXT,
      raw_json TEXT,
      severity TEXT,
      cvss_score DOUBLE PRECISION,
      cvss_version TEXT,
      epss_score DOUBLE PRECISION,
      exploitation_status TEXT,
      vendor TEXT,
      region TEXT,
      industry TEXT,
      confidence DOUBLE PRECISION,
      threat_type TEXT,
      canonical_id INT,
      UNIQUE(source_id, external_id)
    );

    CREATE INDEX IF NOT EXISTS idx_items_source ON items(source_id);
    CREATE INDEX IF NOT EXISTS idx_items_category ON items(category);

    CREATE TABLE IF NOT EXISTS item_cves (item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE, cve_id TEXT NOT NULL, UNIQUE(item_id, cve_id));
    CREATE INDEX IF NOT EXISTS idx_item_cves_cve ON item_cves(cve_id);
    CREATE TABLE IF NOT EXISTS item_iocs (item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE, ioc_type TEXT NOT NULL, ioc_value TEXT NOT NULL, UNIQUE(item_id, ioc_type, ioc_value));
    CREATE INDEX IF NOT EXISTS idx_item_iocs_value ON item_iocs(ioc_value);
    CREATE TABLE IF NOT EXISTS item_actors (item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE, actor TEXT NOT NULL, UNIQUE(item_id, actor));
    CREATE TABLE IF NOT EXISTS item_malware_families (item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE, family TEXT NOT NULL, UNIQUE(item_id, family));
    CREATE TABLE IF NOT EXISTS item_domains (item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE, domain TEXT NOT NULL, UNIQUE(item_id, domain));
    CREATE INDEX IF NOT EXISTS idx_item_domains_domain ON item_domains(domain);

    CREATE TABLE IF NOT EXISTS item_cpes (
      item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      part    TEXT NOT NULL,
      vendor  TEXT NOT NULL,
      product TEXT NOT NULL,
      UNIQUE(item_id, part, vendor, product)
    );
    CREATE INDEX IF NOT EXISTS idx_item_cpes_vendor  ON item_cpes(vendor);
    CREATE INDEX IF NOT EXISTS idx_item_cpes_product ON item_cpes(product);

    -- Profiles are personas, not accounts: no password, no session, no boundary between them.
    -- The loopback bind below is what keeps the unauthenticated API safe.
    CREATE TABLE IF NOT EXISTS profiles (
      id              INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name            TEXT NOT NULL UNIQUE,
      sector          TEXT NOT NULL,
      vendors         TEXT[] NOT NULL DEFAULT '{}',
      products        TEXT[] NOT NULL DEFAULT '{}',
      threat_domains  TEXT[] NOT NULL DEFAULT '{}',
      region          TEXT,
      severity_floor  TEXT NOT NULL DEFAULT 'medium',
      profile_version INT NOT NULL DEFAULT 1,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS ip_intel (
      ip TEXT PRIMARY KEY,
      ports_json TEXT,
      vulns_json TEXT,
      tags_json TEXT,
      cpes_json TEXT,
      hostnames_json TEXT,
      org TEXT,
      isp TEXT,
      city TEXT,
      country_code TEXT,
      source TEXT NOT NULL DEFAULT 'internetdb',
      fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS cve_intel (
      cve_id       TEXT PRIMARY KEY,
      cvss_score   DOUBLE PRECISION,
      cvss_source  TEXT,
      severity     TEXT NOT NULL DEFAULT 'unknown',
      epss_score   DOUBLE PRECISION,
      kev_listed   BOOLEAN NOT NULL DEFAULT false,
      kev_added_at TIMESTAMPTZ,
      description  TEXT,
      first_seen   TIMESTAMPTZ,
      last_seen    TIMESTAMPTZ,
      source_count INT NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_cve_intel_severity ON cve_intel(severity);
    CREATE INDEX IF NOT EXISTS idx_cve_intel_kev ON cve_intel(kev_listed);

    CREATE TABLE IF NOT EXISTS cve_sources (
      cve_id     TEXT NOT NULL REFERENCES cve_intel(cve_id) ON DELETE CASCADE,
      item_id    INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      source_id  INT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
      cvss_score DOUBLE PRECISION,
      severity   TEXT,
      UNIQUE(cve_id, item_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cve_sources_cve ON cve_sources(cve_id);

    CREATE TABLE IF NOT EXISTS clusters (
      id              INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      primary_item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      title           TEXT NOT NULL,
      first_seen      TIMESTAMPTZ,
      last_seen       TIMESTAMPTZ,
      source_count    INT NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS cluster_items (
      cluster_id INT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
      item_id    INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      UNIQUE(item_id)
    );

    CREATE TABLE IF NOT EXISTS source_syncs (
      id          INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      source_id   INT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
      started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      finished_at TIMESTAMPTZ,
      status      TEXT NOT NULL,
      items_new   INT NOT NULL DEFAULT 0,
      items_total INT NOT NULL DEFAULT 0,
      error       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_source_syncs_source ON source_syncs(source_id, started_at DESC);

    -- CREATE TABLE IF NOT EXISTS never alters an existing table, so the column needs this too.
    ALTER TABLE items ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION;
    ALTER TABLE items ADD COLUMN IF NOT EXISTS cvss_version TEXT;
  `);
}

module.exports = store;
module.exports.applySchema = applySchema;
