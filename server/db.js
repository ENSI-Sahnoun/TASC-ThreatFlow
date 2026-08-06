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

    -- CWE (weakness type). NVD's own weaknesses[] field, sitting unused in items.raw_json since
    -- the first sync -- server/cwe.js:cwesFromRaw extracts it. Same shape as item_cpes/
    -- item_actors: a child table, ON DELETE CASCADE, indexed on the lookup column for the
    -- eventual CWE -> CAPEC -> ATT&CK-technique join (a separate, not-yet-designed spec).
    CREATE TABLE IF NOT EXISTS item_cwes (
      item_id INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      cwe_id  TEXT NOT NULL,
      PRIMARY KEY (item_id, cwe_id)
    );
    CREATE INDEX IF NOT EXISTS idx_item_cwes_cwe_id ON item_cwes(cwe_id);

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

    -- Precise tech-stack rows. profiles.vendors/products are retained for backward
    -- compatibility and keep feeding the low tier; only a profile_assets row can earn
    -- act_now, because a vendor-level claim ("we use Microsoft software") is not evidence of
    -- exposure to a specific flaw. 'microsoft' matches 7519 item_cpes rows.
    --
    -- exposure is the crossing that turns a CVSS vector into a statement about the reader:
    -- AV:N alone is a property of the flaw, AV:N on an internet-facing asset is personal.
    -- It defaults to 'unknown', never 'internal' — assuming an unanswered question is safe
    -- would silently demote an actively-exploited flaw.
    CREATE TABLE IF NOT EXISTS profile_assets (
      profile_id INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      vendor     TEXT NOT NULL,
      product    TEXT NOT NULL,
      exposure   TEXT NOT NULL DEFAULT 'unknown'
                 CHECK (exposure IN ('internet','internal','unknown')),
      UNIQUE(profile_id, vendor, product)
    );
    CREATE INDEX IF NOT EXISTS idx_profile_assets_product ON profile_assets(vendor, product);

    -- The version a reader told us they run on this asset, and whether they were ever asked.
    -- Three states, not a nullable string, so a declined question ('unknown') is distinguishable
    -- from a question never asked ('unset') — collapsing them would make the remediation page
    -- re-nag on every visit. Never inferred: a missing answer is recorded as missing, the same
    -- rule 'exposure' already applies by defaulting to 'unknown' rather than to 'internal'.
    ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version TEXT;
    ALTER TABLE profile_assets ADD COLUMN IF NOT EXISTS version_state TEXT NOT NULL DEFAULT 'unset'
      CHECK (version_state IN ('unset','known','unknown'));

    -- A self-report ("I clicked this") from the Check URL page. Undoable by design (DELETE the
    -- row) — same posture as every other signal in this app: relevance is fully re-derived from
    -- current facts on every recompute, never a one-way ratchet.
    CREATE TABLE IF NOT EXISTS profile_reported_clicks (
      profile_id  INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      item_id     INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (profile_id, item_id)
    );

    -- Materialized because sorting 24k rows by tier has to happen in SQL — a page cannot be
    -- sorted by a value that has not been computed. Keyed by profile_version so a profile edit
    -- invalidates verdicts; superseded versions are left orphaned rather than deleted, so
    -- reverting an edit re-exposes the cached set instantly.
    CREATE TABLE IF NOT EXISTS item_relevance (
      profile_id      INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      item_id         INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      profile_version INT NOT NULL,
      tier            TEXT NOT NULL CHECK (tier IN ('act_now','watch','low','not_yours')),
      score           DOUBLE PRECISION NOT NULL,
      matches         JSONB NOT NULL,
      computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (profile_id, item_id, profile_version)
    );
    CREATE INDEX IF NOT EXISTS idx_item_relevance_sort
      ON item_relevance(profile_id, profile_version, tier, score DESC);

    -- Model-written prose lives in its own table, never as a column on item_relevance. The
    -- separation is the guardrail: there is no tier column here, so a bad model output is
    -- structurally incapable of changing a verdict. It can only change wording.
    -- Model-assigned signal quality. Its own table, read only by the presentation layer: the
    -- deterministic pipeline never consults it, and the UI demotes rather than deletes, so a
    -- misclassification costs an item its ranking and never its existence.
    CREATE TABLE IF NOT EXISTS item_quality (
      item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      verdict     TEXT NOT NULL CHECK (verdict IN ('intel','roundup','commentary','promotion')),
      model       TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_item_quality_verdict ON item_quality(verdict);

    -- Model-derived enrichment. Each lives in its own table and NOTHING in the deterministic
    -- pipeline reads them: items.severity, items.industry and items.summary keep whatever the
    -- upstream source actually said, so a model guess can never be mistaken for vendor data or
    -- feed confidence/consolidation scoring. A row's existence means "checked"; its columns may
    -- still be NULL, which means "checked and found nothing" rather than "not looked at".
    CREATE TABLE IF NOT EXISTS item_severity_ml (
      item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      severity    TEXT,
      model       TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS item_summary_ml (
      item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      summary     TEXT,
      model       TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS item_victim_ml (
      item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      sector      TEXT,
      region      TEXT,
      model       TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS item_relevance_prose (
      profile_id      INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      item_id         INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      profile_version INT NOT NULL,
      sentence        TEXT NOT NULL,
      model           TEXT NOT NULL,
      computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (profile_id, item_id, profile_version)
    );

    -- The generated skeleton. Keyed by profile_version like item_relevance, for the same
    -- reason: a profile edit can change which steps apply (exposure changes whether "restrict
    -- access" is relevant), so the cached skeleton must invalidate with it. Disposable — a
    -- superseded version is left orphaned rather than deleted, same as item_relevance.
    CREATE TABLE IF NOT EXISTS item_playbooks (
      profile_id      INT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      item_id         INT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      profile_version INT NOT NULL,
      steps           JSONB NOT NULL,
      worded_by       TEXT,
      computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (profile_id, item_id, profile_version)
    );

    -- What the user ticked. Deliberately NOT keyed by profile_version: "I applied the patch" is
    -- a statement about the real world, and editing an unrelated profile field must not un-tick
    -- it. step_key is a stable identifier ('confirm', 'patch', 'restrict', ...), not a
    -- position, so a step that disappears and later returns finds its tick waiting.
    CREATE TABLE IF NOT EXISTS playbook_step_state (
      profile_id INT  NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      item_id    INT  NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      step_key   TEXT NOT NULL,
      done_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (profile_id, item_id, step_key)
    );

    -- MITRE's own STIX data, matched and ranked by server/backfill-attack.js. Replaces the old
    -- hand-typed data/attack-mitigations.json entirely -- a newly-named group now gets real
    -- coverage instead of waiting for a manual edit. subject_type disambiguates a name that
    -- appears in both data/threat-actors.json and data/malware-families.json (e.g. LockBit is
    -- both an actor and, separately, ransomware tooling) -- same name, potentially different
    -- STIX object, potentially different technique set. DELETE + reinsert on every backfill
    -- run, same rebuild-not-merge posture as rebuildClusters().
    CREATE TABLE IF NOT EXISTS attack_mitigations (
      subject_type    TEXT NOT NULL,
      subject_name    TEXT NOT NULL,
      mitigation_id   TEXT NOT NULL,
      mitigation_name TEXT NOT NULL,
      mitigation_url  TEXT NOT NULL,
      technique_count INT NOT NULL,
      synced_at       TIMESTAMPTZ NOT NULL,
      PRIMARY KEY (subject_type, subject_name, mitigation_id)
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
      -- CISA's remediation deadline. The only externally-set date in the corpus: every other
      -- urgency signal here is derived, this one is stated by the authority that set it.
      kev_due_date DATE,
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

    -- Embedding cache for semantic story linking. Keyed on item_id, NOT cluster id, because
    -- rebuildClusters() does a full DELETE + reinsert on every consolidation: cluster ids are
    -- regenerated each run, so an embedding stored against one would be discarded every sync and
    -- re-paid for on the next. Item ids are stable, so this cache survives.
    --
    -- \`model\` is not decoration. Embeddings from different models are not comparable — they have
    -- different dimensionality (mxbai-embed-large is 1024, nomic-embed-text is 768) and different
    -- geometry even at equal size — so the batch job only ever compares vectors sharing a model.
    CREATE TABLE IF NOT EXISTS item_embeddings (
      item_id     INT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      embedding   DOUBLE PRECISION[] NOT NULL,
      model       TEXT NOT NULL,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- Model-derived "possibly related story" edges. Deliberately NOT part of clusters/
    -- cluster_items: applyConfidence() derives an item's corroboration bonus from
    -- clusters.source_count, so a wrong similarity edge here can never inflate confidence. It
    -- can only add a suggestion link in the UI.
    --
    -- cluster_a_id < cluster_b_id gives one canonical row per pair, enforced rather than
    -- convention, so no reverse-duplicate can be inserted.
    CREATE TABLE IF NOT EXISTS story_links (
      cluster_a_id INT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
      cluster_b_id INT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
      similarity   DOUBLE PRECISION NOT NULL,
      model        TEXT NOT NULL,
      computed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (cluster_a_id < cluster_b_id),
      UNIQUE(cluster_a_id, cluster_b_id)
    );
    CREATE INDEX IF NOT EXISTS idx_story_links_a ON story_links(cluster_a_id);
    CREATE INDEX IF NOT EXISTS idx_story_links_b ON story_links(cluster_b_id);

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
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS kev_due_date DATE;
    -- CISA's own remediation text and its ransomware flag. requiredAction is usually
    -- boilerplate ("Apply mitigations per vendor instructions...") — kept as a citation, not
    -- as step body text. knownRansomwareCampaignUse is the opposite: concrete, binary, and
    -- worth its own playbook step when true.
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS kev_required_action TEXT;
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS kev_ransomware BOOLEAN NOT NULL DEFAULT false;
    -- Lifted from the NVD record's own references[], tagged 'Patch' / 'Vendor Advisory' by NVD
    -- itself. A playbook step never invents a fix location; these are the only two it may cite.
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS patch_url TEXT;
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS advisory_url TEXT;
    -- Per-product version ranges lifted from the real NVD row's CPE match data (parseCpe/
    -- affectedVersionsFrom in consolidate.js). [{vendor, product, text, startIncluding,
    -- startExcluding, endIncluding, endExcluding, pinned}] — 'text' is the rendered sentence,
    -- the rest are NVD's own bound fields kept comparable for code. Empty array, not null, when
    -- the CVE has no parseable version data — see affectedVersionsFrom's own doc comment.
    ALTER TABLE cve_intel ADD COLUMN IF NOT EXISTS affected_versions JSONB;
    ALTER TABLE items ADD COLUMN IF NOT EXISTS cvss_vector TEXT;
    -- Deterministic consequence slots, materialized by the same pure pass that writes tier.
    -- Nullable: rows written before this column existed carry NULL until the next recompute.
    ALTER TABLE item_relevance ADD COLUMN IF NOT EXISTS consequence JSONB;

    -- One-time migration per profile, expressed idempotently so a re-apply is a no-op. Every
    -- profile created before profile_assets existed keeps its act_now lane: its products[]
    -- entries become assets at 'unknown' exposure, which the ladder still allows to reach
    -- act_now. The vendor is recovered by joining item_cpes; a slug appearing under several
    -- vendors yields one row per vendor, because the profile never recorded which it meant,
    -- and a slug matching nothing is skipped.
    --
    -- The NOT EXISTS guard is what makes this a migration rather than a policy: without it,
    -- every boot would reinstate an asset the user had deliberately deleted. The residual
    -- edge case is a profile whose assets are ALL removed while products[] still lists them —
    -- that one reseeds on the next boot. Clearing products[] alongside is the fix, and the
    -- profile editor does exactly that.
    INSERT INTO profile_assets (profile_id, vendor, product, exposure)
    SELECT DISTINCT p.id, c.vendor, c.product, 'unknown'
      FROM profiles p
      JOIN LATERAL unnest(p.products) AS prod(slug) ON true
      JOIN item_cpes c ON c.product = prod.slug
     WHERE NOT EXISTS (SELECT 1 FROM profile_assets pa WHERE pa.profile_id = p.id)
    ON CONFLICT (profile_id, vendor, product) DO NOTHING;
  `);
}

module.exports = store;
module.exports.applySchema = applySchema;
