export interface Kpi { value: number; delta: number; series: number[]; }

export interface IocCheckMatch {
  itemId: number; title: string | null; category: string; publishedAt: string | null; sourceName: string;
}

export interface IocCheckResult { url: string; found: boolean; matches: IocCheckMatch[]; }

// Verdict from /api/preview-check. `reason` is absent when frameable; 'unreachable' and
// 'http-error' mean we never got as far as reading a framing policy.
export interface PreviewCheck {
  url: string;
  status?: number;
  frameable: boolean;
  reason?: 'x-frame-options' | 'frame-ancestors' | 'unreachable' | 'http-error';
  detail?: string;
}

export interface SourceHealthCounts {
  total: number; ok: number; error: number; unsupported: number; neverSynced: number;
}

export interface DashboardStats {
  total: number;
  generatedAt: string;
  kpis: {
    activelyExploited: Kpi; newIocs24h: Kpi; criticalAdvisories7d: Kpi; sourcesHealthy: Kpi;
  };
  sourceHealth: SourceHealthCounts;
  byCategory: { category: string; count: number }[];
  byDomain: { domain: string; label: string; count: number }[];
  byExploitation: { status: string; count: number }[];
  bySeverity: { severity: string; count: number }[];
  topActors: { actor: string; count: number }[];
  topMalware: { family: string; count: number }[];
  topCves: { cve: string; count: number; maxCvss: number | null; itemId: number }[];
  targetedCountries: { code: string; count: number }[];
  timeline: { bucket: string; count: number }[];
  topSources: { id: number; name: string; item_count: number }[];
}

export interface FeedRow {
  cluster_id: number; title: string; first_seen: string | null; last_seen: string | null;
  source_count: number; item_id: number; category: string; summary: string | null;
  severity: string | null; link: string | null; confidence: number | null;
  source_name: string; source_status: string | null; source_fetch_kind: string;
}

// GET /api/sources returns has_api_key (underscore). GET /api/sources/:id/stats returns a nested
// `source` object with has_apikey (no underscore) instead — the backend is genuinely inconsistent
// between these two endpoints for the same conceptual field. See SourceStats below.
export interface Source {
  id: number; name: string; category: string | null; fetch_kind: string; url: string | null;
  tier: string | null; active: boolean; last_synced_at: string | null; last_status: string | null;
  has_api_key: boolean; item_count: number;
  // Name of the env var this source's key comes from (e.g. "ABUSECH_AUTH_KEY"), or null if the
  // source needs no key. "Needs a key" is `auth_required && !has_api_key` — not a single field.
  auth_required: string | null;
}

export interface SourceStats {
  source: {
    id: number; name: string; category: string | null; fetch_kind: string; url: string | null;
    tier: string | null; active: boolean; last_synced_at: string | null; last_status: string | null;
    has_apikey: boolean; auth_required: string | null; notes: string | null;
  };
  counts: { items: number; cves: number; iocs: number; actors: number; families: number };
  timeline: { bucket: string; count: number }[];
  byCategory: { category: string; count: number }[];
  byDomain: { domain: string; count: number }[];
  bySeverity: { severity: string; count: number }[];
  fieldCoverage: Record<string, number>;
  syncHistory: { started_at: string; finished_at: string | null; status: string; items_new: number; items_total: number; error: string | null }[];
}

export interface Item {
  id: number; source_id: number; category: string; title: string; summary: string | null;
  link: string | null; published_at: string | null; severity: string | null;
  cvss_score: number | null; epss_score: number | null; exploitation_status: string | null; vendor: string | null;
  region: string | null; industry: string | null; confidence: number | null; source_name?: string;
  // Non-primary cluster members (the same story from other sources) are excluded from
  // GET /api/items — cluster_id/source_count on the row that remains let the UI offer to
  // expand the collapsed duplicates via GET /api/clusters/:id/items.
  cluster_id: number | null; source_count: number;
}

export interface ClusterMember {
  item_id: number; title: string; published_at: string | null;
  source_id: number; source_name: string; source_status: string | null;
}

// One InternetDB/Shodan enrichment record, keyed by IP in ItemDetail.ip_intel. Array fields come
// back from decodeIpIntel() as parsed JSON (or null if the stored JSON was empty/unparseable).
export interface IpIntelEntry {
  ip: string;
  ports: number[] | null; vulns: string[] | null; tags: string[] | null;
  cpes: string[] | null; hostnames: string[] | null;
  org: string | null; isp: string | null; city: string | null; country_code: string | null;
  source: string | null; fetched_at: string | null;
}

export interface ItemDetail extends Item {
  cves: string[];
  iocs: { type: string; value: string }[];
  actors: string[];
  families: string[];
  domains: string[];
  ip_intel: Record<string, IpIntelEntry>;
  raw: unknown;
}

// Row shape from GET /api/export/iocs?format=json — same fields the CSV variant emits, backing
// the explorer's "Copy all IOCs" clipboard action (JSON avoids re-parsing quoted CSV client-side
// for values that legitimately contain commas).
export interface IocRow {
  type: string; value: string; itemId: number; sourceName: string; firstSeen: string | null;
}

export interface CveIntel {
  cve_id: string; cvss_score: number | null; cvss_source: string | null; severity: string;
  epss_score: number | null; kev_listed: boolean; kev_added_at: string | null;
  description: string | null; first_seen: string | null; last_seen: string | null; source_count: number;
}

export interface CveDetail {
  cve: CveIntel;
  sources: { item_id: number; source_id: number; cvss_score: number | null; severity: string | null;
             source_name: string; last_status: string | null; title: string; link: string | null; published_at: string | null }[];
  actors: string[];
  families: string[];
}

// Narrow row shape returned by GET /api/actors/:name and GET /api/malware/:family for each
// EntityProfile.items entry — verified identical on both endpoints against live data. This is
// NOT the full Item shape: no source_id, link, cvss_score, exploitation_status, vendor, region,
// industry or confidence.
export interface EntityProfileItem {
  id: number; title: string; summary: string | null; category: string; severity: string | null;
  published_at: string | null; source_name: string; last_status: string | null;
}

export interface EntityProfile {
  kind: 'actor' | 'family'; name: string; itemCount: number;
  items: EntityProfileItem[]; cves: string[];
  // Malware families for kind 'actor', actors for kind 'family' — entities sharing at least one
  // item with this one, per the item_actors/item_malware_families join in entityProfile().
  related: string[];
  sources: { id: number; name: string; count: number; last_status: string | null }[];
  timeline: { bucket: string; count: number }[];
}

// GET /api/facets also returns `actors` and `families`, but only `vendors`/`regions` are
// consumed today (vendors bar chart, region filter drill-down) — keep the modeled shape narrow.
export interface Facets {
  vendors: string[];
  regions: string[];
}

export interface SearchResults {
  items: { id: number; title: string; category: string }[];
  cves: { cve_id: string; severity: string; cvss_score: number | null }[];
  actors: { actor: string }[];
  families: { family: string }[];
  sources: { id: number; name: string; last_status: string | null }[];
}

// Profiles are personas, not accounts — no password, no session, no boundary between them.
// `X-Profile-Id` names the active one on every /api/* call.
export interface Profile {
  id: number;
  name: string;
  sector: string;
  vendors: string[];
  products: string[];
  threat_domains: string[];
  region: string | null;
  severity_floor: string;
  profile_version: number;
}

export interface SectorRecommendation {
  vendors: string[];
  products: string[];
  threatDomains: string[];
  severityFloor: string;
}

export interface Sector {
  slug: string;
  label: string;
  recommendation: SectorRecommendation;
}

export interface CpeFacet { value: string; refs: number; }

// Write shape for POST/PUT /api/profiles — camelCase, unlike the snake_case row the API returns.
export interface ProfilePayload {
  name: string;
  sector: string;
  vendors: string[];
  products: string[];
  threatDomains: string[];
  region: string | null;
  severityFloor: string;
}

// GET /api/domains — the threat-domain vocabulary with corpus counts, used by the survey's
// domain step and the explorer facets.
export interface DomainOption { slug: string; label: string; count: number; }
