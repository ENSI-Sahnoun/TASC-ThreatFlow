import type { Source } from './models';

// Framework-free formatting. Kept out of components so it is testable without a browser
// and so two components can never disagree about how a severity renders.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;

export function relativeTime(iso: string | null, now: Date = new Date()): string {
  if (!iso) return 'unknown';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown';
  const delta = now.getTime() - t;
  if (delta < MINUTE) return 'now';
  if (delta < HOUR) return `${Math.floor(delta / MINUTE)}m`;
  if (delta < DAY) return `${Math.floor(delta / HOUR)}h`;
  if (delta < 30 * DAY) return `${Math.floor(delta / DAY)}d`;
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

// A full "Jul 26, 2026" date, for the rare spot (the CVE page's KEV badge) that wants an exact
// date rather than relativeTime's coarse "2d"/"3mo" bucket.
export function formatDate(iso: string | null): string {
  if (!iso) return 'unknown date';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'unknown date';
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function compactNumber(n: number | null): string {
  if (n == null || Number.isNaN(n)) return '—';
  if (Math.abs(n) < 1000) return String(n);
  if (Math.abs(n) < 1_000_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}K`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
}

function normalizeSeverity(severity: string | null): Severity {
  const s = String(severity ?? '').toLowerCase() as Severity;
  return (SEVERITY_ORDER as readonly string[]).includes(s) ? s : 'unknown';
}

export function severityToken(severity: string | null): string {
  return `var(--sev-${normalizeSeverity(severity)})`;
}

// True for a severity worth a colored pill (a real rating, incl. the explicit "none" rating).
// "unknown" means "not analyzed yet" — that's the common case for a fresh RSS item, not a fact
// worth the same visual weight as an actual Critical/High/Medium/Low/None rating, so callers
// render it as plain muted text instead of a chip (see explorer.component.ts's severity cell).
export function isRatedSeverity(severity: string | null): boolean {
  return normalizeSeverity(severity) !== 'unknown';
}

// Same 10 values as filter-bar.component.ts's CATEGORIES select, in the same order, so a
// category's dot color is stable across the app regardless of which categories are present in
// any one page of results (an index-into-visible-data scheme, like the donut chart's, would
// reassign colors every time the filtered set changes).
const CATEGORY_ORDER = ['cve', 'ransomware', 'phishing', 'data-breach', 'malware', 'ioc', 'advisory', 'osint', 'news', 'other'];

export function categoryToken(category: string | null): string {
  const i = category ? CATEGORY_ORDER.indexOf(category) : -1;
  const n = (i === -1 ? CATEGORY_ORDER.length : i) % 8 + 1;
  return `var(--cat-${n})`;
}

export function severityLabel(severity: string | null): string {
  const s = normalizeSeverity(severity);
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Plain RSS items have no severity until something actually scores them — "Unknown" reads as
// a data-quality problem when it's really just "not analyzed yet". Until a local model does
// that classification, an unclassified RSS item shows "News" instead; every other fetch_kind
// (and any item that already has a real severity) keeps the normal Unknown/Critical/etc label.
export function severityDisplayLabel(severity: string | null, fetchKind: string | null): string {
  return normalizeSeverity(severity) === 'unknown' && fetchKind === 'rss' ? 'News' : severityLabel(severity);
}

export function cvssBand(score: number | null): Severity {
  if (score == null || Number.isNaN(score)) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

export type HealthState = 'ok' | 'error' | 'unsupported' | 'never';

export function sourceHealth(lastStatus: string | null): HealthState {
  if (lastStatus == null) return 'never';
  if (lastStatus === 'ok') return 'ok';
  if (lastStatus === 'unsupported') return 'unsupported';
  return 'error';
}

// Strips markup and collapses whitespace. Not every one of the 43 upstream sources guarantees
// a plain-text summary, so anywhere a summary renders it passes through this first.
export function stripHtml(text: string | null): string | null {
  if (!text) return null;
  return text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() || null;
}

// Extracts a bare hostname for the Safari-window address pill (browser-window.component.ts) —
// strips a leading "www." the way a real browser's address bar does. Null for a missing/
// unparseable link rather than throwing, since not every item carries one.
export function hostname(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

// Formats an EPSS probability (0..1) as a percentage for the CVE header, e.g. 0.99999 -> "100%".
// One decimal place unless it would round to a whole number, so "12.3%" stays precise but
// "100.0%" doesn't stutter.
export function epssPercent(score: number | null): string {
  if (score == null || Number.isNaN(score)) return '—';
  const pct = score * 100;
  const rounded = Math.round(pct * 10) / 10;
  return `${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)}%`;
}

export interface ScoredSource { source_name: string; cvss_score: number | null; }

// Cross-source CVSS disagreement for the CVE detail page's "Sources disagree" banner, e.g.
// "OSV.dev 10 · OSV.dev 9" when the same feed files two different scores, or null when there's
// nothing to disagree about (fewer than two distinct scored values). This is exactly why
// `cve_sources` retains every source's value instead of the consolidation pass averaging them
// away — surfacing the spread is signal to an analyst, not noise.
export function cvssDisagreement(sources: ScoredSource[]): string | null {
  const scored = sources.filter((s): s is ScoredSource & { cvss_score: number } => s.cvss_score != null);
  if (scored.length < 2) return null;
  const max = scored.reduce((a, b) => (b.cvss_score > a.cvss_score ? b : a));
  const min = scored.reduce((a, b) => (b.cvss_score < a.cvss_score ? b : a));
  if (max.cvss_score === min.cvss_score) return null;
  return `${max.source_name} ${max.cvss_score} · ${min.source_name} ${min.cvss_score}`;
}

export type CardVariant = 'vulnerability' | 'indicator' | 'incident' | 'plain';

// Which tf-record-card layout a non-RSS item gets, grouped by what data the category actually
// carries rather than one bespoke layout per category (9 categories, 4 real data shapes).
export function cardVariant(category: string | null): CardVariant {
  switch (category) {
    case 'cve':
    case 'advisory':
      return 'vulnerability';
    case 'ioc':
    case 'malware':
    case 'phishing':
      return 'indicator';
    case 'ransomware':
    case 'data-breach':
      return 'incident';
    default:
      return 'plain';
  }
}

export function needsKey(s: Pick<Source, 'auth_required' | 'has_api_key'>): boolean {
  return !!s.auth_required && !s.has_api_key;
}

export type StatusLabel = { kind: 'needs-key' | 'error' | 'count'; text: string };

// "Needs a key" is orthogonal to `sourceHealth()` — a source can be missing a key AND have a
// last-sync error (abuse.ch MalwareBazaar does both). needsKey wins the label slot because it's
// the more actionable fact; sourceHealth() still governs the dot and the red-border treatment.
export function statusLabel(s: Pick<Source, 'auth_required' | 'has_api_key' | 'last_status' | 'item_count'>): StatusLabel {
  if (needsKey(s)) return { kind: 'needs-key', text: `Needs API key (${s.auth_required})` };
  if (sourceHealth(s.last_status) === 'error') return { kind: 'error', text: s.last_status ?? 'Sync failed' };
  return { kind: 'count', text: `${compactNumber(s.item_count)} items` };
}
