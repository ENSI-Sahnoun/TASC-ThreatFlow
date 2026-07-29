// Explorer filters live in the URL so any view is shareable and the back button works.
// Serialization is pure and tested; components never build query strings by hand.

export interface IntelFilters {
  q?: string;
  category?: string;
  source_id?: number;
  domain?: string;
  actor?: string;
  malware_family?: string;
  cve?: string;
  severity?: string;
  exploitation_status?: string;
  vendor?: string;
  region?: string;
  industry?: string;
  min_confidence?: number;
}

const STRING_KEYS = ['q', 'category', 'domain', 'actor', 'malware_family', 'cve',
  'severity', 'exploitation_status', 'vendor', 'region', 'industry'] as const;
const NUMBER_KEYS = ['source_id', 'min_confidence'] as const;

export function toQueryParams(f: IntelFilters): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of STRING_KEYS) {
    const v = f[k];
    if (typeof v === 'string' && v.trim()) out[k] = v.trim();
  }
  for (const k of NUMBER_KEYS) {
    const v = f[k];
    if (typeof v === 'number' && !Number.isNaN(v)) out[k] = String(v);
  }
  return out;
}

export function fromQueryParams(p: Record<string, string | undefined>): IntelFilters {
  const out: IntelFilters = {};
  for (const k of STRING_KEYS) {
    const v = p[k];
    if (typeof v === 'string' && v.trim()) out[k] = v.trim();
  }
  for (const k of NUMBER_KEYS) {
    const v = p[k];
    if (v != null && v !== '' && !Number.isNaN(Number(v))) out[k] = Number(v);
  }
  return out;
}

export function isEmpty(f: IntelFilters): boolean {
  return Object.keys(toQueryParams(f)).length === 0;
}
