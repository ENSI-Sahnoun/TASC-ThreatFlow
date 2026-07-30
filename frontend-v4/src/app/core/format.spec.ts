import { describe, it, expect } from 'vitest';
import {
  relativeTime, compactNumber, severityToken, severityLabel, cvssBand, sourceHealth, needsKey,
  statusLabel, stripHtml, epssPercent, cvssDisagreement, formatDate, hostname, cardVariant,
} from './format';

const NOW = new Date('2026-07-26T12:00:00Z');

describe('relativeTime', () => {
  it('renders coarse buckets and handles missing dates', () => {
    expect(relativeTime('2026-07-26T11:58:00Z', NOW)).toBe('2m');
    expect(relativeTime('2026-07-26T09:00:00Z', NOW)).toBe('3h');
    expect(relativeTime('2026-07-24T12:00:00Z', NOW)).toBe('2d');
    expect(relativeTime('2026-07-26T12:00:00Z', NOW)).toBe('now');
    expect(relativeTime(null, NOW)).toBe('unknown');
    expect(relativeTime('not-a-date', NOW)).toBe('unknown');
  });
});

describe('compactNumber', () => {
  it('compacts thousands and handles null', () => {
    expect(compactNumber(950)).toBe('950');
    expect(compactNumber(2469)).toBe('2.5K');
    expect(compactNumber(1200000)).toBe('1.2M');
    expect(compactNumber(null)).toBe('—');
  });
});

describe('severity mapping', () => {
  it('maps every canonical value to a token and a label', () => {
    expect(severityToken('critical')).toBe('var(--sev-critical)');
    expect(severityToken('unknown')).toBe('var(--sev-unknown)');
    expect(severityToken(null)).toBe('var(--sev-unknown)');
    expect(severityToken('nonsense')).toBe('var(--sev-unknown)');
    expect(severityLabel(null)).toBe('Unknown');
    expect(severityLabel('critical')).toBe('Critical');
  });

  it('bands CVSS scores', () => {
    expect(cvssBand(9.8)).toBe('critical');
    expect(cvssBand(7)).toBe('high');
    expect(cvssBand(4)).toBe('medium');
    expect(cvssBand(0.1)).toBe('low');
    expect(cvssBand(0)).toBe('none');
    expect(cvssBand(null)).toBe('unknown');
  });
});

describe('sourceHealth', () => {
  it('classifies last_status into the four states the UI shows', () => {
    expect(sourceHealth('ok')).toBe('ok');
    expect(sourceHealth('error: HTTP 403')).toBe('error');
    expect(sourceHealth('unsupported')).toBe('unsupported');
    expect(sourceHealth(null)).toBe('never');
  });
});

describe('needsKey', () => {
  it('is true only when a key is required and missing', () => {
    expect(needsKey({ auth_required: 'ABUSECH_AUTH_KEY', has_api_key: false })).toBe(true);
    expect(needsKey({ auth_required: 'ABUSECH_AUTH_KEY', has_api_key: true })).toBe(false);
    expect(needsKey({ auth_required: null, has_api_key: false })).toBe(false);
  });
});

describe('stripHtml', () => {
  it('strips tags, collapses whitespace, and treats blank-only input as null', () => {
    expect(stripHtml('<p>Hello   <b>world</b></p>')).toBe('Hello world');
    expect(stripHtml(null)).toBeNull();
    expect(stripHtml('   ')).toBeNull();
    expect(stripHtml('<script>evil()</script>plain')).toBe('evil() plain');
  });
});

describe('formatDate', () => {
  it('renders a full calendar date and handles missing/invalid input', () => {
    expect(formatDate('2026-07-26T12:00:00Z')).toBe(
      new Date('2026-07-26T12:00:00Z').toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }),
    );
    expect(formatDate(null)).toBe('unknown date');
    expect(formatDate('not-a-date')).toBe('unknown date');
  });
});

describe('epssPercent', () => {
  it('formats a probability as a percentage, trimming a trailing .0', () => {
    expect(epssPercent(0.99999)).toBe('100%');
    expect(epssPercent(0.12345)).toBe('12.3%');
    expect(epssPercent(0.5)).toBe('50%');
    expect(epssPercent(0)).toBe('0%');
    expect(epssPercent(null)).toBe('—');
  });
});

describe('cvssDisagreement', () => {
  it('is null when fewer than two sources carry a score', () => {
    expect(cvssDisagreement([])).toBeNull();
    expect(cvssDisagreement([{ source_name: 'NVD', cvss_score: 9.8 }])).toBeNull();
    expect(cvssDisagreement([
      { source_name: 'NVD', cvss_score: 9.8 },
      { source_name: 'FIRST EPSS', cvss_score: null },
    ])).toBeNull();
  });

  it('is null when every scored source agrees', () => {
    expect(cvssDisagreement([
      { source_name: 'NVD', cvss_score: 9.8 },
      { source_name: 'Red Hat', cvss_score: 9.8 },
    ])).toBeNull();
  });

  it('names the highest and lowest scoring source when they differ', () => {
    expect(cvssDisagreement([
      { source_name: 'Red Hat', cvss_score: 7.5 },
      { source_name: 'NVD', cvss_score: 9.8 },
    ])).toBe('NVD 9.8 · Red Hat 7.5');
  });

  it('picks the widest spread across more than two sources', () => {
    expect(cvssDisagreement([
      { source_name: 'OSV.dev', cvss_score: 9 },
      { source_name: 'FIRST EPSS', cvss_score: null },
      { source_name: 'OSV.dev', cvss_score: 10 },
    ])).toBe('OSV.dev 10 · OSV.dev 9');
  });
});

describe('hostname', () => {
  it('extracts a bare host and strips a leading www.', () => {
    expect(hostname('https://www.redhat.com/security/cve/CVE-2026-1')).toBe('redhat.com');
    expect(hostname('https://blog.talosintelligence.com/post')).toBe('blog.talosintelligence.com');
  });

  it('is null for missing or unparseable input', () => {
    expect(hostname(null)).toBeNull();
    expect(hostname('not a url')).toBeNull();
  });
});

describe('statusLabel', () => {
  it('shows the item count for a normal ok source', () => {
    expect(
      statusLabel({ auth_required: null, has_api_key: false, last_status: 'ok', item_count: 2469 }),
    ).toEqual({ kind: 'count', text: '2.5K items' });
  });

  it('surfaces the raw error for an erroring source with no key requirement', () => {
    expect(
      statusLabel({ auth_required: null, has_api_key: false, last_status: 'error: HTTP 403', item_count: 0 }),
    ).toEqual({ kind: 'error', text: 'error: HTTP 403' });
  });

  it('shows the needs-key message for a source that has never synced', () => {
    expect(
      statusLabel({ auth_required: 'ABUSECH_AUTH_KEY', has_api_key: false, last_status: null, item_count: 0 }),
    ).toEqual({ kind: 'needs-key', text: 'Needs API key (ABUSECH_AUTH_KEY)' });
  });

  it('prefers needs-key over an overlapping sync error (MalwareBazaar case)', () => {
    expect(
      statusLabel({
        auth_required: 'ABUSECH_AUTH_KEY',
        has_api_key: false,
        last_status: 'error: HTTP 401',
        item_count: 12,
      }),
    ).toEqual({ kind: 'needs-key', text: 'Needs API key (ABUSECH_AUTH_KEY)' });
  });
});

describe('cardVariant', () => {
  it('groups categories by which fields they actually populate', () => {
    expect(cardVariant('cve')).toBe('vulnerability');
    expect(cardVariant('advisory')).toBe('vulnerability');
    expect(cardVariant('ioc')).toBe('indicator');
    expect(cardVariant('malware')).toBe('indicator');
    expect(cardVariant('phishing')).toBe('indicator');
    expect(cardVariant('ransomware')).toBe('incident');
    expect(cardVariant('data-breach')).toBe('incident');
    expect(cardVariant('osint')).toBe('plain');
    expect(cardVariant('news')).toBe('plain');
    expect(cardVariant('other')).toBe('plain');
    expect(cardVariant(null)).toBe('plain');
  });
});
