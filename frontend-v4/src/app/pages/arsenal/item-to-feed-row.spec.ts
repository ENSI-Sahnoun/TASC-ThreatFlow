import { describe, it, expect } from 'vitest';
import { itemToFeedRow } from './item-to-feed-row';
import type { Item } from '../../core/models';

const ITEM: Item = {
  id: 42, source_id: 16, category: 'cve', title: 'CVE-2021-20190',
  summary: 'A flaw was found in jackson-databind.', link: 'https://nvd.nist.gov/vuln/detail/CVE-2021-20190',
  published_at: '2021-01-19T16:15:13.427Z', severity: 'high', cvss_score: 8.1, epss_score: null,
  exploitation_status: null, vendor: null, region: null, industry: null, confidence: 0.9,
  source_name: 'NVD CVE API', cluster_id: null, source_count: 1,
};

describe('itemToFeedRow', () => {
  it('collapses a single item into a one-source cluster the story drawer understands', () => {
    const row = itemToFeedRow(ITEM, 'NVD CVE API', 'ok', 'nvd_cve');
    expect(row).toEqual({
      cluster_id: 42,
      title: 'CVE-2021-20190',
      first_seen: '2021-01-19T16:15:13.427Z',
      last_seen: '2021-01-19T16:15:13.427Z',
      source_count: 1,
      item_id: 42,
      category: 'cve',
      summary: 'A flaw was found in jackson-databind.',
      severity: 'high',
      link: 'https://nvd.nist.gov/vuln/detail/CVE-2021-20190',
      confidence: 0.9,
      source_name: 'NVD CVE API',
      source_status: 'ok',
      source_fetch_kind: 'nvd_cve',
    });
  });

  it('passes through null published_at / summary / severity / link / confidence unchanged', () => {
    const bare: Item = { ...ITEM, published_at: null, summary: null, severity: null, link: null, confidence: null };
    const row = itemToFeedRow(bare, 'OpenPhish', null, 'rss');
    expect(row.first_seen).toBeNull();
    expect(row.last_seen).toBeNull();
    expect(row.summary).toBeNull();
    expect(row.severity).toBeNull();
    expect(row.link).toBeNull();
    expect(row.confidence).toBeNull();
    expect(row.source_name).toBe('OpenPhish');
    expect(row.source_status).toBeNull();
    expect(row.source_count).toBe(1);
    expect(row.source_fetch_kind).toBe('rss');
  });
});
