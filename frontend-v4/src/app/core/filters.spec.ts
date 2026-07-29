import { describe, it, expect } from 'vitest';
import { toQueryParams, fromQueryParams, isEmpty, type IntelFilters } from './filters';

const empty: IntelFilters = {};

describe('filter serialization', () => {
  it('omits empty values and round-trips', () => {
    const f: IntelFilters = { q: 'siemens', severity: 'critical', source_id: 3, min_confidence: 0.8 };
    const params = toQueryParams(f);
    expect(params).toEqual({ q: 'siemens', severity: 'critical', source_id: '3', min_confidence: '0.8' });
    expect(fromQueryParams(params)).toEqual(f);
  });

  it('drops blanks rather than sending empty filters to the API', () => {
    expect(toQueryParams({ q: '', severity: undefined, vendor: '   ' })).toEqual({});
  });

  it('ignores unknown query params instead of forwarding them', () => {
    expect(fromQueryParams({ q: 'x', nonsense: 'y' })).toEqual({ q: 'x' });
  });

  it('detects the empty filter set', () => {
    expect(isEmpty(empty)).toBe(true);
    expect(isEmpty({ q: 'x' })).toBe(false);
  });
});
