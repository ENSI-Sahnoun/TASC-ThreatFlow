import { describe, it, expect } from 'vitest';
import {
  isPastDue, formatDueDate, groupHasPastDue, queueSummary, groupProgress, oneUpgradeCloses,
} from './remediation';
import type { RemediationQueueGroup, RemediationQueueItem } from './models';

const item = (over: Partial<RemediationQueueItem> = {}): RemediationQueueItem => ({
  itemId: 1, title: 'T', tier: 'act_now', score: 1,
  status: 'affected', installed: null, versionState: 'unset', entry: null,
  fix: { kind: 'none' }, mitigations: [], dueDate: null, patchUrl: null,
  ...over,
});

const group = (over: Partial<RemediationQueueGroup> = {}): RemediationQueueGroup => ({
  vendor: 'fortinet', product: 'fortios', exposure: 'unknown',
  version: null, versionState: 'unset', items: [],
  ...over,
});

describe('isPastDue', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('is false for a null due date', () => {
    expect(isPastDue(null, now)).toBe(false);
  });
  it('is true for a date before now', () => {
    expect(isPastDue('2026-07-01', now)).toBe(true);
  });
  it('is false for a date after now', () => {
    expect(isPastDue('2026-12-01', now)).toBe(false);
  });
  it('is false for an unparseable date rather than throwing', () => {
    expect(isPastDue('not-a-date', now)).toBe(false);
  });
});

describe('formatDueDate', () => {
  it('formats an ISO date as "Mon D"', () => {
    expect(formatDueDate('2026-08-17')).toBe('Aug 17');
  });
  it('passes through an unparseable value rather than rendering "Invalid Date"', () => {
    expect(formatDueDate('garbage')).toBe('garbage');
  });
});

describe('groupHasPastDue', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('is true when at least one open item is past its due date', () => {
    const items = [item({ dueDate: '2026-07-01', status: 'affected' })];
    expect(groupHasPastDue(items, now)).toBe(true);
  });
  it('is false when the only past-due item already reads not_covered', () => {
    const items = [item({ dueDate: '2026-07-01', status: 'not_covered' })];
    expect(groupHasPastDue(items, now)).toBe(false);
  });
  it('is false with no items', () => {
    expect(groupHasPastDue([], now)).toBe(false);
  });
});

describe('queueSummary', () => {
  const now = new Date('2026-08-04T00:00:00Z');
  it('counts open items across all groups, excluding not_covered', () => {
    const groups = [
      group({ items: [item({ status: 'affected' }), item({ status: 'not_covered' })] }),
      group({ vendor: 'microsoft', product: 'windows', items: [item({ status: 'unknown' })] }),
    ];
    expect(queueSummary(groups, now).open).toBe(2);
  });
  it('counts past-due open items across all groups', () => {
    const groups = [
      group({ items: [
        item({ status: 'affected', dueDate: '2026-07-01' }),
        item({ status: 'affected', dueDate: '2026-12-01' }),
        item({ status: 'not_covered', dueDate: '2026-01-01' }),
      ] }),
    ];
    expect(queueSummary(groups, now)).toEqual({ open: 2, pastDue: 1 });
  });
  it('is all zero for an empty queue', () => {
    expect(queueSummary([], now)).toEqual({ open: 0, pastDue: 0 });
  });
});

describe('groupProgress', () => {
  it('is null when the version has never been asked (unset) — progress is not measurable', () => {
    expect(groupProgress(group({ versionState: 'unset', items: [item()] }))).toBeNull();
  });
  it('is null when the reader declined to say (unknown) — same reason, does not re-ask', () => {
    expect(groupProgress(group({ versionState: 'unknown', items: [item()] }))).toBeNull();
  });
  it('reports done/total from not_covered items once a version is known', () => {
    const items = [
      item({ itemId: 1, status: 'not_covered' }),
      item({ itemId: 2, status: 'not_covered' }),
      item({ itemId: 3, status: 'affected' }),
    ];
    expect(groupProgress(group({ versionState: 'known', version: '7.0.0', items }))).toEqual({ done: 2, total: 3 });
  });
  it('is 0 of 0 for a known version with no items, not null', () => {
    expect(groupProgress(group({ versionState: 'known', version: '7.0.0', items: [] }))).toEqual({ done: 0, total: 0 });
  });
});

describe('oneUpgradeCloses', () => {
  it('fires at two items sharing the same version fix target', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } }),
    ];
    expect(oneUpgradeCloses(items)).toEqual({ value: '7.4.5', count: 2 });
  });
  it('does not fire for a single item, even with a version fix', () => {
    const items = [item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } })];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('never fires for patch targets, however many share the same URL', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'patch', value: 'https://x/patch' } }),
      item({ itemId: 2, fix: { kind: 'patch', value: 'https://x/patch' } }),
    ];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('never fires for advisory or none targets', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'advisory', value: 'https://x/a' } }),
      item({ itemId: 2, fix: { kind: 'advisory', value: 'https://x/a' } }),
      item({ itemId: 3, fix: { kind: 'none' } }),
      item({ itemId: 4, fix: { kind: 'none' } }),
    ];
    expect(oneUpgradeCloses(items)).toBeNull();
  });
  it('picks the larger group when two different version targets both qualify', () => {
    const items = [
      item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 3, fix: { kind: 'version', value: '7.4.5' } }),
      item({ itemId: 4, fix: { kind: 'version', value: '9.0.0' } }),
      item({ itemId: 5, fix: { kind: 'version', value: '9.0.0' } }),
    ];
    expect(oneUpgradeCloses(items)).toEqual({ value: '7.4.5', count: 3 });
  });
  it('never counts one item twice even if fix values were somehow duplicated in the array', () => {
    const shared = item({ itemId: 1, fix: { kind: 'version', value: '7.4.5' } });
    const items = [shared, item({ itemId: 2, fix: { kind: 'version', value: '7.4.5' } })];
    expect(oneUpgradeCloses(items)!.count).toBe(items.length);
  });
  it('is null for an empty list', () => {
    expect(oneUpgradeCloses([])).toBeNull();
  });
});
