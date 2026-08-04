import { describe, it, expect } from 'vitest';
import {
  isPastDue, formatDueDate, groupHasPastDue, queueSummary, groupProgress, oneUpgradeCloses,
  parseVectorMetrics, reachDiagram, affectedWording, fixWording, closesWording, countCleared,
  versionRecordedMessage,
} from './remediation';
import type { RemediationFix, RemediationQueueGroup, RemediationQueueItem } from './models';

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

describe('parseVectorMetrics', () => {
  it('extracts a v3.1 vector\'s metrics into an uppercase map', () => {
    expect(parseVectorMetrics('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))
      .toEqual({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
  });
  it('is null for null/undefined/non-string input', () => {
    expect(parseVectorMetrics(null)).toBeNull();
    expect(parseVectorMetrics(undefined)).toBeNull();
  });
  it('is null for a string with no CVSS: prefix', () => {
    expect(parseVectorMetrics('AV:N/AC:L')).toBeNull();
  });
});

describe('reachDiagram', () => {
  it('AV:N reads as the internet', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N', UI: 'N', C: 'H', I: 'H', A: 'H' });
    expect(d.nodes[0].title).toBe('The internet');
    expect(d.nodes[0].from).toBe('AV:N');
  });
  it('AV:A reads as the adjacent network', () => {
    expect(reachDiagram({ AV: 'A' }).nodes[0].title).toBe('Adjacent network');
  });
  it('AV:L reads as already on the machine', () => {
    expect(reachDiagram({ AV: 'L' }).nodes[0].title).toBe('Already on the machine');
  });
  it('AV:P reads as physical access', () => {
    expect(reachDiagram({ AV: 'P' }).nodes[0].title).toBe('Physical access');
  });
  it('an absent or unrecognised AV is a stated gap, not a guess', () => {
    const noAv = reachDiagram({});
    expect(noAv.nodes[0].title).toBe('Reach not stated');
    const badAv = reachDiagram({ AV: 'X' });
    expect(badAv.nodes[0].title).toBe('Reach not stated');
    expect(badAv.nodes[0].from).toBe('AV:X');
  });

  it('PR:N reads as no account needed', () => {
    expect(reachDiagram({ PR: 'N' }).nodes[1].title).toBe('No account needed');
  });
  it('PR:L reads as a normal account', () => {
    expect(reachDiagram({ PR: 'L' }).nodes[1].title).toBe('A normal account');
  });
  it('PR:H reads as an admin account', () => {
    expect(reachDiagram({ PR: 'H' }).nodes[1].title).toBe('An admin account');
  });
  it('an absent PR is a stated gap', () => {
    expect(reachDiagram({}).nodes[1].title).toBe('Privilege not stated');
  });

  it('UI:N annotates the gate node with "needs nothing from anyone"', () => {
    const d = reachDiagram({ UI: 'N' });
    expect(d.gateAnnotation).toEqual({ text: 'needs nothing from anyone', from: 'UI:N' });
  });
  it('UI:R annotates the gate node with "needs someone to click something"', () => {
    const d = reachDiagram({ UI: 'R' });
    expect(d.gateAnnotation).toEqual({ text: 'needs someone to click something', from: 'UI:R' });
  });
  it('an absent UI produces no annotation at all, not a fabricated one', () => {
    expect(reachDiagram({}).gateAnnotation).toBeNull();
  });

  it('fills the outcome node with read/change/shut down only for H-valued C/I/A', () => {
    const d = reachDiagram({ C: 'H', I: 'H', A: 'H' });
    expect(d.nodes[2].title).toBe('read, change and shut down');
    expect(d.nodes[2].from).toBe('C:H/I:H/A:H');
  });
  it('a single H metric produces a single verb', () => {
    expect(reachDiagram({ C: 'H' }).nodes[2].title).toBe('read');
  });
  it('two H metrics join with "and", not a comma list', () => {
    expect(reachDiagram({ C: 'H', A: 'H' }).nodes[2].title).toBe('read and shut down');
  });
  it('an L-valued metric never reaches the outcome node — only H does', () => {
    const d = reachDiagram({ C: 'L', I: 'L', A: 'L' });
    expect(d.nodes[2].title).toBe('No full-control outcome');
  });
  it('no metrics at all is a stated gap on the outcome node too', () => {
    expect(reachDiagram({}).nodes[2].title).toBe('No full-control outcome');
  });

  it('null metrics produces the same three stated-gap nodes as an empty object', () => {
    expect(reachDiagram(null)).toEqual(reachDiagram({}));
  });

  it('always returns exactly two edges, origin->gate and gate->outcome', () => {
    const d = reachDiagram({ AV: 'N', PR: 'N' });
    expect(d.edges).toEqual([{ from: 'origin', to: 'gate' }, { from: 'gate', to: 'outcome' }]);
  });
});

describe('affectedWording', () => {
  it('affected: states it plainly', () => {
    const w = affectedWording('affected', '7.4.0', 'before 7.4.5');
    expect(w.headline).toBe('You are affected.');
    expect(w.detail).toBe('Your build is inside the range.');
  });

  // Load-bearing: the system must never tell anyone they are safe.
  it('not_covered: never contains the word "safe"', () => {
    const w = affectedWording('not_covered', '8.0.0', 'before 7.4.5');
    expect(`${w.headline} ${w.detail}`.toLowerCase()).not.toContain('safe');
  });
  it('not_covered: states the range doesn\'t cover the build and says to confirm', () => {
    const w = affectedWording('not_covered', '8.0.0', 'before 7.4.5');
    expect(w.headline).toBe('This range does not cover your build.');
    expect(w.detail).toMatch(/confirm/i);
  });

  it('unknown: shows the actual values to compare, not a generic message', () => {
    const w = affectedWording('unknown', 'v7.0', 'before 7.4.5');
    expect(w.detail).toContain('v7.0');
    expect(w.detail).toContain('before 7.4.5');
  });
  it('unknown: never contains the word "safe" either', () => {
    const w = affectedWording('unknown', null, null);
    expect(`${w.headline} ${w.detail}`.toLowerCase()).not.toContain('safe');
  });
});

describe('fixWording', () => {
  it('version: names the target version and nothing else', () => {
    const fix: RemediationFix = { kind: 'version', value: '7.4.5' };
    const w = fixWording(fix);
    expect(w.headline).toBe('Upgrade to 7.4.5 or later');
    expect(w.note).toBeNull();
  });
  it('patch: carries the URL verbatim as the note', () => {
    const fix: RemediationFix = { kind: 'patch', value: 'https://example.com/patch' };
    expect(fixWording(fix).note).toBe('https://example.com/patch');
  });
  it('advisory: states no direct patch link is published', () => {
    const fix: RemediationFix = { kind: 'advisory', value: 'https://example.com/advisory' };
    const w = fixWording(fix);
    expect(w.detail).toMatch(/no direct patch link/i);
    expect(w.note).toBe('https://example.com/advisory');
  });
  it('none: states the fact plainly, load-bearing wording', () => {
    const w = fixWording({ kind: 'none' });
    expect(w.headline).toBe('No fix has been published for this yet.');
  });
});

describe('closesWording', () => {
  it('renders the upgrade-closes-N sentence', () => {
    expect(closesWording({ value: '7.4.5', count: 3 })).toBe('one upgrade to 7.4.5 closes 3 of these');
  });
  it('is null when there is nothing to close', () => {
    expect(closesWording(null)).toBeNull();
  });
});

describe('countCleared', () => {
  it('counts items that flipped from something else to not_covered', () => {
    const before = [{ itemId: 1, status: 'affected' }, { itemId: 2, status: 'affected' }];
    const after = [{ itemId: 1, status: 'not_covered' }, { itemId: 2, status: 'not_covered' }];
    expect(countCleared(before, after, 0)).toBe(2);
  });
  it('excludes the item the reader is currently looking at', () => {
    const before = [{ itemId: 1, status: 'affected' }, { itemId: 2, status: 'affected' }];
    const after = [{ itemId: 1, status: 'not_covered' }, { itemId: 2, status: 'not_covered' }];
    expect(countCleared(before, after, 1)).toBe(1);
  });
  it('does not count an item that was already not_covered before the write', () => {
    const before = [{ itemId: 1, status: 'not_covered' }];
    const after = [{ itemId: 1, status: 'not_covered' }];
    expect(countCleared(before, after, 0)).toBe(0);
  });
  it('does not count an item that stayed affected', () => {
    const before = [{ itemId: 1, status: 'affected' }];
    const after = [{ itemId: 1, status: 'affected' }];
    expect(countCleared(before, after, 0)).toBe(0);
  });
  it('is 0 for empty input', () => {
    expect(countCleared([], [], 0)).toBe(0);
  });
});

describe('versionRecordedMessage', () => {
  it('is null when nothing cleared — never claims a consequence that didn\'t happen', () => {
    expect(versionRecordedMessage(0)).toBeNull();
  });
  it('singular wording for exactly one cleared threat', () => {
    expect(versionRecordedMessage(1)).toBe('Recorded. 1 other threat against this machine is no longer inside its affected range.');
  });
  it('plural wording for more than one', () => {
    expect(versionRecordedMessage(2)).toBe('Recorded. 2 other threats against this machine are no longer inside their affected range.');
  });
});
