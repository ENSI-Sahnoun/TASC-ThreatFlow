import { describe, it, expect } from 'vitest';
import { playbookProgress, stepBlocks, groundingFooter } from './playbook';
import type { Playbook, PlaybookStep } from './models';

const step = (over: Partial<PlaybookStep> = {}): PlaybookStep => ({
  key: 'confirm', title: 't', detail: 'd', source: 's', link: null, ...over,
});

describe('playbookProgress', () => {
  it('counts ticked steps against the total', () => {
    const pb: Playbook = { steps: [step({ key: 'a' }), step({ key: 'b' }), step({ key: 'c' })], done: ['a', 'b'] };
    expect(playbookProgress(pb)).toEqual({ done: 2, total: 3 });
  });

  it('is 0 of 0 for a null playbook rather than throwing', () => {
    expect(playbookProgress(null)).toEqual({ done: 0, total: 0 });
  });

  // A stale tick from a superseded step key must not inflate the count past the total.
  it('ignores a done[] entry that names a step no longer in steps[]', () => {
    const pb: Playbook = { steps: [step({ key: 'a' })], done: ['a', 'ghost'] };
    expect(playbookProgress(pb)).toEqual({ done: 1, total: 1 });
  });
});

describe('stepBlocks', () => {
  it('resolves each step\'s done flag from done[]', () => {
    const pb: Playbook = { steps: [step({ key: 'a' }), step({ key: 'b' })], done: ['a'] };
    const blocks = stepBlocks(pb);
    expect(blocks.find((b) => b.key === 'a')?.done).toBe(true);
    expect(blocks.find((b) => b.key === 'b')?.done).toBe(false);
  });

  it('preserves every field of the underlying step', () => {
    const s = step({ key: 'patch', title: 'Apply the fix', detail: 'd', source: 'NVD reference (Patch)', link: 'https://x.test' });
    const [block] = stepBlocks({ steps: [s], done: [] });
    expect(block).toMatchObject(s);
  });

  it('is an empty array for a null playbook or zero steps, never throws', () => {
    expect(stepBlocks(null)).toEqual([]);
    expect(stepBlocks({ steps: [], done: [] })).toEqual([]);
  });
});

describe('groundingFooter', () => {
  it('reports CISA KEV and NVD Patch when a ransomware and a patch step are present', () => {
    const pb: Playbook = {
      steps: [step({ key: 'confirm' }), step({ key: 'ransomware' }), step({ key: 'patch' })],
      done: [],
    };
    const { groundedIn, missing } = groundingFooter(pb);
    expect(groundedIn).toContain('CISA KEV');
    expect(groundedIn).toContain('NVD Patch reference');
    expect(missing).not.toContain('vendor patch link');
  });

  it('reports the vendor patch link as missing when watch-vendor is present', () => {
    const pb: Playbook = { steps: [step({ key: 'confirm' }), step({ key: 'watch-vendor' })], done: [] };
    const { groundedIn, missing } = groundingFooter(pb);
    expect(missing).toContain('vendor patch link');
    expect(groundedIn).not.toContain('NVD Patch reference');
    expect(groundedIn).not.toContain('NVD Vendor Advisory');
  });

  it('reports CVSS vector as grounded when restrict or rotate is present', () => {
    const pb: Playbook = { steps: [step({ key: 'confirm' }), step({ key: 'rotate' })], done: [] };
    expect(groundingFooter(pb).groundedIn).toContain('CVSS vector');
  });

  it('handles a null playbook without throwing', () => {
    expect(groundingFooter(null)).toEqual({ groundedIn: [], missing: [] });
  });
});
