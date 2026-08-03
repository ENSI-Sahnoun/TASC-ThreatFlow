import { describe, it, expect } from 'vitest';
import {
  tierLabel, tierToken, tierIsProminent, matchSentence, explanation, isModelWritten,
  qualityLabel, qualityHint, TIER_ORDER,
} from './relevance';
import type { RelevanceMatch } from './models';

const m = (kind: RelevanceMatch['kind'], value: string): RelevanceMatch => ({ kind, value });

describe('tier presentation', () => {
  it('orders tiers most to least urgent', () => {
    expect([...TIER_ORDER]).toEqual(['act_now', 'watch', 'low', 'not_yours']);
  });

  // Labels name an action, not a mood. "Watch" and "Low" described a feeling about an item and
  // left the reader with nothing to do about it.
  it('labels every tier with an action', () => {
    expect(tierLabel('act_now')).toBe('Act now');
    expect(tierLabel('watch')).toBe('Plan a fix');
    expect(tierLabel('low')).toBe('Background');
    expect(tierLabel('not_yours')).toBe('Not yours');
  });

  // A missing tier means no profile is active — not that the item is safe.
  it('falls back to "Not assessed" rather than implying safety', () => {
    expect(tierLabel(null)).toBe('Not assessed');
    expect(tierLabel(undefined)).toBe('Not assessed');
    expect(tierLabel('bogus')).toBe('Not assessed');
  });

  it('reuses the severity palette so the chip reads as one system', () => {
    expect(tierToken('act_now')).toBe('var(--sev-critical)');
    expect(tierToken(null)).toBe('var(--sev-unknown)');
  });

  it('gives visual weight only to the two urgent tiers', () => {
    expect(tierIsProminent('act_now')).toBe(true);
    expect(tierIsProminent('watch')).toBe(true);
    expect(tierIsProminent('low')).toBe(false);
    expect(tierIsProminent('not_yours')).toBe(false);
  });
});

describe('matchSentence', () => {
  it('leads with the exact product match', () => {
    expect(matchSentence([m('product', 'fortinet fortios'), m('kev', 'CISA KEV')]))
      .toBe('Matches your stack (fortinet fortios). Actively exploited — listed in CISA KEV.');
  });

  // A vendor hit is a weaker claim than a product hit, and must not be worded as one.
  it('falls back to vendor wording when there is no product hit', () => {
    expect(matchSentence([m('vendor', 'microsoft')]))
      .toBe('Matches a vendor you run (microsoft).');
  });

  it('does not repeat the vendor when the product already named it', () => {
    const s = matchSentence([m('product', 'fortinet fortios'), m('vendor', 'fortinet')]);
    expect(s).toBe('Matches your stack (fortinet fortios).');
  });

  it('joins multiple values readably', () => {
    expect(matchSentence([m('domain', 'ransomware'), m('domain', 'zero-day')]))
      .toBe('You follow ransomware and zero-day.');
    expect(matchSentence([m('domain', 'a'), m('domain', 'b'), m('domain', 'c')]))
      .toBe('You follow a, b and c.');
  });

  it('reports the sector and severity when they were reasons', () => {
    expect(matchSentence([m('sector', 'finance'), m('severity', 'critical')]))
      .toBe('Reported against the finance sector. Severity critical.');
  });

  // not_yours carries no matches, and the sentence must say why rather than being blank.
  it('explains an empty match list instead of returning nothing', () => {
    expect(matchSentence([])).toBe('Nothing in this matches your profile.');
    expect(matchSentence(null)).toBe('Nothing in this matches your profile.');
  });
});

describe('explanation', () => {
  const base = { tier: 'act_now' as const, matches: [m('product', 'fortinet fortios')] };

  it('prefers the model sentence when one was written', () => {
    expect(explanation({ ...base, sentence: 'You run FortiOS, so this is directly exposed.' }))
      .toBe('You run FortiOS, so this is directly exposed.');
  });

  // Ollama down, never run, or output rejected by the guard — all land here.
  it('falls back to the template when there is no model sentence', () => {
    expect(explanation({ ...base, sentence: null })).toBe('Matches your stack (fortinet fortios).');
    expect(explanation(base)).toBe('Matches your stack (fortinet fortios).');
    expect(explanation({ ...base, sentence: '   ' })).toBe('Matches your stack (fortinet fortios).');
  });

  it('still explains an absent verdict', () => {
    expect(explanation(null)).toBe('Nothing in this matches your profile.');
  });
});

// Only the actual model output may be labelled AI-generated — the deterministic template reads
// like prose but is rule-based, and tagging it as AI would misattribute it.
describe('isModelWritten', () => {
  const base = { tier: 'act_now' as const, matches: [m('product', 'fortinet fortios')] };

  it('is true only when a real model sentence is present', () => {
    expect(isModelWritten({ ...base, sentence: 'You run FortiOS, so this is directly exposed.' })).toBe(true);
  });

  it('is false for the deterministic fallback, whitespace-only, or an absent verdict', () => {
    expect(isModelWritten({ ...base, sentence: null })).toBe(false);
    expect(isModelWritten(base)).toBe(false);
    expect(isModelWritten({ ...base, sentence: '   ' })).toBe(false);
    expect(isModelWritten(null)).toBe(false);
  });
});

describe('quality badge', () => {
  it('labels the three demoted kinds in plain words', () => {
    expect(qualityLabel('roundup')).toBe('digest');
    expect(qualityLabel('commentary')).toBe('opinion');
    expect(qualityLabel('promotion')).toBe('vendor');
  });

  // The common case must add no visual noise.
  it('renders nothing for intel or an absent verdict', () => {
    expect(qualityLabel('intel')).toBeNull();
    expect(qualityLabel(null)).toBeNull();
    expect(qualityLabel(undefined)).toBeNull();
    expect(qualityLabel('nonsense')).toBeNull();
  });

  // The classifier is conservative and sometimes wrong; the tooltip must say so.
  it('explains that the item is ranked lower, not hidden', () => {
    expect(qualityHint('promotion')).toContain('not hidden');
    expect(qualityHint('roundup')).toContain('local model');
    expect(qualityHint('intel')).toBe('');
  });
});

// --- Impact indicator (Spec A) ---

import { tierSubline, slotText, hasConsequence, impactBlocks } from './relevance';
import type { Relevance } from './models';

const rel = (over: Partial<Relevance> = {}): Relevance => ({
  tier: 'act_now',
  matches: [],
  sentence: null,
  exposure: 'internet',
  consequence: {
    reach: { text: 'anyone on the internet', from: 'AV:N/PR:N/UI:N + exposure=internet' },
    impact: null,
    role: null,
    urgency: { text: 'already used in real attacks', due: '2026-08-17', from: 'KEV' },
    exposure: 'internet',
  },
  ...over,
} as Relevance);

describe('tier sub-lines', () => {
  it('uses the CISA deadline for act_now when there is one', () => {
    expect(tierSubline(rel())).toContain('Aug 17');
  });

  it('falls back to a fixed window when act_now has no deadline', () => {
    const r = rel({ consequence: {
      reach: null, impact: null, role: null,
      urgency: { text: 'likely to be attacked soon', due: null, from: 'EPSS>=0.5' },
    } } as Partial<Relevance>);
    expect(tierSubline(r)).toBe('within 48 hours');
  });

  it('falls back to a fixed window when act_now has no urgency slot at all', () => {
    const r = rel({ consequence: { reach: null, impact: null, role: null, urgency: null } } as Partial<Relevance>);
    expect(tierSubline(r)).toBe('within 48 hours');
  });

  it('reads watch as a plan, not a vigil', () => {
    expect(tierLabel('watch')).toBe('Plan a fix');
    expect(tierSubline(rel({ tier: 'watch' }))).toBe('this month');
  });

  it('gives low and not_yours no sub-line', () => {
    expect(tierSubline(rel({ tier: 'low' }))).toBeNull();
    expect(tierSubline(rel({ tier: 'not_yours' }))).toBeNull();
  });

  it('survives a null relevance', () => {
    expect(tierSubline(null)).toBeNull();
  });

  // A malformed date must not render as "Invalid Date" in front of a user.
  it('passes a malformed due date through unchanged', () => {
    const r = rel({ consequence: {
      reach: null, impact: null, role: null,
      urgency: { text: 'x', due: 'not-a-date', from: 'KEV' },
    } } as Partial<Relevance>);
    expect(tierSubline(r)).toContain('not-a-date');
  });
});

describe('consequence slots', () => {
  it('states the gap rather than rendering blank', () => {
    expect(slotText(null)).toBe('not stated in the source data');
    expect(slotText(undefined)).toBe('not stated in the source data');
  });

  it('renders the slot text when present', () => {
    expect(slotText({ text: 'anyone on the internet', from: 'x' })).toBe('anyone on the internet');
  });

  it('knows when there is nothing to show at all', () => {
    expect(hasConsequence(rel())).toBe(true);
    expect(hasConsequence(rel({ consequence: { reach: null, impact: null, role: null, urgency: null } } as Partial<Relevance>))).toBe(false);
    expect(hasConsequence(rel({ consequence: null } as Partial<Relevance>))).toBe(false);
    expect(hasConsequence(null)).toBe(false);
  });
});

describe('impact blocks', () => {
  it('always renders four blocks in reading order', () => {
    const labels = impactBlocks(rel()).map((b) => b.label);
    expect(labels).toEqual(['Who could do it', 'What they could do', 'What that is', 'How urgent']);
  });

  it('marks a missing fact rather than dropping the block', () => {
    const blocks = impactBlocks(rel());
    const impact = blocks.find((b) => b.label === 'What they could do')!;
    expect(impact.missing).toBe(true);
    expect(impact.text).toBe('not stated in the source data');
    expect(impact.from).toBeNull();
  });

  it('carries the provenance of a present fact', () => {
    const reach = impactBlocks(rel()).find((b) => b.label === 'Who could do it')!;
    expect(reach.missing).toBe(false);
    expect(reach.from).toBe('AV:N/PR:N/UI:N + exposure=internet');
  });

  it('renders four gaps rather than throwing when there is no consequence', () => {
    const blocks = impactBlocks(rel({ consequence: null } as Partial<Relevance>));
    expect(blocks).toHaveLength(4);
    expect(blocks.every((b) => b.missing)).toBe(true);
  });

  it('renders four gaps for a null relevance', () => {
    expect(impactBlocks(null).every((b) => b.missing)).toBe(true);
  });
});
