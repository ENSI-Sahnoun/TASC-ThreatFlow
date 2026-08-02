import { describe, it, expect } from 'vitest';
import { tierLabel, tierToken, tierIsProminent, matchSentence, explanation, TIER_ORDER } from './relevance';
import type { RelevanceMatch } from './models';

const m = (kind: RelevanceMatch['kind'], value: string): RelevanceMatch => ({ kind, value });

describe('tier presentation', () => {
  it('orders tiers most to least urgent', () => {
    expect([...TIER_ORDER]).toEqual(['act_now', 'watch', 'low', 'not_yours']);
  });

  it('labels every tier in plain language', () => {
    expect(tierLabel('act_now')).toBe('Act now');
    expect(tierLabel('watch')).toBe('Watch');
    expect(tierLabel('low')).toBe('Low');
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
