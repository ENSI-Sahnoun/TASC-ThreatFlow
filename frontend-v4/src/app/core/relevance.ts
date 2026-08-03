import type { Relevance, RelevanceMatch } from './models';

// Presentation for the "Possible Threat" verdict. Pure, so it carries the whole spec of what a
// tier means and what a match sentence reads like, testable without a DOM.

export const TIER_ORDER = ['act_now', 'watch', 'low', 'not_yours'] as const;
export type Tier = (typeof TIER_ORDER)[number];

const LABELS: Record<string, string> = {
  act_now: 'Act now',
  watch: 'Watch',
  low: 'Low',
  not_yours: 'Not yours',
};

// Reuses the severity palette so the threat chip reads as part of the same system as the
// severity chip beside it, rather than introducing a second colour language.
const TOKENS: Record<string, string> = {
  act_now: 'var(--sev-critical)',
  watch: 'var(--sev-high)',
  low: 'var(--sev-medium)',
  not_yours: 'var(--sev-unknown)',
};

export function tierLabel(tier: string | null | undefined): string {
  return (tier && LABELS[tier]) || 'Not assessed';
}

export function tierToken(tier: string | null | undefined): string {
  return (tier && TOKENS[tier]) || 'var(--sev-unknown)';
}

// Only act_now and watch earn visual weight in a dense list. low and not_yours are still
// present and still ordered, they just do not shout.
export function tierIsProminent(tier: string | null | undefined): boolean {
  return tier === 'act_now' || tier === 'watch';
}

function joinList(values: string[]): string {
  if (values.length <= 1) return values[0] ?? '';
  if (values.length === 2) return `${values[0]} and ${values[1]}`;
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`;
}

// The explanation the user actually reads. Built from the same `matches` the scorer emitted, so
// the sentence can never claim a reason the verdict was not based on.
//
// Phase 3 replaces the wording here with model prose — and only the wording. The tier is
// already decided by the time this runs.
export function matchSentence(matches: RelevanceMatch[] | null | undefined): string {
  if (!matches || !matches.length) return 'Nothing in this matches your profile.';

  const pick = (kind: string) => matches.filter((m) => m.kind === kind).map((m) => m.value);
  const parts: string[] = [];

  const products = pick('product');
  const vendors = pick('vendor');
  if (products.length) parts.push(`Matches your stack (${joinList(products)}).`);
  else if (vendors.length) parts.push(`Matches a vendor you run (${joinList(vendors)}).`);

  const domains = pick('domain');
  if (domains.length) parts.push(`You follow ${joinList(domains)}.`);

  const sector = pick('sector');
  if (sector.length) parts.push(`Reported against the ${sector[0]} sector.`);

  if (pick('kev').length) parts.push('Actively exploited — listed in CISA KEV.');

  const severity = pick('severity');
  if (severity.length) parts.push(`Severity ${severity[0]}.`);

  return parts.join(' ');
}

export function relevanceTier(relevance: Relevance | null | undefined): string | null {
  return relevance?.tier ?? null;
}

// What the user actually reads. The model's wording wins when it exists; otherwise the
// deterministic template does the job. Both describe the same verdict — the tier was decided
// before either was written.
export function explanation(relevance: Relevance | null | undefined): string {
  const sentence = relevance?.sentence?.trim();
  if (sentence) return sentence;
  return matchSentence(relevance?.matches);
}

// True only when `explanation()` would render the actual model output rather than the
// deterministic template — the one case that may carry an "AI-generated" label. The template
// reads like a sentence too, but it's rule-based, not model output.
export function isModelWritten(relevance: Relevance | null | undefined): boolean {
  return !!relevance?.sentence?.trim();
}

// Short badge for a demoted item. `intel` and an absent verdict both render nothing — the
// common case should add no visual noise at all.
const QUALITY_LABELS: Record<string, string> = {
  roundup: 'digest',
  commentary: 'opinion',
  promotion: 'vendor',
};

export function qualityLabel(verdict: string | null | undefined): string | null {
  return (verdict && QUALITY_LABELS[verdict]) || null;
}

// Explains the badge on hover. Says who decided and how confident to be — the classifier is
// conservative and occasionally wrong, and the tooltip should not pretend otherwise.
export function qualityHint(verdict: string | null | undefined): string {
  const label = qualityLabel(verdict);
  if (!label) return '';
  const what = verdict === 'roundup' ? 'a digest of several stories'
    : verdict === 'commentary' ? 'opinion or analysis rather than a report of an incident'
      : 'a product, funding or vendor announcement';
  return `Classified by a local model as ${what}. Ranked lower, not hidden — open it if you disagree.`;
}
