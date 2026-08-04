import type { Exposure } from '../../core/models';

// The onboarding exposure step, as pure functions. Keeping the logic out of the component is
// what makes it testable in this app: vitest runs in a node environment with no TestBed, so
// components stay thin bindings.
//
// No vendor here. CpeFacet is { value, refs } and the product step is a bare string[], so the
// client genuinely has no vendor to send — the server resolves it from item_cpes on write.
export interface SurveyAsset {
  product: string;
  exposure: Exposure;
}

// Called when leaving the tech step. Adds a row for each newly chosen product at 'unknown',
// drops rows for products no longer selected, and preserves every answer already given — a
// user who goes back to edit their product list must not lose the exposures they answered.
export function syncAssets(products: string[], existing: SurveyAsset[]): SurveyAsset[] {
  const answered = new Map(existing.map((a) => [a.product, a.exposure]));
  return products.map((product) => ({
    product,
    exposure: answered.get(product) ?? 'unknown',
  }));
}

export function setExposure(assets: SurveyAsset[], product: string, exposure: Exposure): SurveyAsset[] {
  return assets.map((a) => (a.product === product ? { ...a, exposure } : a));
}
