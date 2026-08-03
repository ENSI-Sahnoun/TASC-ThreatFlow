import { describe, it, expect } from 'vitest';
import { syncAssets, setExposure, type SurveyAsset } from './assets';

// The exposure step's whole behaviour, extracted as pure functions so it is testable without a
// DOM — vitest runs in a node environment here with no TestBed, matching the rest of the app.

describe('syncAssets', () => {
  it('creates one asset per chosen product, defaulting to unknown', () => {
    expect(syncAssets(['fortios', 'windows'], [])).toEqual([
      { product: 'fortios', exposure: 'unknown' },
      { product: 'windows', exposure: 'unknown' },
    ]);
  });

  // A user who answers, goes back to change their product list, and returns must not lose the
  // answers they already gave.
  it('preserves answers already given', () => {
    const existing: SurveyAsset[] = [{ product: 'fortios', exposure: 'internet' }];
    expect(syncAssets(['fortios', 'windows'], existing)).toEqual([
      { product: 'fortios', exposure: 'internet' },
      { product: 'windows', exposure: 'unknown' },
    ]);
  });

  it('drops assets for products no longer selected', () => {
    const existing: SurveyAsset[] = [
      { product: 'fortios', exposure: 'internet' },
      { product: 'windows', exposure: 'internal' },
    ];
    expect(syncAssets(['fortios'], existing)).toEqual([
      { product: 'fortios', exposure: 'internet' },
    ]);
  });

  it('follows the product order, not the answer order', () => {
    const existing: SurveyAsset[] = [{ product: 'windows', exposure: 'internal' }];
    expect(syncAssets(['fortios', 'windows'], existing).map((a) => a.product))
      .toEqual(['fortios', 'windows']);
  });

  it('handles an empty product list', () => {
    expect(syncAssets([], [{ product: 'fortios', exposure: 'internet' }])).toEqual([]);
  });
});

describe('setExposure', () => {
  it('changes only the named product', () => {
    const assets: SurveyAsset[] = [
      { product: 'fortios', exposure: 'unknown' },
      { product: 'windows', exposure: 'unknown' },
    ];
    expect(setExposure(assets, 'fortios', 'internet')).toEqual([
      { product: 'fortios', exposure: 'internet' },
      { product: 'windows', exposure: 'unknown' },
    ]);
  });

  it('is a no-op for a product that is not listed', () => {
    const assets: SurveyAsset[] = [{ product: 'fortios', exposure: 'unknown' }];
    expect(setExposure(assets, 'ghost', 'internet')).toEqual(assets);
  });

  it('does not mutate its input', () => {
    const assets: SurveyAsset[] = [{ product: 'fortios', exposure: 'unknown' }];
    setExposure(assets, 'fortios', 'internal');
    expect(assets[0].exposure).toBe('unknown');
  });
});
