import { describe, it, expect } from 'vitest';
import { describeBarChart, describeDonutChart, describeWorldMap } from './chart-summary';

describe('describeBarChart', () => {
  it('lists label:value pairs with an oxford-comma join', () => {
    const s = describeBarChart([
      { label: 'Critical', value: 12 },
      { label: 'High', value: 8 },
      { label: 'Medium', value: 3 },
    ]);
    expect(s).toBe('Bar chart, 3 bars. Critical: 12, High: 8, and Medium: 3.');
  });

  it('drops values when withValues is false (presence-only data)', () => {
    const s = describeBarChart([{ label: 'Acme Corp', value: 1 }, { label: 'Globex', value: 1 }], false);
    expect(s).toBe('Bar chart, 2 bars. Acme Corp and Globex.');
  });

  it('handles a single bar without "and"', () => {
    expect(describeBarChart([{ label: 'Only', value: 5 }])).toBe('Bar chart, 1 bar. Only: 5.');
  });

  it('reports empty data', () => {
    expect(describeBarChart([])).toBe('No data to show.');
  });
});

describe('describeDonutChart', () => {
  it('converts values to percentages of the total', () => {
    const s = describeDonutChart([
      { label: 'Ransomware', value: 30 },
      { label: 'Loader', value: 10 },
    ]);
    expect(s).toBe('Donut chart, 2 segments. Ransomware 75% and Loader 25%.');
  });

  it('does not divide by zero when every value is zero', () => {
    const s = describeDonutChart([{ label: 'A', value: 0 }, { label: 'B', value: 0 }]);
    expect(s).toBe('Donut chart, 2 segments. A 0% and B 0%.');
  });

  it('reports empty data', () => {
    expect(describeDonutChart([])).toBe('No data to show.');
  });
});

describe('describeWorldMap', () => {
  it('sorts by count descending and caps at topN', () => {
    const data = [
      { code: 'US', count: 40 }, { code: 'DE', count: 12 }, { code: 'FR', count: 8 },
    ];
    expect(describeWorldMap(data, 2)).toBe('World map, 3 countries. US 40 and DE 12, and 1 more country.');
  });

  it('omits the remainder clause when everything fits', () => {
    const data = [{ code: 'US', count: 40 }, { code: 'DE', count: 12 }];
    expect(describeWorldMap(data, 8)).toBe('World map, 2 countries. US 40 and DE 12.');
  });

  it('reports empty data', () => {
    expect(describeWorldMap([])).toBe('No data to show.');
  });
});
