// Framework-free text-alternative generation for chart components. ECharts renders to a
// <canvas>, which is invisible to a screen reader — every chart panel needs a words-only
// description of the same data the canvas draws, per the accessibility audit (Task 15).
// Kept pure/testable so a data shape change can't silently drop the description.

export interface LabelValue { label: string; value: number; }
export interface CountryValue { code: string; count: number; }

const listify = (parts: string[]): string => {
  if (parts.length <= 1) return parts.join('');
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}`;
};

// Bar chart: an ordered list of categories, each with a magnitude. When `withValues` is false
// (the vendors-affected chart, whose "1" per bar is a layout placeholder, not a measurement) the
// summary states presence only, matching what `showLabels=false` does visually.
export function describeBarChart(data: LabelValue[], withValues = true): string {
  if (!data.length) return 'No data to show.';
  const parts = data.map((d) => (withValues ? `${d.label}: ${d.value}` : d.label));
  const noun = data.length === 1 ? 'bar' : 'bars';
  return `Bar chart, ${data.length} ${noun}. ${listify(parts)}.`;
}

// Donut chart: a share-of-whole breakdown. Percentages (not raw counts) are what a donut
// actually encodes visually, so the text alternative reports the same thing.
export function describeDonutChart(data: LabelValue[]): string {
  if (!data.length) return 'No data to show.';
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const parts = data.map((d) => `${d.label} ${total > 0 ? Math.round((d.value / total) * 100) : 0}%`);
  const noun = data.length === 1 ? 'segment' : 'segments';
  return `Donut chart, ${data.length} ${noun}. ${listify(parts)}.`;
}

// Choropleth: report the top entries by count rather than every country, or the sentence
// becomes unreadable for a 40+ country payload.
export function describeWorldMap(data: CountryValue[], topN = 8): string {
  if (!data.length) return 'No data to show.';
  const sorted = [...data].sort((a, b) => b.count - a.count);
  const shown = sorted.slice(0, topN);
  const parts = shown.map((d) => `${d.code} ${d.count}`);
  const remainder = sorted.length - shown.length;
  const tail = remainder > 0 ? `, and ${remainder} more ${remainder === 1 ? 'country' : 'countries'}` : '';
  const noun = sorted.length === 1 ? 'country' : 'countries';
  return `World map, ${sorted.length} ${noun}. ${listify(parts)}${tail}.`;
}
