// Read the real token values off the document so the chart palette and the CSS palette can
// never drift apart. ECharts needs concrete colours, not var() references.
// Exported so every chart component resolves colour through this one helper — never a second
// copy of the same getComputedStyle lookup, never a literal hex.
export function token(name: string, fallback: string): string {
  if (typeof getComputedStyle !== 'function') return fallback;
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

// Chart components accept colour inputs as either a bare custom-property name ("--sev-critical")
// or a literal var(--x) reference (so callers can reuse the same string they'd use in a
// template's inline style). This normalizes both forms and resolves through token().
export function resolveVar(ref: string, fallback: string): string {
  const match = /^var\((--[\w-]+)\)$/.exec(ref.trim());
  return token(match ? match[1] : ref, fallback);
}

// --ink-2 is a real token in core/tokens.css — resolved once here and exported so every chart
// component consumes this single resolved value instead of each repeating the literal.
export function ink2(): string {
  return token('--ink-2', 'rgba(235,235,245,.62)');
}

export function buildTheme() {
  const ink = token('--ink', '#ffffff');
  const ink2Value = ink2();
  const hairline = token('--hairline', 'rgba(255,255,255,.11)');

  return {
    color: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => token(`--cat-${i}`, '#0a84ff')),
    backgroundColor: 'transparent',
    textStyle: { fontFamily: 'Poppins, -apple-system, system-ui, sans-serif', color: ink2Value },
    grid: { left: 8, right: 8, top: 16, bottom: 8, containLabel: true },
    categoryAxis: {
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: ink2Value, fontSize: 11 },
      splitLine: { show: false },
    },
    valueAxis: {
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: ink2Value, fontSize: 11 },
      splitLine: { lineStyle: { color: hairline } },
    },
    tooltip: {
      backgroundColor: token('--surface', '#1c1c1e'),
      borderColor: hairline, borderWidth: 1,
      textStyle: { color: ink, fontSize: 12 },
      extraCssText: 'backdrop-filter: blur(20px); border-radius: 10px;',
    },
    legend: { textStyle: { color: ink2Value, fontSize: 11 }, icon: 'circle', itemWidth: 8, itemHeight: 8 },
  };
}

export const THEME_NAME = 'threatflow';
