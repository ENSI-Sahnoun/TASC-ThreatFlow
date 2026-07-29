# ThreatFlow frontend (v4)

Angular 19 SPA — standalone components, signals for state, ECharts for visualization.
See the [root README](../README.md) for full project setup, architecture and the API reference.

The backend must already be running on `:4173` — this app has no data source of its own.

```bash
npm install
npm start        # ng serve on :4400, proxying /api -> :4173 via proxy.conf.json
npm run build    # production bundle into dist/
npm test         # tsc --noEmit + vitest
npm run smoke    # Playwright smoke run against a live dev server
npm run typecheck
```

## Layout

```
src/app/
  shell/     app chrome — nav, command palette
  pages/     routed pages: dashboard, arsenal, intel, entity, check
  charts/    ECharts wrappers (bar, donut, world map) + shared theme
  ui/        presentational components — KPI tiles, stat cards, sparklines, empty states
  core/      api.service, models, formatters, theme.service, design tokens
```

Design tokens live in `src/app/core/tokens.css` and drive both light and dark themes through
`core/theme.service.ts`. Add new colors and spacing there rather than in component styles.
