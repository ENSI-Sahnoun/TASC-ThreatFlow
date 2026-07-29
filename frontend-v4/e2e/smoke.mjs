// The failure mode the previous frontends actually shipped with was a page that rendered its
// chrome perfectly and no data at all. This asserts the opposite: real values, no console noise.
import { chromium } from 'playwright';

const BASE = process.env.BASE ?? 'http://localhost:4400';

const ROUTES = [
  { path: '/', expect: 'Actively exploited' },
  { path: '/arsenal', expect: 'NVD CVE API' },
  { path: '/intel', expect: 'Intel' },
  { path: '/cve/CVE-2024-3400', expect: 'CVE-2024-3400' },
];

let failures = 0;

const browser = await chromium.launch();
for (const route of ROUTES) {
  const page = await browser.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));

  await page.goto(`${BASE}${route.path}`, { waitUntil: 'networkidle' });
  const body = await page.textContent('body');

  const hasContent = body && body.includes(route.expect);
  // A page that renders only skeletons is a failure, not a pass.
  const stillLoading = await page.locator('tf-skeleton').count() > 0;

  if (!hasContent) { console.error(`FAIL ${route.path}: expected "${route.expect}"`); failures += 1; }
  if (stillLoading) { console.error(`FAIL ${route.path}: still showing skeletons after networkidle`); failures += 1; }
  if (errors.length) { console.error(`FAIL ${route.path}: console errors:\n  ${errors.join('\n  ')}`); failures += 1; }
  if (hasContent && !stillLoading && !errors.length) console.log(`ok   ${route.path}`);

  await page.close();
}
await browser.close();

process.exit(failures ? 1 : 0);
