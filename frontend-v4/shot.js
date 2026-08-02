const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1000, height: 700 } });
  await page.goto('http://127.0.0.1:4400/intel/454287', { waitUntil: 'load', timeout: 60000 });
  await page.waitForTimeout(4000);
  await page.screenshot({ path: '/tmp/claude-1000/-home-sah-projects/1e184334-4339-4b57-8354-7fad8a7fb311/scratchpad/item-detail-current.png' });
  await browser.close();
})();
