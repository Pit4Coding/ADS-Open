import { chromium } from 'file:///C:/Users/pierre/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';
import fs from 'node:fs';

const [outputPath, ...ids] = process.argv.slice(2);
if (!outputPath || ids.length === 0) {
  throw new Error('Usage: node Extract-AnssiRendered.mjs <output.json> <id...>');
}

const browser = await chromium.launch({
  headless: true,
  executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
});
const results = [];
let nextIndex = 0;
async function worker() {
  while (true) {
    const index = nextIndex++;
    if (index >= ids.length) return;
    const id = ids[index];
    console.log(id);
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    await page.goto(`https://www.cert.ssi.gouv.fr/uploads/ad_checklist.html#${id}`, {
      waitUntil: 'networkidle', timeout: 60000
    });
    const modal = page.locator('#myModal');
    await modal.waitFor({ state: 'visible', timeout: 15000 });
    const title = await modal.locator('h1').first().innerText();
    const sections = await modal.locator('tbody > tr').evaluateAll(rows => rows.map(row => ({
      text: (row.innerText || '').trim(),
      html: row.innerHTML
    })));
    results[index] = { id, title, description: sections[0]?.text || '', recommendation: sections[1]?.text || '', sections };
    await page.close();
  }
}
await Promise.all(Array.from({ length: Math.min(6, ids.length) }, () => worker()));await browser.close();
fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), 'utf8');
