// Smoke-tests a PACKAGED build (release/*-unpacked). The packaged app has the Node inspector fuse
// disabled, so Playwright's electron.launch() can't attach; we use Chromium's DevTools protocol instead.
// Usage: xvfb-run -a node scripts/package-smoke.mjs [path-to-executable] [--portable]
// --portable: the copy has portable.txt next to it; its data must land in <exe dir>/BLAZMA-data.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const portable = args.includes('--portable');
const exe = args.find((a) => !a.startsWith('--')) ?? join(root, 'release', 'linux-unpacked', 'blazma-cyber');
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-pkg-'));
const port = 9300 + Math.floor(Math.random() * 500);

const child = spawn(exe, [...(process.platform === 'linux' ? ['--no-sandbox'] : []), `--remote-debugging-port=${port}`], {
  env: portable ? { ...process.env, BLAZMA_DATA_DIR: '' } : { ...process.env, BLAZMA_DATA_DIR: dataDir },
  stdio: 'ignore',
});

try {
  let browser = null;
  for (let i = 0; i < 60 && !browser; i++) {
    await new Promise((r) => setTimeout(r, 500));
    browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`).catch(() => null);
  }
  assert.ok(browser, 'packaged app did not expose a window');
  let page = null;
  for (let i = 0; i < 40 && !page; i++) {
    page = browser.contexts().flatMap((c) => c.pages()).find((p) => p.url().startsWith('file:')) ?? null;
    if (!page) await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(page, 'renderer page not found');
  // First launch: the language picker proves the renderer, preload bridge and locales all loaded from app.asar.
  await page.getByText('العربية').first().waitFor({ timeout: 20000 });
  await page.getByText('English').first().waitFor();
  const bridge = await page.evaluate(() => typeof window.blazma === 'object' && typeof window.blazma.settings?.get === 'function');
  assert.equal(bridge, true, 'preload bridge missing');
  const nodeLeak = await page.evaluate(() => typeof (globalThis).require);
  assert.equal(nodeLeak, 'undefined', 'renderer must not have Node access');
  await page.screenshot({ path: join(root, 'docs', 'screenshots', '27-packaged-first-launch.png') });
  // Pages are code-split: open one to prove lazy chunks load from app.asar.
  await page.getByText('العربية').first().click();
  await page.getByRole('radio', { name: /احترافي/ }).click();
  await page.getByRole('button', { name: 'متابعة' }).click();
  await page.locator('.nav-item', { hasText: 'محلل الملفات' }).click();
  await page.locator('.page-title', { hasText: 'محلل الملفات' }).waitFor({ timeout: 15000 });
  if (portable) {
    const own = join(dirname(exe), 'BLAZMA-data');
    assert.ok(existsSync(join(own, 'state', 'settings.json')), 'portable copy must keep its settings next to the program');
    assert.ok(existsSync(join(own, 'electron')), "portable copy must keep Chromium's data next to the program");
    const info = await page.evaluate(() => window.blazma.app.info());
    assert.equal(info.portable, true);
    console.log('Portable mode verified:', own);
  }
  await browser.close();
  console.log('Packaged app smoke test passed.');
} finally {
  child.kill();
  rmSync(dataDir, { recursive: true, force: true });
}
