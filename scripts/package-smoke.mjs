// Smoke-tests a PACKAGED build (release/*-unpacked). The packaged app has the Node inspector fuse
// disabled, so Playwright's electron.launch() can't attach; we use Chromium's DevTools protocol instead.
// Usage: xvfb-run -a node scripts/package-smoke.mjs [path-to-executable]
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const root = new URL('..', import.meta.url).pathname;
const exe = process.argv[2] ?? join(root, 'release', 'linux-unpacked', 'blazma-cyber');
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-pkg-'));
const port = 9300 + Math.floor(Math.random() * 500);

const child = spawn(exe, [...(process.platform === 'linux' ? ['--no-sandbox'] : []), `--remote-debugging-port=${port}`], {
  env: { ...process.env, BLAZMA_DATA_DIR: dataDir },
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
  await browser.close();
  console.log('Packaged app smoke test passed.');
} finally {
  child.kill();
  rmSync(dataDir, { recursive: true, force: true });
}
