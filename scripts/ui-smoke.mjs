// End-to-end smoke test of the REAL Electron app (real main process, real IPC, real data).
// Launches with an isolated data dir, walks the first-launch flow in Arabic, checks RTL/LTR,
// analyzes a sample file, and saves screenshots to docs/screenshots/.
//
// Usage: node scripts/ui-smoke.mjs [samplePath]
// On Linux CI run under xvfb-run. --no-sandbox is used ONLY by this test harness (root in containers).
import { _electron as electron } from 'playwright';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';

const root = resolve(import.meta.dirname, '..');
const out = join(root, 'docs', 'screenshots');
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-smoke-'));
const sample = process.argv[2];

const app = await electron.launch({
  executablePath: join(root, 'node_modules', 'electron', 'dist', process.platform === 'win32' ? 'electron.exe' : 'electron'),
  args: [...(process.platform === 'linux' ? ['--no-sandbox'] : []), root],
  env: { ...process.env, BLAZMA_DATA_DIR: dataDir },
});

const errors = [];
try {
  const win = await app.firstWindow();
  win.on('pageerror', (e) => errors.push(String(e)));
  win.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await win.setViewportSize({ width: 1440, height: 900 });

  // 1) First launch: bilingual language picker
  await win.getByText('اختر اللغة').waitFor();
  await win.waitForTimeout(700); // entrance animation
  await win.screenshot({ path: join(out, '01-language-picker.png') });

  // 2) Choose Arabic -> RTL dashboard
  await win.getByRole('button', { name: /العربية/ }).first().click();
  await win.getByRole('button', { name: 'متابعة' }).click();
  await win.locator('h1', { hasText: 'لوحة التحكم' }).waitFor();
  assert.equal(await win.evaluate(() => document.documentElement.dir), 'rtl');
  assert.equal(await win.evaluate(() => document.documentElement.lang), 'ar');
  // Sidebar must be on the right in RTL
  const sb = await win.locator('.sidebar').boundingBox();
  assert.ok(sb && sb.x > 700, `sidebar should be on the right in RTL (x=${sb?.x})`);
  await win.waitForTimeout(7000); // let CPU samples accumulate (real data)
  await win.screenshot({ path: join(out, '02-dashboard-ar.png') });

  // 3) Switch to English -> LTR
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('h1', { hasText: 'Dashboard' }).waitFor();
  assert.equal(await win.evaluate(() => document.documentElement.dir), 'ltr');
  const sb2 = await win.locator('.sidebar').boundingBox();
  assert.ok(sb2 && sb2.x < 10, 'sidebar should be on the left in LTR');
  await win.waitForTimeout(3500);
  await win.screenshot({ path: join(out, '03-dashboard-en.png') });

  // 4) Offline Mode blocks the external public-IP lookup (default is Local Only)
  const blocked = await win.evaluate(() => window.blazma.privacy.publicIp());
  assert.deepEqual(blocked, { ok: false, error: 'offline_mode' });

  // 5) File analysis of a real sample (dialog stubbed to return the path)
  if (sample) {
    await app.evaluate(({ dialog }, p) => {
      dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [p] });
    }, resolve(sample));
    await win.getByRole('button', { name: 'Scan File' }).click();
    await win.getByRole('button', { name: 'Browse…' }).click();
    await win.getByText('Why this result').waitFor({ timeout: 30000 });
    await win.screenshot({ path: join(out, '04-file-analyzer-en.png'), fullPage: true });

    await win.getByRole('button', { name: 'العربية' }).click();
    await win.getByText('سبب هذه النتيجة').waitFor();
    await win.locator('.main').evaluate((m) => m.scrollTo(0, 0));
    await win.screenshot({ path: join(out, '05-file-analyzer-ar.png') });
    await win.locator('.main').evaluate((m) => m.scrollTo(0, 700));
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '06-file-analyzer-pe-ar.png') });
  }

  // 6) Hash Lab identify (Arabic)
  await win.locator('.nav-item', { hasText: 'مختبر الهاشات' }).click();
  await win.getByRole('tab', { name: 'تعرّف' }).click();
  await win.locator('input.input').fill('5d41402abc4b2a76b9719d911017c592');
  await win.getByRole('button', { name: 'تعرّف' }).last().click();
  await win.getByText('الصيغ المحتملة').waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '07-hashlab-ar.png') });

  // 7) Privacy Center shows the blocked request in Network Activity
  await win.locator('.nav-item', { hasText: 'مركز الخصوصية' }).click();
  await win.getByText('محجوب (دون اتصال)').first().waitFor();
  await win.screenshot({ path: join(out, '08-privacy-ar.png') });

  // 8) A planned module is labeled honestly
  await win.locator('.nav-item', { hasText: 'استعادة كلمات المرور' }).click();
  await win.getByText('هذه الوحدة غير متاحة بعد').waitFor();
  await win.screenshot({ path: join(out, '09-planned-module-ar.png') });

  // 9) Settings (English)
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('.nav-item', { hasText: 'Appearance' }).click();
  await win.getByText('Theme').first().waitFor();
  await win.screenshot({ path: join(out, '10-settings-en.png') });

  assert.deepEqual(errors, [], `renderer errors:\n${errors.join('\n')}`);
  console.log('UI smoke test passed. Screenshots in docs/screenshots/');
} finally {
  await app.close();
  rmSync(dataDir, { recursive: true, force: true });
}
