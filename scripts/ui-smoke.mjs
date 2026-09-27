// End-to-end smoke test of the REAL Electron app (real main process, real IPC, real data).
// Launches with an isolated data dir, walks the first-launch flow in Arabic, checks RTL/LTR,
// analyzes a sample file, and saves screenshots to docs/screenshots/.
//
// Usage: node scripts/ui-smoke.mjs [samplePath]
// On Linux CI run under xvfb-run. --no-sandbox is used ONLY by this test harness (root in containers).
import { _electron as electron } from 'playwright';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';

const root = resolve(import.meta.dirname, '..');
const out = join(root, 'docs', 'screenshots');
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-smoke-'));
const sample = process.argv[2];
const yr = process.env.BLAZMA_TEST_YR; // optional: real YARA-X CLI for the Phase 2 flow
const stubOpen = (p) => app.evaluate(({ dialog }, x) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [x] }); }, p);

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

  // Drag & drop path resolution works inside the sandboxed preload (webUtils)
  const dropPath = await win.evaluate(() => window.blazma.files.pathForFile(new File(['x'], 'a.txt')));
  assert.equal(dropPath, '', 'in-memory File has no disk path, but the API must not throw');

  // No horizontal overflow at the minimum window width (RTL)
  await win.setViewportSize({ width: 1100, height: 700 });
  await win.waitForTimeout(300);
  const overflow = await win.locator('.main').evaluate((m) => m.scrollWidth - m.clientWidth);
  assert.ok(overflow <= 1, `horizontal overflow in RTL at 1100px: ${overflow}px`);
  await win.screenshot({ path: join(out, '11-dashboard-ar-min-width.png') });
  await win.setViewportSize({ width: 1440, height: 900 });

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

  // 5b) Phase 2: YARA-X engine + EICAR analysis + quarantine round-trip (English UI)
  if (yr && existsSync(yr)) {
    await win.getByRole('button', { name: 'English' }).click();
    await win.locator('.nav-item', { hasText: 'YARA Scanner' }).click();
    await win.getByRole('tab', { name: 'Engine' }).click();
    await stubOpen(yr);
    await win.getByRole('button', { name: 'Choose yr executable…' }).click();
    await win.getByText(/YARA-X \d+\.\d+\.\d+ is ready/).first().waitFor();
    await win.getByRole('tab', { name: 'Rules' }).click();
    await win.getByRole('button', { name: 'Validate all' }).click();
    await win.getByText('Valid').first().waitFor();
    await win.screenshot({ path: join(out, '12-yara-rules-en.png') });

    // EICAR test file assembled at runtime (never stored contiguously in source)
    const work = mkdtempSync(join(tmpdir(), 'blazma-smoke-eicar-'));
    const eicar = join(work, 'eicar-test.com');
    const eicarBody = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    writeFileSync(eicar, eicarBody);

    await win.locator('.nav-item', { hasText: 'File Analyzer' }).click();
    await stubOpen(eicar);
    await win.getByRole('button', { name: 'Browse…' }).click();
    await win.getByText('YARA rule matched: Blazma_EICAR_Test_File').waitFor({ timeout: 30000 });
    assert.ok(await win.getByText('Suspicious', { exact: true }).isVisible(), 'EICAR should be assessed Suspicious by YARA alone');
    await win.screenshot({ path: join(out, '13-file-analyzer-yara-en.png') });

    // Quarantine it
    await win.getByRole('button', { name: 'Quarantine this file' }).first().click();
    await win.locator('.dialog').getByRole('button', { name: 'Quarantine this file' }).click();
    await win.getByText('Moved to quarantine').first().waitFor();
    assert.equal(existsSync(eicar), false, 'original must be removed after quarantine');

    // Security Center -> Quarantine tab lists it
    await win.locator('.nav-item', { hasText: 'Security Center' }).click();
    await win.getByRole('tab', { name: 'Quarantine' }).click();
    await win.getByText('eicar-test.com').first().waitFor();
    await win.screenshot({ path: join(out, '14-quarantine-en.png') });

    // Re-scan from quarantine
    await win.getByRole('button', { name: 'Re-scan' }).click();
    await win.getByText('Re-scan result').waitFor({ timeout: 30000 });
    await win.getByText('This file is in quarantine').waitFor();

    // Restore to original path, verify exact bytes
    await win.getByRole('button', { name: 'Restore', exact: true }).click();
    await win.locator('.dialog').getByRole('button', { name: 'Restore' }).click();
    await win.getByText('Quarantine is empty').waitFor();
    assert.equal(readFileSync(eicar, 'utf8'), eicarBody, 'restored bytes must match the original');
    rmSync(work, { recursive: true, force: true });

    // Arabic Security Center
    await win.getByRole('button', { name: 'العربية' }).click();
    await win.getByRole('tab', { name: 'نظرة عامة' }).click();
    await win.waitForTimeout(400);
    await win.screenshot({ path: join(out, '15-security-center-ar.png') });
  }

  // 5c) Phase 3: intelligence. Offline Mode (default) must block every external source.
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('.nav-item', { hasText: 'IP Intelligence' }).click();
  await win.getByText('Offline Mode is on: all external sources are blocked').waitFor();
  await win.locator('input.input').first().fill('8.8.8.8');
  await win.getByRole('button', { name: 'Look up', exact: true }).click();
  await win.getByText('Sources', { exact: true }).waitFor();
  const blockedCount = await win.getByText('Blocked: Offline Mode is on', { exact: false }).count();
  assert.ok(blockedCount >= 5, `every source should be blocked offline (got ${blockedCount})`);
  await win.getByRole('button', { name: 'العربية' }).click();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '16-ip-intel-offline-ar.png'), fullPage: true });

  if (process.env.BLAZMA_E2E_ONLINE === '1') {
    // Opt-in live check against the IANA-reserved example.com only.
    await win.locator('.nav-item', { hasText: 'مركز الخصوصية' }).click();
    await win.getByRole('switch', { name: 'وضع عدم الاتصال' }).click();
    await win.getByText('الاستعلامات الخارجية مفعّلة', { exact: false }).first().waitFor();
    await win.locator('.nav-item', { hasText: 'معلومات النطاقات' }).click();
    await win.locator('input.input').first().fill('example.com');
    await win.getByRole('button', { name: 'استعلام', exact: true }).click();
    await win.getByText('أمان البريد').waitFor({ timeout: 30000 });
    await win.waitForTimeout(500);
    await win.screenshot({ path: join(out, '17-domain-intel-ar.png'), fullPage: true });
    await win.getByRole('button', { name: 'English' }).click();
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '18-domain-intel-en.png'), fullPage: true });
    await win.getByRole('button', { name: 'العربية' }).click();
    // Back to Local only
    await win.locator('.nav-item', { hasText: 'مركز الخصوصية' }).click();
    await win.getByRole('switch', { name: 'وضع عدم الاتصال' }).click();
  }

  // 5d) Phase 4: forensics (real processes/sockets) and network toolkit (localhost only)
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('.nav-item', { hasText: 'Windows Forensics' }).click();
  await win.getByText(/\d+ of \d+/).first().waitFor({ timeout: 30000 });
  await win.getByPlaceholder('Filter…').fill('electron');
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '19-forensics-processes-en.png') });
  await win.getByRole('tab', { name: 'Connections' }).click();
  await win.getByText(/\d+ of \d+/).first().waitFor({ timeout: 30000 });

  const srv = createServer((c) => c.end());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  await win.locator('.nav-item', { hasText: 'Network Toolkit' }).click();
  await win.getByText('Loopback').first().waitFor();
  await win.getByRole('tab', { name: 'Port check' }).click();
  await win.locator('input.input.mono').nth(1).fill(`${port},1`);
  await win.getByRole('button', { name: 'Run', exact: true }).click();
  // Authorization is required: the confirm button stays disabled until the box is ticked
  const confirmBtn = win.locator('.dialog').getByRole('button', { name: 'Run' });
  assert.equal(await confirmBtn.isDisabled(), true, 'authorization checkbox must be required');
  await win.locator('.dialog input[type=checkbox]').check();
  await confirmBtn.click();
  await win.getByText(/1 open of 2/).waitFor({ timeout: 20000 });
  await win.getByRole('button', { name: 'العربية' }).click();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '20-port-check-ar.png') });
  srv.close();

  // 5e) Phase 5: Password Recovery — detect a real encrypted archive; engine required + authorization
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('.nav-item', { hasText: 'Password Recovery' }).click();
  await win.getByText('BLAZMA CYBER does not include a recovery engine', { exact: false }).waitFor();
  const zc = process.env.BLAZMA_TEST_ZIP;
  if (zc && existsSync(zc)) {
    await stubOpen(zc);
    await win.getByRole('button', { name: 'Browse…' }).click();
    await win.getByText('zip-zipcrypto').waitFor({ timeout: 15000 });
    // No engine configured in the test environment, so the workspace says so honestly.
    await win.getByText('No recovery engine is configured', { exact: false }).first().waitFor();
    await win.screenshot({ path: join(out, '21-password-recovery-en.png'), fullPage: true });
    await win.getByRole('button', { name: 'العربية' }).click();
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '22-password-recovery-ar.png'), fullPage: true });
  } else {
    await win.getByRole('button', { name: 'العربية' }).click();
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
  await win.locator('.nav-item', { hasText: 'صيد التهديدات' }).click();
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
