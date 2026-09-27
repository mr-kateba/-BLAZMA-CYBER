// End-to-end smoke test of the REAL Electron app (real main process, real IPC, real data).
// Launches with an isolated data dir, walks the first-launch flow in Arabic, checks RTL/LTR,
// analyzes a sample file, and saves screenshots to docs/screenshots/.
//
// Usage: node scripts/ui-smoke.mjs [samplePath]
// On Linux CI run under xvfb-run. --no-sandbox is used ONLY by this test harness (root in containers).
import { _electron as electron } from 'playwright';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createRequire } from 'node:module';

const root = resolve(import.meta.dirname, '..');
const out = join(root, 'docs', 'screenshots');
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-smoke-'));
const sample = process.argv[2];
const yr = process.env.BLAZMA_TEST_YR; // optional: real YARA-X CLI for the Phase 2 flow
const stubOpen = (p) => app.evaluate(({ dialog }, x) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [x] }); }, p);

const app = await electron.launch({
  // require('electron') returns the binary path and downloads it first if npm skipped that step.
  executablePath: createRequire(import.meta.url)('electron'),
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

  // 2) Choose Arabic + Expert mode (this test walks every module) -> RTL dashboard
  await win.getByRole('button', { name: /العربية/ }).first().click();
  await win.getByRole('radio', { name: /احترافي/ }).click();
  await win.getByRole('button', { name: 'متابعة' }).click();
  await win.locator('h1', { hasText: 'لوحة التحكم' }).waitFor();
  assert.equal(await win.evaluate(() => document.documentElement.dir), 'rtl');
  assert.equal(await win.evaluate(() => document.documentElement.lang), 'ar');
  // Sidebar must be on the right in RTL
  const sb = await win.locator('.sidebar').boundingBox();
  assert.ok(sb && sb.x > 700, `sidebar should be on the right in RTL (x=${sb?.x})`);
  await win.waitForTimeout(7000); // let CPU samples accumulate (real data)
  await win.screenshot({ path: join(out, '02-dashboard-ar.png') });

  // Device Security Score: the dashboard hero and the page. Real score on Windows; elsewhere the
  // app says it's Windows-only (never a made-up score).
  await win.getByRole('button', { name: 'افحص ملفًا' }).waitFor();
  await win.locator('.nav-item', { hasText: 'أمان جهازي' }).click();
  if (process.platform === 'win32') {
    await win.getByText('الفحوص', { exact: true }).waitFor({ timeout: 90000 });
    const rows = await win.locator('.devsec-row').count();
    assert.ok(rows >= 10, `device security should list its checks (got ${rows})`);
    await win.locator('.devsec-head').first().click();
    await win.getByText('لماذا يهم:').first().waitFor();
  } else {
    await win.getByText('متاح على Windows فقط.').first().waitFor({ timeout: 30000 });
  }
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '28-device-security-ar.png'), fullPage: true });
  await win.locator('.nav-item', { hasText: 'لوحة التحكم' }).click();

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
    // "What does this mean?" explains a technical term in plain Arabic; Escape closes it.
    const explainBtn = win.getByRole('button', { name: 'ما معنى «الإنتروبيا (العشوائية)»؟' });
    await explainBtn.evaluate((el) => el.scrollIntoView({ block: 'center' }));
    await explainBtn.click();
    await win.getByText('مقياس للعشوائية من 0 إلى 8', { exact: false }).waitFor();
    await win.screenshot({ path: join(out, '29-explain-ar.png') });
    await win.keyboard.press('Escape');
    await win.getByText('مقياس للعشوائية من 0 إلى 8', { exact: false }).waitFor({ state: 'detached' });
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

  // "Is this site trustworthy?" never guesses: offline, it says there isn't enough information.
  await win.locator('.nav-item', { hasText: 'معلومات النطاقات' }).click();
  await win.locator('input.input').first().fill('example.com');
  await win.getByRole('button', { name: 'استعلام', exact: true }).click();
  await win.getByText('هل هذا الموقع موثوق؟').waitFor({ timeout: 30000 });
  await win.getByText('لا توجد معلومات كافية').first().waitFor();

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

  // 5f) Phase 6: case → evidence → note → Arabic HTML report → threat hunting correlation
  await app.evaluate(({ shell }) => { shell.openPath = async () => ''; shell.showItemInFolder = () => {}; });
  await win.getByRole('button', { name: 'English' }).click();
  await win.locator('.nav-item', { hasText: 'Cases' }).click();
  await win.getByText('No cases yet').waitFor();
  await win.getByLabel('Case name').fill('E2E phishing <b>wave</b>');
  await win.getByRole('button', { name: 'Create case' }).click();
  await win.getByText(/CASE-\d{4}-001/).first().waitFor();
  await win.locator('input.input.mono').first().fill('203.0.113.77');
  await win.getByRole('button', { name: 'Add', exact: true }).click();
  await win.getByText('203.0.113.77').first().waitFor();
  await win.getByRole('tab', { name: 'Analyst notes' }).click();
  await win.getByPlaceholder('Write an analyst note…').fill('Sender domain spoofed; see headers.');
  await win.getByRole('button', { name: 'Add note' }).click();
  await win.getByText('Sender domain spoofed').waitFor();
  await win.getByRole('button', { name: 'العربية' }).click();
  await win.getByRole('tab', { name: 'التقرير' }).click();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '23-case-report-ar.png') });
  await win.getByRole('button', { name: 'إنشاء تقرير' }).first().click();
  await win.getByText('أُنشئ التقرير').first().waitFor({ timeout: 20000 });
  const repDir = join(dataDir, 'reports');
  const html = readdirSync(repDir).filter((f) => f.endsWith('.html')).map((f) => readFileSync(join(repDir, f), 'utf8'))[0];
  assert.ok(html, 'an HTML report file must exist');
  assert.match(html, /<html lang="ar" dir="rtl">/);
  assert.ok(html.includes('203.0.113.77'), 'report contains the evidence');
  assert.ok(!html.includes('<b>wave</b>') && html.includes('&lt;b&gt;wave&lt;/b&gt;'), 'case name must be escaped');
  assert.ok(!/<script/i.test(html), 'report contains no scripts');

  await win.locator('.nav-item', { hasText: 'التقارير' }).click();
  await win.getByText('HTML').first().waitFor();
  await win.screenshot({ path: join(out, '24-reports-ar.png') });

  await win.locator('.nav-item', { hasText: 'صيد التهديدات' }).click();
  await win.locator('input.input.mono').first().fill('203.0.113.77');
  await win.getByRole('button', { name: 'ابحث', exact: true }).click();
  await win.getByText(/نتيجة ·/).first().waitFor({ timeout: 30000 });
  await win.getByText(/CASE-\d{4}-001/).first().waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '25-threat-hunting-ar.png') });

  // 5g) Phase 7: OSINT workspace. Offline Mode blocks every source and every pivot link;
  //     each source row carries its provenance (the public endpoint that would have been queried).
  const offlineAr = 'محجوب: وضع عدم الاتصال مفعّل';
  await win.locator('.nav-item', { hasText: 'مساحة OSINT' }).click();
  await win.locator('input.input.mono').first().fill('not a domain');
  await win.getByText('هذه القيمة غير صالحة لنوع الهدف المحدد.').waitFor();
  await win.locator('input.input.mono').first().fill('example.com');
  await win.getByRole('button', { name: 'استعلام', exact: true }).click();
  await win.getByText('التتبع في مصادر عامة').waitFor({ timeout: 30000 });
  const osintBlocked = await win.getByText(offlineAr, { exact: false }).count();
  assert.ok(osintBlocked >= 4, `OSINT sources must be blocked offline (got ${osintBlocked})`);
  await win.getByText('https://crt.sh/?q=%25.example.com&output=json').waitFor();
  await win.getByRole('button', { name: 'موقع crt.sh' }).click();
  await win.getByText('سيفتح متصفحك crt.sh', { exact: false }).waitFor();
  await win.keyboard.press('Escape'); // keyboard: Escape cancels a dialog
  await win.getByText('سيفتح متصفحك crt.sh', { exact: false }).waitFor({ state: 'detached' });
  await win.getByRole('button', { name: 'موقع crt.sh' }).click();
  await win.getByText('سيفتح متصفحك crt.sh', { exact: false }).waitFor();
  await win.getByRole('button', { name: 'فتح في المتصفح' }).click();
  await win.locator('.toast', { hasText: offlineAr }).first().waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '26-osint-offline-ar.png'), fullPage: true });

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

  // 8) "Terminal" opens the regular Windows terminal in its own window (not a page inside BLAZMA).
  //    On Windows a separate terminal window really opens; elsewhere the app says it's Windows-only.
  const pageBefore = await win.locator('.page-title').first().textContent();
  await win.locator('.nav-item', { hasText: 'الطرفية' }).click();
  const terminalToast = process.platform === 'win32' ? /فُتحت (Windows Terminal|PowerShell) في نافذة منفصلة/ : 'متاح على Windows فقط.';
  await win.locator('.toast', { hasText: terminalToast }).first().waitFor();
  assert.equal(await win.locator('.page-title').first().textContent(), pageBefore, 'terminal must not navigate away');

  // 8b) Simple mode: only the essentials in the sidebar, friendlier labels; switch back to expert.
  const expertItems = await win.locator('.nav-item').count();
  await win.getByRole('button', { name: 'الوضع البسيط' }).click();
  await win.locator('.nav-item', { hasText: 'افحص رابطًا أو موقعًا' }).waitFor();
  const simpleItems = await win.locator('.nav-item').count();
  assert.ok(simpleItems <= 8 && simpleItems < expertItems, `simple mode should show only the essentials (${simpleItems} vs ${expertItems})`);
  await win.locator('.nav-item', { hasText: 'لوحة التحكم' }).click();
  await win.locator('.hero').getByRole('button', { name: 'افحص ملفًا' }).waitFor();
  // Drag a file anywhere: the drop overlay appears; a file without a real path is refused honestly.
  await win.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['x'], 'x.txt'));
    window.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
  });
  await win.getByText('أفلت الملف لفحصه', { exact: false }).waitFor();
  await win.screenshot({ path: join(out, '30-simple-mode-ar.png') });
  await win.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['x'], 'x.txt'));
    window.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
  });
  await win.getByText('أفلت الملف لفحصه', { exact: false }).waitFor({ state: 'detached' });
  await win.locator('.toast').first().waitFor();
  await win.getByRole('button', { name: 'اعرض كل الأدوات (الوضع الاحترافي)' }).click();
  await win.locator('.nav-item', { hasText: 'صيد التهديدات' }).waitFor();

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
