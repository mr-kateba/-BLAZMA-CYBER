// End-to-end smoke test of the REAL Electron app (real main process, real IPC, real data).
// Launches with an isolated data dir, walks the first-launch flow in Arabic, checks RTL/LTR,
// analyzes a sample file, and saves screenshots to docs/screenshots/.
//
// Usage: node scripts/ui-smoke.mjs [samplePath]
// On Linux CI run under xvfb-run. --no-sandbox is used ONLY by this test harness (root in containers).
import { _electron as electron } from 'playwright';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';

// The top-bar controls must stay inside the title-bar area left free by the native caption buttons
// (Window Controls Overlay). Only checked where the overlay is active (Windows).
async function assertClearOfCaptionButtons(win, label) {
  const r = await win.evaluate(() => {
    const o = navigator.windowControlsOverlay;
    if (!o || !o.visible) return null;
    const area = o.getTitlebarAreaRect();
    const els = [...document.querySelectorAll('.topbar .brand, .topbar-actions')].map((e) => e.getBoundingClientRect());
    return { area: { x: area.x, w: area.width }, els: els.map((b) => ({ l: b.left, r: b.right })) };
  });
  if (!r) return;
  for (const b of r.els) {
    assert.ok(b.l >= r.area.x - 1 && b.r <= r.area.x + r.area.w + 1, `${label}: top-bar content [${b.l}, ${b.r}] overlaps the caption buttons (free area x=${r.area.x} w=${r.area.w})`);
  }
}
import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { createRequire } from 'node:module';

const root = resolve(import.meta.dirname, '..');
const out = join(root, 'docs', 'screenshots');
mkdirSync(out, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), 'blazma-smoke-'));
// Linux: a fixture browser profile (XDG_CONFIG_HOME) for the extensions audit — one extension loaded
// from a folder with access to all sites, one from the store. On Windows the runner's real browsers are read.
const xdg = join(dataDir, 'xdg');
if (process.platform === 'linux') {
  const prof = join(xdg, 'google-chrome', 'Default');
  const put = (id, name, manifest) => {
    mkdirSync(join(prof, 'Extensions', id, '1.0_0'), { recursive: true });
    writeFileSync(join(prof, 'Extensions', id, '1.0_0', 'manifest.json'), JSON.stringify({ name, version: '1.0', manifest_version: 3, ...manifest }));
  };
  put('a'.repeat(32), 'Free PDF Converter', { permissions: ['webRequest', 'cookies'], host_permissions: ['<all_urls>'] });
  put('b'.repeat(32), 'Simple Notes', { permissions: ['storage'] });
  mkdirSync(join(dataDir, 'Downloads'), { recursive: true });
  writeFileSync(join(xdg, 'user-dirs.dirs'), `XDG_DOWNLOAD_DIR="${join(dataDir, 'Downloads')}"\n`);
  writeFileSync(join(prof, 'Secure Preferences'), JSON.stringify({ extensions: { settings: { ['a'.repeat(32)]: { location: 4, state: 1 }, ['b'.repeat(32)]: { location: 1, state: 1 } } } }));
}
const sample = process.argv[2];
const yr = process.env.BLAZMA_TEST_YR; // optional: real YARA-X CLI for the Phase 2 flow
const stubOpen = (p) => app.evaluate(({ dialog }, x) => { dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [x] }); }, p);

const app = await electron.launch({
  // require('electron') returns the binary path and downloads it first if npm skipped that step.
  executablePath: createRequire(import.meta.url)('electron'),
  args: [...(process.platform === 'linux' ? ['--no-sandbox'] : []), root],
  env: { ...process.env, BLAZMA_DATA_DIR: dataDir, ...(process.platform === 'linux' ? { XDG_CONFIG_HOME: xdg } : {}) },
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
  await assertClearOfCaptionButtons(win, 'ar');
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
  // Signs of tampering: the hosts file is read on every OS; the other checks are Windows-only.
  await win.getByText('علامات العبث بالإعدادات').waitFor();
  await win.locator('.devsec-title', { hasText: 'ملف hosts' }).waitFor({ timeout: 60000 });
  assert.equal(await win.locator('.devsec-title', { hasText: 'شهادات موثوقة مضافة' }).count(), 1);
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
  await assertClearOfCaptionButtons(win, 'en');
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
    // Bundled engines (capa can take a while on a real program).
    await win.getByText('Why this result').waitFor({ timeout: 240000 });
    if (existsSync(join(root, 'build', 'engines', 'manifest.json')) && process.platform === 'win32') {
      await win.getByText('What can this program do?').waitFor();
      await win.getByText('Built with').first().waitFor();
    }
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
    await win.getByText('YARA rule matched: Blazma_EICAR_Test_File').waitFor({ timeout: 240000 });
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
  await win.getByText('Blazma Cyber does not include a recovery engine', { exact: false }).waitFor();
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
  // Phase F: IOC export as STIX 2.1 and CSV from the same case.
  for (const [fmt, ext] of [['STIX 2.1', '.stix.json'], ['CSV (مؤشرات)', '.csv']]) {
    await win.getByRole('button', { name: fmt, exact: true }).click();
    await win.getByRole('button', { name: 'إنشاء تقرير' }).first().click();
    const deadline = Date.now() + 20000;
    while (!readdirSync(repDir).some((f) => f.endsWith(ext)) && Date.now() < deadline) await win.waitForTimeout(200);
  }
  const stix = JSON.parse(readdirSync(repDir).filter((f) => f.endsWith('.stix.json')).map((f) => readFileSync(join(repDir, f), 'utf8'))[0]);
  assert.equal(stix.type, 'bundle');
  assert.ok(stix.objects.some((o) => o.type === 'indicator' && o.pattern === "[ipv4-addr:value = '203.0.113.77']"), 'STIX has the IP indicator');
  const csv = readdirSync(repDir).filter((f) => f.endsWith('.csv')).map((f) => readFileSync(join(repDir, f), 'utf8'))[0];
  assert.ok(csv.startsWith('type,value,label') && csv.includes('ipv4,203.0.113.77'), 'CSV has the IP indicator');
  await win.getByRole('button', { name: 'HTML', exact: true }).click();

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

  // Username: the accounts check (WhatsMyName rules) is offered for social networks and is blocked
  // as a whole in Offline Mode, like every other source.
  await win.getByRole('tab', { name: 'اسم مستخدم' }).click();
  await win.getByRole('button', { name: /مواقع التواصل الاجتماعي \(\d+ موقعًا\)/ }).waitFor();
  await win.locator('input.input.mono').first().fill('octocat');
  await win.getByRole('button', { name: 'استعلام', exact: true }).click();
  await win.getByText('حسابات بهذا الاسم').waitFor({ timeout: 30000 });
  await win.locator('.card', { hasText: 'حسابات بهذا الاسم' }).getByText('وضع عدم الاتصال', { exact: false }).first().waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '37-osint-accounts-offline-ar.png') });

  // File integrity: fingerprint a folder, change it (incl. an edit that keeps its timestamp), check.
  const fimDir = mkdtempSync(join(tmpdir(), 'blazma-fim-'));
  writeFileSync(join(fimDir, 'readme.txt'), 'hello');
  writeFileSync(join(fimDir, 'tool.dll'), 'original');
  writeFileSync(join(fimDir, 'old.txt'), 'bye');
  await win.locator('.nav-item', { hasText: 'سلامة الملفات' }).click();
  await win.locator('h1', { hasText: 'مراقبة سلامة الملفات' }).waitFor();
  await stubOpen(fimDir);
  await win.getByRole('button', { name: 'اختر مجلدًا…' }).click();
  await win.locator('.fim-row').first().waitFor({ timeout: 30000 });
  const dllTime = statSync(join(fimDir, 'tool.dll'));
  writeFileSync(join(fimDir, 'tool.dll'), 'patched!');
  utimesSync(join(fimDir, 'tool.dll'), dllTime.atime, dllTime.mtime);
  rmSync(join(fimDir, 'old.txt'));
  writeFileSync(join(fimDir, 'run.ps1'), 'Write-Output 1');
  await win.getByRole('button', { name: 'افحص الآن' }).click();
  await win.getByText('3 تغيير منذ أخذ البصمة').waitFor({ timeout: 30000 });
  await win.getByText('1 ملف تغيّر محتواه لكنه احتفظ بنفس وقت التعديل', { exact: false }).waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '43-file-integrity-ar.png'), fullPage: true });
  rmSync(fimDir, { recursive: true, force: true });

  // Full checkup: runs every read-only area one after another and gives one plain verdict.
  await win.locator('.nav-item', { hasText: 'فحص شامل' }).click();
  await win.getByRole('button', { name: 'ابدأ الفحص الشامل' }).click();
  await win.getByText(/^فُحص /).waitFor({ timeout: 180000 });
  assert.equal(await win.locator('.devsec-row').count(), 7, 'seven checkup areas');
  if (process.platform !== 'win32') await win.locator('.devsec-row', { hasText: 'أمان الجهاز' }).getByText('متاح على Windows فقط.').waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '44-checkup-ar.png') });
  // Save the checkup as a report (states and counts only); opening the file is stubbed in the test.
  await app.evaluate(({ shell }) => { shell.openPath = async () => ''; });
  await win.getByRole('button', { name: 'احفظ التقرير (HTML)' }).click();
  await win.locator('.toast', { hasText: 'حُفظ التقرير' }).first().waitFor({ timeout: 20000 });
  const reportFiles = readdirSync(join(dataDir, 'reports')).filter((f) => f.startsWith('checkup-ar-') && f.endsWith('.html'));
  assert.equal(reportFiles.length, 1, 'checkup report written');
  const reportHtml = readFileSync(join(dataDir, 'reports', reportFiles[0]), 'utf8');
  assert.ok(reportHtml.includes("default-src 'none'") && !/<script/i.test(reportHtml), 'report is script-free with a strict CSP');
  // The dashboard remembers the last checkup (states and counts only).
  await win.locator('.nav-item', { hasText: 'لوحة التحكم' }).click();
  await win.getByText(/آخر فحص شامل: .* \(اليوم\)/).waitFor({ timeout: 20000 });

  // What starts with Windows: real list + signatures on Windows, honest "Windows only" elsewhere.
  await win.locator('.nav-item', { hasText: 'برامج بدء التشغيل' }).click();
  await win.locator('h1', { hasText: 'ما يبدأ مع Windows' }).waitFor();
  await win.getByText(process.platform === 'win32' ? /برنامج يبدأ تلقائيًا/ : 'متاح على Windows فقط.').first().waitFor({ timeout: 120000 });
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '46-startup-ar.png') });

  // Open ports on this PC: listening programs from the real connection table (read-only).
  const portSrv = createServer(() => {});
  await new Promise((r) => portSrv.listen(0, '0.0.0.0', r));
  await win.locator('.nav-item', { hasText: 'المنافذ المفتوحة' }).click();
  await win.locator('h1', { hasText: 'المنافذ المفتوحة على جهازك' }).waitFor();
  await win.getByText(`${portSrv.address().port}/tcp`).waitFor({ timeout: 60000 });
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '45-open-ports-ar.png') });
  portSrv.close();

  // Smart search: Ctrl+K, paste a (defanged) indicator, pick the suggested tool — it opens pre-filled.
  await win.keyboard.press('Control+K');
  await win.keyboard.type('evil[.]example');
  await win.locator('.search-results button.smart', { hasText: 'استعلم عن هذا النطاق' }).waitFor();
  await win.waitForTimeout(200);
  await win.screenshot({ path: join(out, '42-smart-search-ar.png') });
  await win.keyboard.press('Enter');
  await win.locator('h1', { hasText: 'معلومات النطاقات' }).waitFor();
  assert.equal(await win.locator('input.input.mono').first().inputValue(), 'evil.example', 'smart search pre-fills the tool');

  // Network traffic: analyse a real capture file (synthetic fixture) end to end — reader, parser,
  // analyzer, findings, devices with manufacturers, and the cleartext view without secrets.
  await win.locator('.nav-item', { hasText: 'حركة الشبكة' }).click();
  await win.locator('h1', { hasText: 'حركة الشبكة' }).waitFor();
  await stubOpen(resolve('tests/fixtures/traffic/sample.pcapng'));
  await win.getByRole('button', { name: 'اختر ملف التقاط…' }).click();
  await win.getByText('ملخص الحركة').waitFor({ timeout: 60000 });
  await win.getByText('نمط فحص منافذ من 192.168.1.66').waitFor();
  await win.getByText('جهازان يدّعيان العنوان 192.168.1.1').waitFor();
  assert.ok(await win.getByText('Apple', { exact: true }).count() >= 1, 'device manufacturer shown');
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '38-network-traffic-ar.png'), fullPage: true });
  await win.getByRole('tab', { name: /غير المشفّر/ }).click();
  await win.getByText('plain.example').first().waitFor();
  assert.equal(await win.getByText(/SECRET/).count(), 0, 'no secret from the capture may reach the UI');

  // Wi-Fi Center: real data on Windows; elsewhere an honest "Windows only" state.
  await win.locator('.nav-item', { hasText: 'الواي فاي' }).click();
  await win.locator('h1', { hasText: 'الواي فاي' }).waitFor();
  if (process.platform === 'win32') {
    await win.locator('.card').filter({ hasText: /اتصالك الحالي|لا يوجد محوّل واي فاي|تعذّرت قراءة/ }).first().waitFor({ timeout: 90000 });
  } else {
    await win.getByText('متاح على Windows فقط.').first().waitFor({ timeout: 30000 });
  }
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '39-wifi-ar.png') });

  // Service scan (Nmap, user-installed): where Nmap exists, a real authorized scan of this computer
  // (a local web server on 8000 gives it something to find); otherwise the honest "not installed" state.
  await win.locator('.nav-item', { hasText: 'فحص الخدمات' }).click();
  await win.locator('h1', { hasText: 'فحص الخدمات (Nmap)' }).waitFor();
  await win.getByText(/برنامج Nmap غير مثبّت|ابدأ الفحص/).first().waitFor({ timeout: 30000 });
  if (await win.getByRole('button', { name: 'ابدأ الفحص' }).count()) {
    const web = createHttpServer((_q, s) => s.end('ok'));
    await new Promise((r) => web.once('error', r).listen(8000, '127.0.0.1', r));
    await win.locator('input.input.mono').fill('127.0.0.1');
    await win.getByRole('radio', { name: /سريع/ }).click();
    await win.getByRole('button', { name: 'ابدأ الفحص' }).click();
    const go = win.locator('.dialog').getByRole('button', { name: 'ابدأ الفحص' });
    assert.equal(await go.isDisabled(), true, 'Nmap needs the authorization checkbox');
    await win.locator('.dialog input[type=checkbox]').check();
    await go.click();
    await win.getByText('نتائج 127.0.0.1').waitFor({ timeout: 180000 });
    await win.getByText('الأجهزة والخدمات المفتوحة').waitFor();
    web.close();
  } else {
    await win.getByRole('button', { name: 'افتح صفحة تنزيل Nmap' }).waitFor();
  }
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '40-service-scan-ar.png'), fullPage: true });

  // Phase D: phishing email check (local only). A classic phishing sample: spoofed display name,
  // DMARC fail, a link that shows paypal.com but goes to an IP, and a double-extension attachment.
  const phish = [
    'Authentication-Results: mx.example.net; spf=softfail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail header.from=paypa1-secure.example',
    'From: "service@paypal.com" <alerts@paypa1-secure.example>',
    'Reply-To: recover.account@gmail.com',
    'Subject: =?UTF-8?B?' + Buffer.from('تنبيه: تم إيقاف حسابك').toString('base64') + '?=',
    'Date: Mon, 21 Sep 2026 08:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="B1"',
    '',
    '--B1',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Dear customer <a href="http://192.0.2.10/login">https://www.paypal.com/signin</a></p>',
    '--B1',
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('not really a program').toString('base64'),
    '--B1--',
    '',
  ].join('\r\n');
  await win.locator('.nav-item', { hasText: 'افحص رسالة بريد' }).click();
  await win.getByRole('textbox', { name: '…أو الصق مصدر الرسالة' }).fill(phish);
  await win.getByRole('button', { name: 'افحص هذه الرسالة' }).click();
  await win.getByText('علامات تحذير — غالبًا تصيّد').waitFor({ timeout: 30000 });
  await win.getByText('اسم المرسل يظهر «service@paypal.com»', { exact: false }).waitFor();
  await win.getByText('يُظهر موقعًا مختلفًا').first().waitFor();
  await win.getByText('امتداد مزدوج').first().waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '31-email-check-ar.png'), fullPage: true });
  // "Analyze" hands the attachment to File Analyzer (saved under a non-executable name, never opened).
  await win.getByRole('button', { name: 'حلّل' }).first().click();
  await win.getByText('سبب هذه النتيجة').waitFor({ timeout: 240000 });
  await win.getByText('.blazma-attachment', { exact: false }).first().waitFor();

  // Phase D2: "Was my password leaked?" — local observations while typing; the check itself is an
  // external request, so Offline Mode (default) blocks it; the field is cleared either way.
  await win.locator('.nav-item', { hasText: 'هل تسرّبت كلمة مروري؟' }).click();
  const pwBox = win.getByRole('textbox', { name: 'كلمة المرور' });
  await pwBox.fill('qwerty1990');
  assert.equal(await pwBox.getAttribute('type'), 'password');
  await win.getByText('نمط لوحة مفاتيح', { exact: false }).waitFor();
  await win.getByText('ما يشبه سنة', { exact: false }).waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '32-password-check-ar.png'), fullPage: true });
  await win.getByRole('button', { name: 'افحص', exact: true }).click();
  await win.getByText(offlineAr, { exact: false }).first().waitFor();
  assert.equal(await pwBox.inputValue(), '', 'the password field is cleared after checking');

  // Phase D3: abuse.ch services are offered for file hashes; without a key they are visibly disabled
  // (never faked), and the notice explains that a free abuse.ch key enables them.
  await win.locator('.nav-item', { hasText: 'مركز السمعة' }).click();
  await win.getByRole('tab', { name: 'هاش ملف' }).click();
  for (const svc of ['MalwareBazaar (abuse.ch)', 'URLhaus (abuse.ch)', 'ThreatFox (abuse.ch)']) {
    assert.ok(await win.locator('button.opt', { hasText: svc }).isDisabled(), `${svc} must be disabled without a key`);
  }
  await win.getByText('مفتاح abuse.ch المجاني', { exact: false }).waitFor();
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '33-reputation-abusech-ar.png'), fullPage: true });

  // Phase E4: opt-in Downloads watcher — a finished download is scanned (read only) and listed.
  const dlDir = await app.evaluate(({ app: a }) => a.getPath('downloads'));
  const dlName = `blazma-e2e-${Date.now()}.txt`;
  await win.locator('.nav-item', { hasText: 'لوحة التحكم' }).click();
  await win.getByRole('switch', { name: 'افحص التنزيلات الجديدة تلقائيًا' }).click();
  await win.getByText('قيد المراقبة', { exact: false }).waitFor();
  mkdirSync(dlDir, { recursive: true });
  writeFileSync(join(dlDir, `${dlName}.crdownload`), 'downloaded text');
  await win.waitForTimeout(500);
  const { renameSync } = await import('node:fs');
  renameSync(join(dlDir, `${dlName}.crdownload`), join(dlDir, dlName));
  const dlRow = win.locator('.row', { hasText: dlName });
  await dlRow.getByRole('button', { name: 'اعرض التفاصيل' }).waitFor({ timeout: 120000 });
  await win.waitForTimeout(300);
  await win.screenshot({ path: join(out, '35-downloads-watch-ar.png') });
  await win.getByRole('switch', { name: 'افحص التنزيلات الجديدة تلقائيًا' }).click();
  rmSync(join(dlDir, dlName), { force: true });

  // Phase E3: browser extensions audit (read-only).
  await win.locator('.nav-item', { hasText: 'إضافات المتصفح' }).click();
  if (process.platform === 'linux') {
    await win.locator('.devsec-title', { hasText: 'Free PDF Converter' }).waitFor({ timeout: 30000 });
    await win.locator('.devsec-row', { hasText: 'Free PDF Converter' }).getByText('ليست من المتجر').waitFor();
    await win.locator('.devsec-row', { hasText: 'Simple Notes' }).getByText('صلاحيات محدودة').waitFor();
    await win.locator('.devsec-head', { hasText: 'Free PDF Converter' }).click();
    await win.getByText('chrome://extensions', { exact: false }).first().waitFor();
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '34-extensions-ar.png'), fullPage: true });
  } else {
    await win.getByText('إضافات المتصفح', { exact: true }).first().waitFor();
    await win.locator('.page .card').first().waitFor({ timeout: 30000 });
  }

  // Phase E5: event-log hunting with the bundled Hayabusa (file path; the elevated path is covered by
  // tests/windows-integration.test.ts). Windows: a freshly exported System log. Elsewhere: BLAZMA_TEST_EVTX.
  await win.locator('.nav-item', { hasText: 'تحليل سجلات الأحداث' }).click();
  const hbAvailable = await win.getByRole('button', { name: /evtx/ }).waitFor({ timeout: 15000 }).then(() => true, () => false);
  let evtx = process.env.BLAZMA_TEST_EVTX ?? null;
  if (process.platform === 'win32' && hbAvailable) {
    const { execFileSync } = await import('node:child_process');
    evtx = join(mkdtempSync(join(tmpdir(), 'blazma-smoke-evtx-')), 'System.evtx');
    execFileSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'wevtutil.exe'), ['epl', 'System', evtx]);
  }
  if (hbAvailable && evtx) {
    await win.getByText('كل شيء', { exact: true }).click();
    await win.getByText('منخفض', { exact: true }).click();
    await stubOpen(evtx);
    await win.getByRole('button', { name: /evtx/ }).click();
    await win.getByText('النتيجة', { exact: true }).waitFor({ timeout: 300000 });
    if (process.env.BLAZMA_TEST_EVTX) await win.getByText('خريطة MITRE ATT&CK').waitFor();
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '36-event-logs-ar.png'), fullPage: true });
  } else {
    assert.ok(!hbAvailable || !evtx, 'Hayabusa page should load');
    if (!hbAvailable) await win.getByText('Hayabusa مضمَّن في مثبّت Windows.').waitFor();
  }

  // Phase E6: memory implant scan (bundled HollowsHunter on Windows; elsewhere honestly unavailable).
  await win.locator('.nav-item', { hasText: 'فحص الذاكرة' }).click();
  if (process.platform === 'win32') {
    await win.getByRole('button', { name: 'افحص الآن' }).click();
    await win.getByText('النتيجة', { exact: true }).waitFor({ timeout: 600000 });
    await win.waitForTimeout(300);
    await win.screenshot({ path: join(out, '37-memory-scan-ar.png'), fullPage: true });
  } else {
    await win.getByText('HollowsHunter مضمَّن في مثبّت Windows.').waitFor();
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

  // 8) "Terminal" opens the regular Windows terminal in its own window (not a page inside Blazma).
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
  assert.ok(simpleItems <= 13 && simpleItems < expertItems, `simple mode should show only the essentials (${simpleItems} vs ${expertItems})`);
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
  // Phase F4: manual update check — Offline Mode (default) blocks it; nothing is fetched or installed.
  await win.getByRole('tab', { name: 'About' }).click();
  await win.getByRole('button', { name: 'Check for updates' }).click();
  await win.getByText('Blocked: Offline Mode is on', { exact: false }).first().waitFor();

  // Light theme: applied to the whole window at once and remembered.
  await win.getByRole('tab', { name: 'General' }).click();
  await win.locator('select.select', { has: win.locator('option[value="light"]') }).selectOption('light');
  await win.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  const bg = await win.evaluate(() => getComputedStyle(document.body).getPropertyValue('--bg').trim());
  assert.equal(bg, '#f3f6fb', 'light palette active');
  await win.locator('.nav-item', { hasText: 'Dashboard' }).click();
  await win.waitForFunction(() => !document.querySelector('.toast'), null, { timeout: 20000 }).catch(() => {});
  await win.waitForTimeout(500);
  await win.screenshot({ path: join(out, '41-light-theme-en.png') });

  assert.deepEqual(errors, [], `renderer errors:\n${errors.join('\n')}`);
  console.log('UI smoke test passed. Screenshots in docs/screenshots/');
} finally {
  await app.close();
  rmSync(dataDir, { recursive: true, force: true });
}
