// Turns an unpacked build (release/win-unpacked) into the portable .zip: adds portable.txt (the switch
// that keeps all data in a BLAZMA-data folder next to the program) and removes any data left by tests.
// Usage: node scripts/make-portable.mjs <unpacked dir> <out.zip>
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const [dir, out] = process.argv.slice(2).map((p) => resolve(p));
if (!dir || !out) throw new Error('usage: make-portable.mjs <unpacked dir> <out.zip>');
writeFileSync(join(dir, 'portable.txt'), [
  'BLAZMA CYBER — portable copy / نسخة محمولة',
  'All data (settings, cases, reports, quarantine, logs) is kept in the BLAZMA-data folder next to this file.',
  'كل البيانات (الإعدادات، القضايا، التقارير، الحجر، السجلات) تُحفظ في مجلد BLAZMA-data بجانب هذا الملف.',
  'Delete this file to use the normal per-user location instead.',
  '',
].join('\r\n'));
rmSync(join(dir, 'BLAZMA-data'), { recursive: true, force: true });
rmSync(out, { force: true });
if (process.platform === 'win32') {
  execFileSync(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe'), ['-a', '-c', '-f', out, '-C', dir, '.'], { stdio: 'inherit' });
} else {
  execFileSync('zip', ['-q', '-r', out, '.'], { cwd: dir, stdio: 'inherit' });
}
console.log(`Portable zip: ${out}`);
