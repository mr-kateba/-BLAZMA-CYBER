// Regenerates build/icon.ico (16–256 px, PNG-compressed entries) and build/icon.png (512 px)
// from build/icon.svg, using the Chromium that Playwright already uses for the E2E test.
// Run: node scripts/make-icon.mjs   (only needed when the logo changes; outputs are committed)
import { readFileSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright';

const root = new URL('../build/', import.meta.url);
const svg = readFileSync(new URL('icon.svg', root), 'utf8');
const SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256];

// CHROMIUM_PATH lets you use an existing Chromium instead of Playwright's pinned download.
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const page = await browser.newPage();
async function render(size) {
  await page.setViewportSize({ width: size, height: size });
  const inner = svg.replace('width="64" height="64"', `width="${size}" height="${size}"`);
  await page.setContent(`<html><body style="margin:0;background:transparent">${inner}</body></html>`);
  return page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
}

const pngs = [];
for (const s of SIZES) pngs.push({ size: s, data: await render(s) });
writeFileSync(new URL('icon.png', root), await render(512));
await browser.close();

// ICO container: 6-byte header, 16-byte directory entry per image, then the PNG payloads.
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(pngs.length, 4);
let offset = 6 + 16 * pngs.length;
const dir = pngs.map(({ size, data }) => {
  const e = Buffer.alloc(16);
  e.writeUInt8(size >= 256 ? 0 : size, 0);
  e.writeUInt8(size >= 256 ? 0 : size, 1);
  e.writeUInt16LE(1, 4);
  e.writeUInt16LE(32, 6);
  e.writeUInt32LE(data.length, 8);
  e.writeUInt32LE(offset, 12);
  offset += data.length;
  return e;
});
writeFileSync(new URL('icon.ico', root), Buffer.concat([header, ...dir, ...pngs.map((p) => p.data)]));
console.log(`build/icon.ico (${SIZES.join(', ')}) and build/icon.png (512) written`);
