// Builds src/core/oui-data.json (MAC prefix → manufacturer) from the `oui-data` npm package, which
// packages the IEEE MA-L public registry.
// Usage: node scripts/make-oui-data.mjs <path to oui-data/index.json> <oui-data version>
// Source: https://github.com/silverwind/oui-data — BSD-2-Clause (see engines/licenses/oui-data.txt);
// the underlying listing is the IEEE Registration Authority's public OUI registry.
//
// Output: { source, names: [...], table: "PPPPPPi,PPPPPPi,…" } where i is the base-36 index into
// names. Names are the organisation line only (no postal address), with corporate suffixes trimmed.
import { readFileSync, writeFileSync } from 'node:fs';

const [src, version] = process.argv.slice(2);
if (!src || !version) throw new Error('usage: make-oui-data.mjs <oui-data/index.json> <version>');
const data = JSON.parse(readFileSync(src, 'utf8'));

const SUFFIX = /[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|s\.?a|s\.?a\.?s|s\.?r\.?l|s\.?p\.?a|b\.?v|n\.?v|oy|ab|as|a\/s|k\.?k|pty|plc|pte|sdn\.? bhd|bhd|technology|technologies|electronics?|group|holdings?|international|intl)\b\.?$/i;
function clean(raw) {
  let s = String(raw).split('\n')[0].trim().replace(/\s+/g, ' ');
  // Title-case names the registry lists in capitals (XEROX CORPORATION → Xerox).
  if (s === s.toUpperCase() && /[A-Z]{3}/.test(s)) s = s.toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
  for (let i = 0; i < 4; i++) {
    const next = s.replace(SUFFIX, '').replace(/[\s,.(]+$/, '').trim();
    if (next === s || next.length < 2) break;
    s = next;
  }
  return s.slice(0, 48);
}

const names = [];
const index = new Map();
const rows = [];
for (const [prefix, org] of Object.entries(data).sort(([a], [b]) => a.localeCompare(b))) {
  if (!/^[0-9A-F]{6}$/.test(prefix)) continue;
  const name = clean(org);
  if (!name || /^private$/i.test(name)) continue;
  let i = index.get(name);
  if (i === undefined) {
    i = names.length;
    names.push(name);
    index.set(name, i);
  }
  rows.push(prefix + i.toString(36));
}
const out = { source: `oui-data@${version} (IEEE MA-L registry)`, names, table: rows.join(',') };
writeFileSync(new URL('../src/core/oui-data.json', import.meta.url), `${JSON.stringify(out)}\n`);
console.log(`${rows.length} prefixes, ${names.length} manufacturers, ${Math.round(JSON.stringify(out).length / 1024)} KB`);
