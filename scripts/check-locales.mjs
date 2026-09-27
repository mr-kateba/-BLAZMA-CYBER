// Fails when ar.json and en.json diverge (missing keys or mismatched {{placeholders}}).
import { readFileSync } from 'node:fs';

const load = (l) => JSON.parse(readFileSync(new URL(`../locales/${l}.json`, import.meta.url), 'utf8'));
const flat = (d, p = '', out = {}) => {
  for (const [k, v] of Object.entries(d)) {
    const key = p ? `${p}.${k}` : k;
    if (typeof v === 'string') out[key] = v;
    else flat(v, key, out);
  }
  return out;
};
const ph = (s) => [...s.matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort().join(',');

const en = flat(load('en'));
const ar = flat(load('ar'));
const problems = [];
for (const k of Object.keys(en)) if (!(k in ar)) problems.push(`missing in ar: ${k}`);
for (const k of Object.keys(ar)) if (!(k in en)) problems.push(`missing in en: ${k}`);
for (const k of Object.keys(en)) if (k in ar && ph(en[k]) !== ph(ar[k])) problems.push(`placeholder mismatch: ${k}`);

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`locales OK: ${Object.keys(en).length} keys in both languages`);
