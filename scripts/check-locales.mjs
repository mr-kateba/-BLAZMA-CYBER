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
const dotted = (d, p = '') => Object.entries(d).flatMap(([k, v]) => [...(k.includes('.') ? [`${p}${k}`] : []), ...(typeof v === 'object' ? dotted(v, `${p}${k}.`) : [])]);
for (const l of ['en', 'ar']) for (const k of dotted(load(l))) problems.push(`key contains a dot (unreachable by t()): ${l}:${k}`);
for (const k of Object.keys(en)) if (!(k in ar)) problems.push(`missing in ar: ${k}`);
for (const k of Object.keys(ar)) if (!(k in en)) problems.push(`missing in en: ${k}`);
for (const k of Object.keys(en)) if (k in ar && ph(en[k]) !== ph(ar[k])) problems.push(`placeholder mismatch: ${k}`);
// t() only fills {{name}}; a single-brace {name} would be shown to the user as-is.
for (const [l, d] of [['en', en], ['ar', ar]]) for (const [k, v] of Object.entries(d)) if (/(?<!\{)\{\s*\w+\s*\}(?!\})/.test(v)) problems.push(`single-brace placeholder (use {{name}}): ${l}:${k}`);

if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`locales OK: ${Object.keys(en).length} keys in both languages`);
