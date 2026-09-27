// Builds src/core/username-sites.json (the sites the OSINT "accounts" check asks) from the
// WhatsMyName project's wmn-data.json.
// Usage: node scripts/make-username-sites.mjs <path to wmn-data.json> <WhatsMyName commit>
// Source: https://github.com/WebBreacher/WhatsMyName — © Micah Hoffman and contributors,
// CC BY-SA 4.0 (see engines/licenses/whatsmyname.txt). The generated file is an adaptation and is
// distributed under the same license.
//
// Kept: HTTPS checks with an exact "account exists" and "account missing" signature.
// Left out: adult, dating and political categories (sensitive, not needed for a security workbench),
// archive.org mirrors, entries the project marks invalid, plain-HTTP checks, checks that need a
// cookie, and checks whose "missing" answer can't be told apart from "exists".
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const [src, commit] = process.argv.slice(2);
if (!src || !/^[0-9a-f]{40}$/.test(commit ?? '')) throw new Error('usage: make-username-sites.mjs <wmn-data.json> <40-hex commit>');
const raw = readFileSync(src);
const data = JSON.parse(raw.toString('utf8'));

const EXCLUDED_CATS = new Set(['xx NSFW xx', 'dating', 'political', 'archived']);
// Categories shown as "social networks"; everything else kept is "other sites".
const SOCIAL_CATS = new Set(['social', 'video', 'images', 'music', 'blog', 'news', 'art']);
const DROP_HEADERS = new Set(['host', 'te']);

const slug = (s) => s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const ids = new Set();
const sites = [];
let skipped = 0;
for (const s of data.sites) {
  const headers = Object.entries(s.headers ?? {});
  if (
    EXCLUDED_CATS.has(s.cat) || s.valid === false || !s.uri_check.startsWith('https://') ||
    (s.uri_pretty && !s.uri_pretty.startsWith('https://')) || headers.some(([k]) => k.toLowerCase() === 'cookie') ||
    !s.e_string || typeof s.e_code !== 'number' || typeof s.m_code !== 'number' ||
    // Without a "missing" text, the status code alone must tell the answers apart.
    (!s.m_string && s.m_code === s.e_code)
  ) {
    skipped++;
    continue;
  }
  let id = slug(s.name) || 'site';
  for (let n = 2; ids.has(id); n++) id = `${slug(s.name)}-${n}`;
  ids.add(id);
  const h = Object.fromEntries(headers.filter(([k]) => !DROP_HEADERS.has(k.toLowerCase())));
  sites.push({
    id,
    name: s.name,
    cat: s.cat,
    group: SOCIAL_CATS.has(s.cat) ? 'social' : 'other',
    check: s.uri_check,
    ...(s.uri_pretty ? { pretty: s.uri_pretty } : {}),
    ...(s.post_body ? { post: s.post_body } : {}),
    ...(Object.keys(h).length ? { headers: h } : {}),
    ...(s.strip_bad_char ? { strip: s.strip_bad_char } : {}),
    eCode: s.e_code,
    eString: s.e_string,
    mCode: s.m_code,
    mString: s.m_string ?? '',
  });
}
sites.sort((a, b) => a.name.localeCompare(b.name, 'en'));
const out = {
  source: `WebBreacher/WhatsMyName@${commit}`,
  sha256: createHash('sha256').update(raw).digest('hex'),
  license: 'CC BY-SA 4.0 — adapted from WhatsMyName (© Micah Hoffman and contributors)',
  sites,
};
writeFileSync(new URL('../src/core/username-sites.json', import.meta.url), `${JSON.stringify(out)}\n`);
const social = sites.filter((s) => s.group === 'social').length;
console.log(`${sites.length} sites (${social} social, ${sites.length - social} other); ${skipped} left out`);
