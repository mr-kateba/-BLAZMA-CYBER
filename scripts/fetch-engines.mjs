// Downloads the engines listed in engines.lock.json into build/engines/<id>/ for packaging.
// BUILD TIME ONLY — the app itself never downloads or updates executables.
//
// Every archive is verified against the pinned size and SHA-256 before it is extracted; any mismatch
// aborts the build. Already-verified engines are reused (build/engines/<id>/.verified holds the hash).
//
// Usage: node scripts/fetch-engines.mjs   (Windows packaging; also works on Linux with `unzip`)
import { createHash } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, copyFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, relative } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const lock = JSON.parse(readFileSync(join(root, 'engines.lock.json'), 'utf8'));
const out = join(root, 'build', 'engines');
mkdirSync(out, { recursive: true });

function findFile(dir, name) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      const hit = findFile(p, name);
      if (hit) return hit;
    } else if (e.name.toLowerCase() === name.toLowerCase()) return p;
  }
  return null;
}

async function download(url, dest) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok || !res.body) throw new Error(`download failed ${res.status} ${url}`);
  const hash = createHash('sha256');
  const file = createWriteStream(dest);
  await pipeline(Readable.fromWeb(res.body), async function* (src) {
    for await (const chunk of src) {
      hash.update(chunk);
      yield chunk;
    }
  }, file);
  return hash.digest('hex');
}

function extract(zip, dir) {
  if (process.platform === 'win32') {
    const tar = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
    execFileSync(tar, ['-xf', zip, '-C', dir], { stdio: 'inherit' });
  } else {
    execFileSync('unzip', ['-q', '-o', zip, '-d', dir], { stdio: 'inherit' });
  }
}

const manifest = { generatedAt: new Date().toISOString(), engines: {} };
for (const e of lock.engines) {
  const dir = join(out, e.id);
  const marker = join(dir, '.verified');
  if (!(existsSync(marker) && readFileSync(marker, 'utf8').trim() === e.sha256)) {
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    const zip = join(out, `${e.id}.zip`);
    console.log(`Downloading ${e.name} ${e.version} …`);
    const sha = await download(e.url, zip);
    const size = statSync(zip).size;
    if (size !== e.size || sha !== e.sha256) {
      rmSync(zip, { force: true });
      rmSync(dir, { recursive: true, force: true });
      throw new Error(`${e.id}: integrity check FAILED (size ${size} vs ${e.size}, sha256 ${sha} vs ${e.sha256})`);
    }
    extract(zip, dir);
    rmSync(zip, { force: true });
    writeFileSync(marker, e.sha256);
  }
  const exe = findFile(dir, e.exe);
  if (!exe) throw new Error(`${e.id}: ${e.exe} not found in the archive`);
  copyFileSync(join(root, 'engines', 'licenses', `${e.id}.txt`), join(dir, 'LICENSE.txt'));
  manifest.engines[e.id] = { name: e.name, version: e.version, license: e.license, homepage: e.homepage, sha256: e.sha256, exe: relative(dir, exe).replace(/\\/g, '/') };
  console.log(`  ✓ ${e.name} ${e.version} verified (${e.sha256.slice(0, 16)}…) → ${manifest.engines[e.id].exe}`);
}
writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`Engines ready in ${relative(root, out)}`);
