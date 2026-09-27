// File integrity monitoring: fingerprint a folder the user chooses (SHA-256 of every file), then
// compare later to see exactly which files were added, removed or changed. Read-only: files are
// hashed, never opened or run; symbolic links and junctions are not followed.

import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { lstat, opendir, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { diffFingerprints, type FimEntry, type FimFingerprint } from '../../core/fim';
import { validateAbsolutePath } from '../../core/validation';
import type { FimCheckResult, FimPreset, FimWatch } from '../../shared/api';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

export class FimError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export const FIM_MAX_FILES = 50_000;
const MAX_DEPTH = 40;
const MAX_WATCHES = 50;
const ID_RE = /^[0-9a-f-]{36}$/;

interface StoredWatch {
  id: string;
  name: string;
  fingerprint: FimFingerprint;
  lastCheck: FimWatch['lastCheck'];
}

type Progress = (files: number, bytes: number) => void;

function hashFile(path: string, signal: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    const s = createReadStream(path, { highWaterMark: 1024 * 1024 });
    const onAbort = () => s.destroy(new FimError('cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
    s.on('data', (c) => h.update(c as Buffer));
    s.on('error', (e) => {
      signal.removeEventListener('abort', onAbort);
      reject(e);
    });
    s.on('end', () => {
      signal.removeEventListener('abort', onAbort);
      resolve(h.digest('hex'));
    });
  });
}

/** Walks `root` and hashes every regular file (no links followed). */
export async function fingerprint(root: string, signal: AbortSignal, progress?: Progress): Promise<FimFingerprint> {
  const files: FimEntry[] = [];
  const unreadable: string[] = [];
  let truncated = false;
  let bytes = 0;
  const rel = (p: string) => relative(root, p).split(sep).join('/');

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > MAX_DEPTH || truncated) return;
    let handle;
    try {
      handle = await opendir(dir);
    } catch {
      unreadable.push(rel(dir) + '/');
      return;
    }
    for await (const d of handle) {
      if (signal.aborted) throw new FimError('cancelled');
      const p = join(dir, d.name);
      if (d.isSymbolicLink()) continue;
      if (d.isDirectory()) {
        await walk(p, depth + 1);
        continue;
      }
      if (!d.isFile()) continue;
      if (files.length >= FIM_MAX_FILES) {
        truncated = true;
        break;
      }
      try {
        const st = await lstat(p);
        const sha256 = await hashFile(p, signal);
        files.push({ path: rel(p), size: st.size, mtimeMs: Math.round(st.mtimeMs), sha256 });
        bytes += st.size;
        progress?.(files.length, bytes);
      } catch (e) {
        if (e instanceof FimError) throw e;
        unreadable.push(rel(p));
      }
    }
  };

  await walk(root, 0);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { root, createdAt: new Date().toISOString(), files, unreadable: unreadable.slice(0, 500), truncated };
}

async function checkFolder(raw: unknown): Promise<string> {
  const v = validateAbsolutePath(raw);
  if (!v.ok) throw new FimError('invalid_path');
  const st = await stat(v.path).catch(() => null);
  if (!st?.isDirectory()) throw new FimError('fim_not_folder');
  return v.path;
}

export class FimService {
  private readonly dir = join(subDir('state'), 'fim');

  private file(id: string) {
    if (!ID_RE.test(id)) throw new FimError('invalid_input');
    return join(this.dir, `${id}.json`);
  }

  private load(id: unknown): StoredWatch {
    if (typeof id !== 'string') throw new FimError('invalid_input');
    const w = readJson<StoredWatch | null>(this.file(id), null);
    if (!w) throw new FimError('fim_not_found');
    return w;
  }

  private summary(w: StoredWatch): FimWatch {
    const fp = w.fingerprint;
    return {
      id: w.id,
      name: w.name,
      root: fp.root,
      createdAt: fp.createdAt,
      files: fp.files.length,
      bytes: fp.files.reduce((n, f) => n + f.size, 0),
      unreadable: fp.unreadable.length,
      truncated: fp.truncated,
      lastCheck: w.lastCheck,
    };
  }

  list(): FimWatch[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((f) => /^[0-9a-f-]{36}\.json$/.test(f))
      .map((f) => readJson<StoredWatch | null>(join(this.dir, f), null))
      .filter((w): w is StoredWatch => !!w?.fingerprint)
      .map((w) => this.summary(w))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async create(folder: unknown, name: unknown, signal: AbortSignal, progress?: Progress): Promise<FimWatch> {
    const root = await checkFolder(folder);
    if (this.list().length >= MAX_WATCHES) throw new FimError('fim_too_many');
    const label = typeof name === 'string' && name.trim() ? name.trim().slice(0, 80) : root.split(/[\\/]/).filter(Boolean).pop() ?? root;
    const fp = await fingerprint(root, signal, progress);
    const w: StoredWatch = { id: randomUUID(), name: label, fingerprint: fp, lastCheck: null };
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    writeJson(this.file(w.id), w);
    return this.summary(w);
  }

  async check(id: unknown, signal: AbortSignal, progress?: Progress): Promise<FimCheckResult> {
    const w = this.load(id);
    const st = await stat(w.fingerprint.root).catch(() => null);
    if (!st?.isDirectory()) throw new FimError('fim_folder_missing');
    const now = await fingerprint(w.fingerprint.root, signal, progress);
    const diff = diffFingerprints(w.fingerprint, now);
    const count = (c: string) => diff.changes.filter((x) => x.change === c).length;
    w.lastCheck = { at: now.createdAt, added: count('added'), removed: count('removed'), modified: count('modified') };
    writeJson(this.file(w.id), w);
    return { watch: this.summary(w), diff: { ...diff, changes: diff.changes.slice(0, 5000) }, totalChanges: diff.changes.length, unreadableNow: now.unreadable, truncated: now.truncated };
  }

  /** Accept the current state as the new baseline (after the user reviewed the changes). */
  async accept(id: unknown, signal: AbortSignal, progress?: Progress): Promise<FimWatch> {
    const w = this.load(id);
    w.fingerprint = await fingerprint(w.fingerprint.root, signal, progress);
    w.lastCheck = null;
    writeJson(this.file(w.id), w);
    return this.summary(w);
  }

  remove(id: unknown): void {
    if (typeof id !== 'string') throw new FimError('invalid_input');
    rmSync(this.file(id), { force: true });
  }

  /** Absolute path of a file inside a watched folder (for "analyze this file"). */
  resolve(id: unknown, relPath: unknown): string {
    const w = this.load(id);
    if (typeof relPath !== 'string' || !relPath || relPath.includes('\0') || relPath.split('/').some((s) => s === '..' || s === '')) throw new FimError('invalid_input');
    return join(w.fingerprint.root, ...relPath.split('/'));
  }
}

/** Places worth watching on Windows; only those that exist are offered. */
export function fimPresets(): FimPreset[] {
  if (process.platform !== 'win32') return [];
  const env = process.env;
  const list: FimPreset[] = [
    { id: 'startup_user', path: join(env.APPDATA ?? '', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') },
    { id: 'startup_all', path: join(env.ProgramData ?? 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp') },
    { id: 'hosts_folder', path: join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'drivers', 'etc') },
    { id: 'powershell_profiles', path: join(env.USERPROFILE ?? '', 'Documents', 'WindowsPowerShell') },
  ];
  return list.filter((p) => p.path && existsSync(p.path));
}
