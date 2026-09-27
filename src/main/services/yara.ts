// YARA-X adapter + local rule manager.
//
// - Engine: the official YARA-X CLI (`yr`), installed by the user. We never download or bundle it.
//   Located by the path configured in Settings → Engines, or `yr` on PATH as a fallback.
//   Invoked with execFile argument arrays only.
// - Rules live under <data>/yara/rules/*.yar with an index (enabled flag, origin).
// - Rule "updates" are imports from local files the user chooses. Nothing is fetched from the internet.

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

import type { YaraEngineInfo, YaraFileResult, YaraMatch, YaraRuleFile, YaraScanResult } from '../../shared/api';
import { BUILTIN_RULES, parseNdjson } from '../../core/yara';
export type { YaraEngineInfo, YaraFileResult, YaraMatch, YaraRuleFile, YaraScanResult };
export { BUILTIN_RULES, parseNdjson };

export class YaraError extends Error {
  constructor(readonly code: string, readonly detail?: string) {
    super(code);
  }
}

const ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_RULE_BYTES = 1024 * 1024;

function run(exe: string, args: string[], opts: { timeoutMs: number; signal?: AbortSignal; cwd?: string }): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      exe,
      args,
      { timeout: opts.timeoutMs, windowsHide: true, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8', signal: opts.signal, cwd: opts.cwd },
      (err, stdout, stderr) => {
        if (err) {
          const e = err as NodeJS.ErrnoException & { code?: number | string; killed?: boolean };
          if (e.name === 'AbortError' || opts.signal?.aborted) return reject(new YaraError('cancelled'));
          if (e.code === 'ENOENT' || e.code === 'EACCES') return reject(new YaraError('yara_not_installed'));
          if (e.killed) return reject(new YaraError('timeout'));
          return resolve({ code: typeof e.code === 'number' ? e.code : 1, stdout: stdout ?? '', stderr: stderr ?? '' });
        }
        resolve({ code: 0, stdout: stdout ?? '', stderr: stderr ?? '' });
      },
    );
  });
}

export class YaraService {
  private readonly root = subDir('yara');
  private readonly rulesDir = join(this.root, 'rules');
  private readonly indexFile = join(this.root, 'index.json');

  constructor(
    private readonly configuredPath: () => string | null,
    /** Engine and rule packs shipped with Blazma (see services/bundled.ts). */
    private readonly bundled: { exe: () => string | null; packs: () => Array<{ id: string; name: string; path: string }> } = { exe: () => null, packs: () => [] },
  ) {}

  private read(): YaraRuleFile[] {
    const raw = readJson<unknown>(this.indexFile, null);
    return Array.isArray(raw) ? (raw as YaraRuleFile[]) : [];
  }
  private write(list: YaraRuleFile[]): void {
    writeJson(this.indexFile, list);
  }
  rulePath(id: string): string {
    return join(this.rulesDir, `${id}.yar`);
  }

  /** Installs the builtin starter pack the first time (never overwrites user choices). */
  async ensureBuiltins(): Promise<void> {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(this.rulesDir, { recursive: true, mode: 0o700 });
    const list = this.read();
    let changed = false;
    for (const b of BUILTIN_RULES) {
      if (list.some((r) => r.id === b.id)) continue;
      await writeFile(this.rulePath(b.id), b.source, { mode: 0o600 });
      list.push({ id: b.id, name: b.name, enabled: true, origin: 'builtin', createdAt: new Date().toISOString(), sizeBytes: Buffer.byteLength(b.source), valid: null });
      changed = true;
    }
    // Rule packs shipped with Blazma: installed on first run and refreshed when a new app version
    // ships a different pack. The user's enabled/disabled choice is kept.
    for (const p of this.bundled.packs()) {
      const src = await readFile(p.path);
      const hash = createHash('sha256').update(src).digest('hex');
      const cur = list.find((r) => r.id === p.id);
      const installed = existsSync(this.rulePath(p.id)) ? createHash('sha256').update(await readFile(this.rulePath(p.id))).digest('hex') : null;
      if (installed !== hash) await writeFile(this.rulePath(p.id), src, { mode: 0o600 });
      if (!cur) {
        list.push({ id: p.id, name: p.name, enabled: true, origin: 'pack', createdAt: new Date().toISOString(), sizeBytes: src.length, valid: null });
        changed = true;
      } else if (installed !== hash) {
        Object.assign(cur, { name: p.name, sizeBytes: src.length, valid: null });
        delete cur.error;
        changed = true;
      }
    }
    if (changed) this.write(list);
  }

  async listRules(): Promise<YaraRuleFile[]> {
    await this.ensureBuiltins();
    return this.read();
  }

  async engine(): Promise<YaraEngineInfo> {
    // Order: the executable the user chose → the one shipped with Blazma → `yr` on PATH.
    const configured = this.configuredPath();
    if (configured && !existsSync(configured)) return { available: false, reason: 'yara_path_missing' };
    const shipped = this.bundled.exe();
    const candidates = configured ? [configured] : [...(shipped ? [shipped] : []), 'yr'];
    for (const exe of candidates) {
      try {
        const r = await run(exe, ['--version'], { timeoutMs: 10_000 });
        const m = /(\d+\.\d+\.\d+)/.exec(`${r.stdout} ${r.stderr}`);
        if (r.code === 0 && m) return { available: true, path: exe, version: m[1], ...(exe === shipped ? { bundled: true } : {}) };
      } catch {
        /* try next */
      }
    }
    return { available: false, reason: 'yara_not_installed' };
  }

  private async requireEngine(): Promise<string> {
    const e = await this.engine();
    if (!e.available || !e.path) throw new YaraError(e.reason ?? 'yara_not_installed');
    return e.path;
  }

  /** Validates a rule file with `yr check`. Returns null when valid, or the error text. */
  async checkFile(path: string): Promise<string | null> {
    const exe = await this.requireEngine();
    // Run from the rule's folder with a relative name (see scan() for why).
    const r = await run(exe, ['check', basename(path)], { timeoutMs: 30_000, cwd: dirname(path) });
    const text = `${r.stdout}\n${r.stderr}`;
    // YARA-X: exit 0 = [ PASS ], exit 2 = [ WARN ] (valid, with warnings such as deprecated fields),
    // exit 1 = [ FAIL ]. Diagnostics start with "error[Exxx]:". Don't match the bare word "error":
    // warnings quote rule source, which may legitimately contain it.
    const failed = /\[\s*FAIL\s*\]/.test(text) || /^error(\[|:)/m.test(text) || (r.code !== 0 && !/\[\s*WARN\s*\]/.test(text));
    if (failed) return text.trim().slice(0, 2000) || 'invalid';
    return null;
  }

  /** Validates all rules that have not been validated yet (when the engine is available). */
  async validateAll(): Promise<YaraRuleFile[]> {
    const list = await this.listRules();
    const e = await this.engine();
    if (!e.available) return list;
    for (const r of list) {
      const err = await this.checkFile(this.rulePath(r.id)).catch((x: YaraError) => x.code);
      r.valid = err === null;
      if (err) r.error = err;
      else delete r.error;
    }
    this.write(list);
    return list;
  }

  async setEnabled(id: unknown, enabled: unknown): Promise<YaraRuleFile[]> {
    if (typeof id !== 'string' || !ID_RE.test(id) || typeof enabled !== 'boolean') throw new YaraError('invalid_input');
    const list = await this.listRules();
    const r = list.find((x) => x.id === id);
    if (!r) throw new YaraError('yara_rule_not_found');
    r.enabled = enabled;
    this.write(list);
    return list;
  }

  async getSource(id: unknown): Promise<string> {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new YaraError('invalid_input');
    const rule = (await this.listRules()).find((r) => r.id === id);
    if (!rule) throw new YaraError('yara_rule_not_found');
    const text = await readFile(this.rulePath(id), 'utf8');
    // Packs are large (MBs): show the beginning only; the full file stays on disk.
    if (rule.origin === 'pack' && text.length > 200_000) return `${text.slice(0, 200_000)}\n\n// … (${text.length - 200_000} more characters — the full pack is used when scanning)\n`;
    return text;
  }

  /** Saves (creates or replaces) a custom rule. Validated with the engine when available. */
  async saveCustom(name: unknown, source: unknown, origin: 'custom' | 'imported' = 'custom'): Promise<YaraRuleFile> {
    if (typeof name !== 'string' || typeof source !== 'string') throw new YaraError('invalid_input');
    const cleanName = name.trim().slice(0, 80);
    if (!cleanName || !source.trim()) throw new YaraError('invalid_input');
    if (Buffer.byteLength(source) > MAX_RULE_BYTES) throw new YaraError('yara_rule_too_large');
    const id = `${origin === 'custom' ? 'c' : 'i'}-${cleanName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'rule'}`;
    if (!ID_RE.test(id)) throw new YaraError('invalid_input');

    await this.ensureBuiltins();
    const path = this.rulePath(id);
    await writeFile(path, source, { mode: 0o600 });

    let valid: boolean | null = null;
    let error: string | undefined;
    const e = await this.engine();
    if (e.available) {
      const err = await this.checkFile(path);
      valid = err === null;
      if (err) error = err;
    }
    const list = this.read().filter((r) => r.id !== id);
    const entry: YaraRuleFile = {
      id,
      name: cleanName,
      enabled: valid !== false,
      origin,
      createdAt: new Date().toISOString(),
      sizeBytes: Buffer.byteLength(source),
      valid,
      ...(error ? { error } : {}),
    };
    this.write([...list, entry]);
    return entry;
  }

  /** Imports a local .yar/.yara file chosen by the user. */
  async importFile(path: string): Promise<YaraRuleFile> {
    if (!/\.(yar|yara)$/i.test(path)) throw new YaraError('yara_bad_extension');
    const st = await stat(path).catch(() => null);
    if (!st || !st.isFile()) throw new YaraError('file_not_found');
    if (st.size > MAX_RULE_BYTES) throw new YaraError('yara_rule_too_large');
    const source = await readFile(path, 'utf8');
    return this.saveCustom(basename(path).replace(/\.(yar|yara)$/i, ''), source, 'imported');
  }

  async remove(id: unknown): Promise<YaraRuleFile[]> {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new YaraError('invalid_input');
    const list = await this.listRules();
    const rule = list.find((r) => r.id === id);
    if (!rule) throw new YaraError('yara_rule_not_found');
    if (rule.origin === 'pack') throw new YaraError('yara_pack_readonly');
    await rm(this.rulePath(id), { force: true });
    const next = list.filter((r) => r.id !== id);
    this.write(next);
    return next;
  }

  /** Scans a file or folder with all enabled, non-invalid rules. */
  async scan(target: string, opts: { recursive: boolean; signal: AbortSignal; timeoutMs?: number }): Promise<YaraScanResult> {
    const exe = await this.requireEngine();
    const rules = (await this.listRules()).filter((r) => r.enabled && r.valid !== false);
    if (rules.length === 0) throw new YaraError('yara_no_rules');
    const started = Date.now();
    // Each rule file gets its own namespace (the rule id) so identically named rules don't collide.
    // YARA-X separates namespace and path with ':', which would clash with Windows drive letters
    // (C:\...), so we run from the rules directory and pass RELATIVE rule paths.
    const args = ['scan', '--output-format', 'ndjson', '--print-namespace', '--print-tags', '--print-meta', '--disable-console-logs'];
    if (opts.recursive) args.push('--recursive');
    for (const r of rules) args.push(`${r.id}:${r.id}.yar`);
    args.push(target);

    const r = await run(exe, args, { timeoutMs: opts.timeoutMs ?? 30 * 60_000, signal: opts.signal, cwd: this.rulesDir });
    if (r.code !== 0 && !r.stdout.trim()) throw new YaraError('yara_scan_failed', r.stderr.trim().slice(0, 1000));
    const files = parseNdjson(r.stdout);
    return {
      target,
      files,
      matchedFiles: files.filter((f) => f.matches.length > 0).length,
      rulesUsed: rules.length,
      durationMs: Date.now() - started,
    };
  }
}
