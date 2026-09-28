// Authorized password recovery workspace.
//
// Scope and safety (see SECURITY.md):
//  - This is for files the user OWNS or is explicitly authorized to recover (e.g. their own
//    forgotten archive/PDF password). The UI requires an explicit authorization confirmation.
//  - Blazma Cyber does NOT implement a recovery engine and does NOT bundle one. It runs a mature
//    engine the user installed and configured (John the Ripper or hashcat), located by the path
//    set in Settings, invoked with an argument array (never a shell).
//  - Recovered results are returned to the UI only. They are NEVER written to logs or history.
//  - Everything is local. Nothing about the file, its hash, or any candidate leaves the machine.
//
// The session runner here is engine-agnostic: it launches the configured executable with validated
// arguments, streams progress, and supports stop / pause / resume. It parses generic status output.

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { cpus } from 'node:os';
import { randomUUID } from 'node:crypto';
import type { RecoveryEngineKind, RecoveryMode, RecoveryPerformance, RecoveryProgress, RecoverySessionInfo, RecoveryStartResult } from '../../shared/api';
import { validateAbsolutePath } from '../../core/validation';
import { detectEncryption, sevenZipNextHeaderRange, type EncryptedFormat } from '../../core/encrypted';
import { extractorFor, firstHashLine, hashcatHash, hashcatMode, johnHashLine } from '../../core/recovery-format';
import { subDir } from './paths';
import { open as fsOpen } from 'node:fs/promises';

export class RecoveryError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export interface EngineInfo {
  kind: RecoveryEngineKind;
  available: boolean;
  path?: string;
  version?: string;
  reason?: string;
}

const MASK_RE = /^[?A-Za-z0-9ludsahHb ]{1,128}$/; // hashcat/JtR-style masks: literals + ?l ?u ?d ?s ?a ...

/** Validates a user-chosen mode. Wordlist/candidate files must be absolute; masks are charset-limited. */
export function validatePerformance(perf: unknown): RecoveryPerformance {
  const p = (perf ?? {}) as Record<string, unknown>;
  const intensity = p.intensity === 'max' ? 'max' : 'balanced';
  const device = p.device === 'gpu' || p.device === 'cpu' ? p.device : 'auto';
  return { intensity, device };
}

export function validateMode(mode: unknown): RecoveryMode {
  if (!mode || typeof mode !== 'object') throw new RecoveryError('invalid_mode');
  const m = mode as Record<string, unknown>;
  if (m.type === 'wordlist' || m.type === 'candidates') {
    const v = validateAbsolutePath(m.path);
    if (!v.ok) throw new RecoveryError(v.reason);
    return { type: m.type, path: v.path };
  }
  if (m.type === 'mask') {
    if (typeof m.mask !== 'string' || !MASK_RE.test(m.mask)) throw new RecoveryError('invalid_mask');
    return { type: 'mask', mask: m.mask };
  }
  throw new RecoveryError('invalid_mode');
}

/**
 * Builds the argument array for the configured engine. Arguments are always separate argv elements,
 * so a file path or mask can never be interpreted as a command. The engine reads the (already
 * extracted) target hash file the user's own `*2john`/tooling produced, or the target file directly
 * for engines that accept it. This function does not construct any shell string.
 */
export function buildEngineArgs(
  kind: RecoveryEngineKind,
  targetPath: string,
  mode: RecoveryMode,
  perf: RecoveryPerformance = { intensity: 'balanced', device: 'auto' },
  logicalCores = 1,
  hashcatMode?: number | null,
): string[] {
  const args: string[] = [];
  if (kind === 'john') {
    if (mode.type === 'wordlist' || mode.type === 'candidates') args.push(`--wordlist=${mode.path}`);
    else args.push('--mask=' + mode.mask);
    // Use several CPU cores in parallel. Balanced leaves headroom; max uses every logical core.
    const cores = perf.intensity === 'max' ? logicalCores : Math.max(1, Math.floor(logicalCores / 2));
    if (cores > 1) args.push(`--fork=${cores}`);
    args.push(targetPath);
  } else {
    // hashcat needs the hash type; -a 0 wordlist, -a 3 mask.
    if (typeof hashcatMode === 'number') args.push('-m', String(hashcatMode));
    if (mode.type === 'wordlist' || mode.type === 'candidates') args.push('-a', '0', targetPath, mode.path);
    else args.push('-a', '3', targetPath, mode.mask);
    // Workload profile: 2 = balanced default, 4 = use the machine fully (less responsive desktop).
    args.push('-w', perf.intensity === 'max' ? '4' : '2');
    // Device type: 1 = CPU, 2 = GPU. 'auto' lets hashcat use whatever it finds (usually the GPU).
    if (perf.device === 'gpu') args.push('-D', '2');
    else if (perf.device === 'cpu') args.push('-D', '1');
    args.push('--status', '--status-json', '--quiet');
  }
  return args;
}

// Progress lines look different per engine; parse both John ("g/s", "0g 0:00:00:03") and
// hashcat status JSON. Only counters/speed are read — never candidates.
export function parseProgress(line: string, kind: RecoveryEngineKind): Partial<RecoveryProgress> | null {
  const s = line.trim();
  if (!s) return null;
  if (kind === 'hashcat' && s.startsWith('{')) {
    try {
      const j = JSON.parse(s) as { progress?: [number, number]; recovered_hashes?: [number, number]; devices?: Array<{ speed: number }>; status?: number };
      const out: Partial<RecoveryProgress> = {};
      if (Array.isArray(j.progress)) {
        out.tried = j.progress[0];
        out.total = j.progress[1];
      }
      if (Array.isArray(j.devices)) out.rate = j.devices.reduce((a, d) => a + (d.speed ?? 0), 0);
      if (Array.isArray(j.recovered_hashes) && j.recovered_hashes[0] > 0) out.recovered = true;
      return out;
    } catch {
      return null;
    }
  }
  // John status line, e.g. "0g 0:00:00:05 33.3% ... 1234p/s 1234c/s 1234C/s"
  const rate = /([\d.]+)\s*[pcC]\/s/.exec(s);
  const guessed = /^(\d+)g\b/.exec(s);
  if (rate || guessed) {
    const out: Partial<RecoveryProgress> = {};
    if (rate) out.rate = Number(rate[1]);
    if (guessed && Number(guessed[1]) > 0) out.recovered = true;
    return out;
  }
  return null;
}

let SESSION_SEQ = 0;

interface Session {
  id: string;
  proc: ChildProcessWithoutNullStreams;
  info: RecoverySessionInfo;
  progress: RecoveryProgress;
  paused: boolean;
  onEvent: (id: string, ev: RecoveryEvent) => void;
  /** The extracted-hash file to crack and clean up (never the original archive). */
  hashFile: string;
  hashcatMode: number | null;
}

/** Runs a short-lived helper process and returns its combined output (used for hash extraction). */
function runCapture(exe: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = spawn(exe, args, { windowsHide: true });
    let out = '';
    let size = 0;
    const timer = setTimeout(() => {
      p.kill();
      reject(new RecoveryError('hash_extract_failed'));
    }, timeoutMs);
    const take = (b: Buffer) => {
      size += b.length;
      if (size <= 8 * 1024 * 1024) out += b.toString('utf8'); // a hash is tiny; ignore runaway output
    };
    p.stdout.on('data', take);
    p.stderr.on('data', take);
    p.on('error', () => {
      clearTimeout(timer);
      reject(new RecoveryError('hash_extract_failed'));
    });
    p.on('close', () => {
      clearTimeout(timer);
      resolve(out);
    });
  });
}

export type RecoveryEvent =
  | { type: 'progress'; progress: RecoveryProgress }
  | { type: 'done'; found: boolean; password: string | null }
  | { type: 'error'; error: string }
  | { type: 'stopped' };

export class RecoveryService {
  private sessions = new Map<string, Session>();

  constructor(private readonly enginePath: (kind: RecoveryEngineKind) => string | null) {}

  async engine(kind: RecoveryEngineKind): Promise<EngineInfo> {
    const path = this.enginePath(kind);
    if (!path) return { kind, available: false, reason: 'engine_not_configured' };
    if (!existsSync(path)) return { kind, available: false, reason: 'engine_path_missing' };
    return new Promise((resolve) => {
      const args = kind === 'john' ? ['--list=build-info'] : ['--version'];
      const p = spawn(path, args, { windowsHide: true });
      let out = '';
      const timer = setTimeout(() => {
        p.kill();
        resolve({ kind, available: false, reason: 'engine_check_failed' });
      }, 10_000);
      p.stdout.on('data', (b) => (out += b));
      p.stderr.on('data', (b) => (out += b));
      p.on('error', () => {
        clearTimeout(timer);
        resolve({ kind, available: false, reason: 'engine_check_failed' });
      });
      p.on('close', () => {
        clearTimeout(timer);
        const v = /(\d+\.\d+(?:\.\d+)?(?:-jumbo(?:-\d+)?)?)/.exec(out);
        resolve({ kind, available: true, path, version: v?.[1] });
      });
    });
  }

  list(): RecoverySessionInfo[] {
    return [...this.sessions.values()].map((s) => s.info);
  }

  /** Reads the file's own header to decide its format (the renderer is untrusted). */
  private async detectFormat(path: string): Promise<EncryptedFormat> {
    const fh = await fsOpen(path, 'r').catch(() => null);
    if (!fh) throw new RecoveryError('access_denied');
    try {
      const buf = Buffer.alloc(64);
      await fh.read(buf, 0, 64, 0);
      return detectEncryption(buf).format;
    } finally {
      await fh.close();
    }
  }

  /**
   * Turns an encrypted file into the hash file the engine cracks, using John's `*2john` extractor for
   * that format (they live next to john.exe). Returns the temp hash-file path and, for hashcat, the
   * hash type. The extracted hash and any candidate never leave the machine.
   */
  private async extractHash(format: EncryptedFormat, targetPath: string, kind: RecoveryEngineKind): Promise<{ hashFile: string; hashcatMode: number | null }> {
    const spec = extractorFor(format);
    if (!spec) throw new RecoveryError('engine_unsupported_file');
    // The extractors ship with John, so we locate them from John's configured path (even for hashcat).
    const johnPath = this.enginePath('john');
    if (!johnPath) throw new RecoveryError('hash_extractor_needs_john');
    if (!spec.compiled) throw new RecoveryError('hash_extractor_script'); // 7z/PDF/Office need Perl/Python
    const exe = spec.files.map((f) => join(dirname(johnPath), f)).find(existsSync);
    if (!exe) throw new RecoveryError('hash_extractor_missing');

    const out = await runCapture(exe, [targetPath], 120_000);
    const line = firstHashLine(out);
    if (!line) throw new RecoveryError('hash_extract_failed');
    const mode = kind === 'hashcat' ? hashcatMode(hashcatHash(line)) : null;
    if (kind === 'hashcat' && mode === null) throw new RecoveryError('hashcat_type_unsupported');

    const dir = join(subDir('temp'), 'recovery');
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const hashFile = join(dir, `${randomUUID().slice(0, 8)}.hash`);
    await writeFile(hashFile, `${kind === 'john' ? johnHashLine(line) : hashcatHash(line)}\n`, { mode: 0o600 });
    return { hashFile, hashcatMode: mode };
  }

  /** Starts a recovery session. `authorized` must be true (the UI collects an explicit confirmation). */
  async start(
    kind: RecoveryEngineKind,
    rawTarget: unknown,
    rawMode: unknown,
    rawPerf: unknown,
    authorized: boolean,
    onEvent: (id: string, ev: RecoveryEvent) => void,
  ): Promise<RecoveryStartResult> {
    if (authorized !== true) throw new RecoveryError('authorization_required');
    const engine = await this.engine(kind);
    if (!engine.available || !engine.path) throw new RecoveryError(engine.reason ?? 'engine_not_configured');
    const v = validateAbsolutePath(rawTarget);
    if (!v.ok) throw new RecoveryError(v.reason);
    const st = await stat(v.path).catch(() => null);
    if (!st || !st.isFile()) throw new RecoveryError('file_not_found');
    const mode = validateMode(rawMode);
    if ((mode.type === 'wordlist' || mode.type === 'candidates') && !existsSync(mode.path)) throw new RecoveryError('wordlist_not_found');
    const perf = validatePerformance(rawPerf);

    // John and hashcat can't read the archive directly: extract its hash with John's `*2john` tool.
    const format = await this.detectFormat(v.path);
    const { hashFile, hashcatMode: hcMode } = await this.extractHash(format, v.path, kind);

    const id = `rec-${Date.now().toString(36)}-${++SESSION_SEQ}`;
    const args = buildEngineArgs(kind, hashFile, mode, perf, Math.max(1, cpus().length), hcMode);
    const proc = spawn(engine.path, args, { windowsHide: true, env: { ...process.env }, cwd: dirname(hashFile) });

    const info: RecoverySessionInfo = { id, engine: kind, target: basename(v.path), mode: mode.type, startedAt: new Date().toISOString() };
    const progress: RecoveryProgress = { id, tried: 0, total: null, rate: null, recovered: false, elapsedMs: 0 };
    const started = Date.now();
    const session: Session = { id, proc, info, progress, paused: false, onEvent, hashFile, hashcatMode: hcMode };
    this.sessions.set(id, session);

    let found: string | null = null;
    const consume = (buf: Buffer) => {
      for (const line of buf.toString('utf8').split(/\r?\n/)) {
        const upd = parseProgress(line, kind);
        if (upd) {
          Object.assign(progress, upd, { elapsedMs: Date.now() - started });
          onEvent(id, { type: 'progress', progress: { ...progress } });
        }
      }
    };
    proc.stdout.on('data', consume);
    proc.stderr.on('data', consume);

    proc.on('error', () => {
      this.sessions.delete(id);
      void rm(hashFile, { force: true });
      onEvent(id, { type: 'error', error: 'engine_run_failed' });
    });
    proc.on('close', async () => {
      if (!this.sessions.has(id)) return; // stopped by the user
      this.sessions.delete(id);
      // The recovered secret is fetched via the engine's own "show" output and passed to the UI once,
      // then dropped. It is never logged.
      found = await this.reveal(kind, engine.path!, hashFile, hcMode).catch(() => null);
      void rm(hashFile, { force: true });
      onEvent(id, { type: 'done', found: !!found, password: found });
    });

    return { id, info };
  }

  /** Asks the engine to print the recovered secret for the extracted hash (John/hashcat `--show`). */
  private reveal(kind: RecoveryEngineKind, enginePath: string, hashFile: string, mode: number | null): Promise<string | null> {
    return new Promise((resolve) => {
      const args = kind === 'john' ? ['--show', hashFile] : ['-m', String(mode ?? 0), '--show', hashFile];
      const p = spawn(enginePath, args, { windowsHide: true, cwd: dirname(hashFile) });
      let out = '';
      const timer = setTimeout(() => {
        p.kill();
        resolve(null);
      }, 15_000);
      p.stdout.on('data', (b) => (out += b));
      p.on('error', () => {
        clearTimeout(timer);
        resolve(null);
      });
      p.on('close', () => {
        clearTimeout(timer);
        for (const l of out.split(/\r?\n/)) {
          if (kind === 'john') {
            // John: "target:PASSWORD" (login fixed to "target" when the hash file was written).
            if (l.startsWith('target:')) return resolve(l.slice('target:'.length) || null);
          } else if (l.includes(':') && l.startsWith('$')) {
            // hashcat: "HASH:PASSWORD"; the hash contains no ':', so split on the first one.
            return resolve(l.slice(l.indexOf(':') + 1) || null);
          }
        }
        resolve(null);
      });
    });
  }

  stop(id: unknown): void {
    if (typeof id !== 'string') return;
    const s = this.sessions.get(id);
    if (!s) return;
    this.sessions.delete(id);
    s.proc.kill('SIGKILL');
    void rm(s.hashFile, { force: true });
    s.onEvent(id, { type: 'stopped' });
  }

  /** Best-effort pause/resume via process signals (POSIX). On Windows this is a no-op and reported. */
  setPaused(id: unknown, paused: unknown): boolean {
    if (typeof id !== 'string') return false;
    const s = this.sessions.get(id);
    if (!s || process.platform === 'win32') return false;
    try {
      s.proc.kill(paused ? 'SIGSTOP' : 'SIGCONT');
      s.paused = !!paused;
      return true;
    } catch {
      return false;
    }
  }

  stopAll(): void {
    for (const id of [...this.sessions.keys()]) this.stop(id);
  }
}

/** Reads a file's header + (for PDFs) more, and reports its encryption. Used by the workspace. */
export async function detectFileEncryption(rawPath: unknown) {
  const v = validateAbsolutePath(rawPath);
  if (!v.ok) throw new RecoveryError(v.reason);
  const st = await stat(v.path).catch(() => null);
  if (!st || !st.isFile()) throw new RecoveryError('file_not_found');
  const fh = await fsOpen(v.path, 'r').catch(() => null);
  if (!fh) throw new RecoveryError('access_denied');
  try {
    // OLE documents (legacy Office, encrypted OOXML) are read whole so their streams can be checked.
    const sig = Buffer.alloc(8);
    await fh.read(sig, 0, 8, 0);
    const ole = sig.equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]));
    const size = Math.min(st.size, ole ? 64 * 1024 * 1024 : 4 * 1024 * 1024);
    const buf = Buffer.alloc(size);
    await fh.read(buf, 0, size, 0);
    // 7z keeps its index (and so the encryption facts) at the end of the archive.
    let index: Buffer | undefined;
    const range = sevenZipNextHeaderRange(buf.subarray(0, 32));
    if (range && range.offset + range.size <= st.size) {
      index = Buffer.alloc(range.size);
      await fh.read(index, 0, range.size, range.offset);
    }
    return { encryption: detectEncryption(buf.subarray(0, 64), buf, index), name: basename(v.path), sizeBytes: st.size };
  } finally {
    await fh.close();
  }
}
