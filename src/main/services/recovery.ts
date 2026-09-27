// Authorized password recovery workspace.
//
// Scope and safety (see SECURITY.md):
//  - This is for files the user OWNS or is explicitly authorized to recover (e.g. their own
//    forgotten archive/PDF password). The UI requires an explicit authorization confirmation.
//  - BLAZMA CYBER does NOT implement a recovery engine and does NOT bundle one. It runs a mature
//    engine the user installed and configured (John the Ripper or hashcat), located by the path
//    set in Settings, invoked with an argument array (never a shell).
//  - Recovered results are returned to the UI only. They are NEVER written to logs or history.
//  - Everything is local. Nothing about the file, its hash, or any candidate leaves the machine.
//
// The session runner here is engine-agnostic: it launches the configured executable with validated
// arguments, streams progress, and supports stop / pause / resume. It parses generic status output.

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { stat } from 'node:fs/promises';
import { basename } from 'node:path';
import type { RecoveryEngineKind, RecoveryMode, RecoveryProgress, RecoverySessionInfo, RecoveryStartResult } from '../../shared/api';
import { validateAbsolutePath } from '../../core/validation';
import { detectEncryption } from '../../core/encrypted';
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
export function buildEngineArgs(kind: RecoveryEngineKind, targetPath: string, mode: RecoveryMode): string[] {
  const args: string[] = [];
  if (kind === 'john') {
    if (mode.type === 'wordlist' || mode.type === 'candidates') args.push(`--wordlist=${mode.path}`);
    else args.push('--mask=' + mode.mask);
    args.push(targetPath);
  } else {
    // hashcat: user pre-extracts the hash; -a 0 wordlist, -a 3 mask. Engine autodetects the type.
    if (mode.type === 'wordlist' || mode.type === 'candidates') args.push('-a', '0', targetPath, mode.path);
    else args.push('-a', '3', targetPath, mode.mask);
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

  /** Starts a recovery session. `authorized` must be true (the UI collects an explicit confirmation). */
  async start(
    kind: RecoveryEngineKind,
    rawTarget: unknown,
    rawMode: unknown,
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

    const id = `rec-${Date.now().toString(36)}-${++SESSION_SEQ}`;
    const args = buildEngineArgs(kind, v.path, mode);
    const proc = spawn(engine.path, args, { windowsHide: true, env: { ...process.env } });

    const info: RecoverySessionInfo = { id, engine: kind, target: basename(v.path), mode: mode.type, startedAt: new Date().toISOString() };
    const progress: RecoveryProgress = { id, tried: 0, total: null, rate: null, recovered: false, elapsedMs: 0 };
    const started = Date.now();
    const session: Session = { id, proc, info, progress, paused: false, onEvent };
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
      onEvent(id, { type: 'error', error: 'engine_run_failed' });
    });
    proc.on('close', async () => {
      if (!this.sessions.has(id)) return; // stopped by the user
      this.sessions.delete(id);
      // The recovered secret is fetched via the engine's own "show" output and passed to the UI once,
      // then dropped. It is never logged.
      found = await this.reveal(kind, engine.path!, v.path).catch(() => null);
      onEvent(id, { type: 'done', found: !!found, password: found });
    });

    return { id, info };
  }

  /** Asks the engine to print the recovered secret for this target (John --show / hashcat --show). */
  private reveal(kind: RecoveryEngineKind, enginePath: string, target: string): Promise<string | null> {
    return new Promise((resolve) => {
      const args = kind === 'john' ? ['--show', target] : ['--show', target];
      const p = spawn(enginePath, args, { windowsHide: true });
      let out = '';
      const timer = setTimeout(() => {
        p.kill();
        resolve(null);
      }, 10_000);
      p.stdout.on('data', (b) => (out += b));
      p.on('error', () => {
        clearTimeout(timer);
        resolve(null);
      });
      p.on('close', () => {
        clearTimeout(timer);
        // John: "target:PASSWORD:..." ; take the field after the first colon of a data line.
        const line = out.split(/\r?\n/).find((l) => l.includes(':') && !/password hash/i.test(l));
        resolve(line ? line.split(':')[1] ?? null : null);
      });
    });
  }

  stop(id: unknown): void {
    if (typeof id !== 'string') return;
    const s = this.sessions.get(id);
    if (!s) return;
    this.sessions.delete(id);
    s.proc.kill('SIGKILL');
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
    const size = Math.min(st.size, 4 * 1024 * 1024);
    const buf = Buffer.alloc(size);
    await fh.read(buf, 0, size, 0);
    return { encryption: detectEncryption(buf.subarray(0, 64), buf), name: basename(v.path), sizeBytes: st.size };
  } finally {
    await fh.close();
  }
}
