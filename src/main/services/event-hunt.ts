// Event-log hunting with the bundled Hayabusa (Yamato Security, AGPL-3.0) and its Sigma/Hayabusa
// rules (Detection Rule License 1.1). Hayabusa only READS .evtx files; BLAZMA never changes logs.
//
// - Files / folders chosen by the user: run unelevated, cancellable.
// - "This computer": Windows keeps its event logs readable by administrators only, so Hayabusa is
//   started with a Windows UAC prompt (Start-Process -Verb RunAs) after the user confirmed in BLAZMA.
//   Only this one engine run is elevated; BLAZMA itself stays unelevated.

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createReadStream, existsSync } from 'node:fs';
import { mkdir, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { HuntAccumulator, parseHayabusaLine, type EventDetection, type EventHuntSummary } from '../../core/hayabusa';
import { validateAbsolutePath } from '../../core/validation';
import { subDir } from './paths';
import { runPowerShellJson } from './powershell';

export class EventHuntError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

import type { EventHuntOptions, EventHuntResult, EventHuntSource } from '../../shared/api';

const LEVELS = ['low', 'medium', 'high', 'critical'] as const;
const DAYS = [1, 7, 30, 90] as const;

export function parseOptions(raw: unknown): EventHuntOptions {
  const o = (raw ?? {}) as Record<string, unknown>;
  if (!LEVELS.includes(o.minLevel as never)) throw new EventHuntError('invalid_input');
  if (o.days !== null && !DAYS.includes(o.days as never)) throw new EventHuntError('invalid_input');
  return { minLevel: o.minLevel as EventHuntOptions['minLevel'], days: o.days as EventHuntOptions['days'] };
}

export async function parseSource(raw: unknown): Promise<EventHuntSource> {
  const s = (raw ?? {}) as Record<string, unknown>;
  if (s.kind === 'live') return { kind: 'live' };
  if (s.kind !== 'file' && s.kind !== 'dir') throw new EventHuntError('invalid_input');
  const v = validateAbsolutePath(s.path);
  if (!v.ok) throw new EventHuntError(v.reason);
  const st = await stat(v.path).catch(() => null);
  if (!st) throw new EventHuntError('file_not_found');
  if (s.kind === 'file' && (!st.isFile() || !/\.evtx$/i.test(v.path))) throw new EventHuntError('evtx_expected');
  if (s.kind === 'dir' && !st.isDirectory()) throw new EventHuntError('not_a_folder');
  return { kind: s.kind, path: v.path };
}

/** Arguments shared by every run: JSON lines, rule authors kept (DRL), no prompts/colours/banner, UTC. */
export function hayabusaArgs(input: string[], out: string, rules: string, opts: EventHuntOptions): string[] {
  return [
    'dfir-timeline', ...input, '-o', out, '-t', 'jsonl', '-p', 'super-verbose',
    '-w', '-q', '-K', '-N', '-C', '-U', '-Q', '-b', '-m', opts.minLevel, '-r', rules,
    ...(opts.days ? ['--time-offset', `${opts.days}d`] : []),
  ];
}

async function readResults(out: string): Promise<{ summary: EventHuntSummary; rows: EventDetection[] }> {
  const acc = new HuntAccumulator(3000);
  if (existsSync(out)) {
    const rl = createInterface({ input: createReadStream(out, { encoding: 'utf8' }), crlfDelay: Infinity });
    for await (const line of rl) {
      const d = parseHayabusaLine(line);
      if (d) acc.add(d);
    }
  }
  return { summary: acc.summary(), rows: acc.sortedRows() };
}

// Elevated run for "this computer". Arguments containing paths are quoted with [char]34 (no double
// quotes in scripts); every value comes from BLAZMA itself via BLAZMA_ARG_* (never from the renderer).
export const LIVE_SCRIPT = `
$ErrorActionPreference = 'Stop'
$q = [char]34
$al = @('dfir-timeline', '-l', '-o', ($q + $env:BLAZMA_ARG_OUT + $q), '-t', 'jsonl', '-p', 'super-verbose', '-w', '-q', '-K', '-N', '-C', '-U', '-Q', '-b', '-m', $env:BLAZMA_ARG_LEVEL, '-r', ($q + $env:BLAZMA_ARG_RULES + $q))
if ($env:BLAZMA_ARG_OFFSET) { $al += @('--time-offset', $env:BLAZMA_ARG_OFFSET) }
try {
  $p = Start-Process -FilePath $env:BLAZMA_ARG_EXE -ArgumentList $al -WorkingDirectory $env:BLAZMA_ARG_CWD -Verb RunAs -WindowStyle Hidden -Wait -PassThru
  @{ ok = $true; exitCode = $p.ExitCode } | ConvertTo-Json -Compress
} catch {
  $e = $_.Exception
  $code = 0
  while ($e) { if ($e.NativeErrorCode) { $code = $e.NativeErrorCode }; $e = $e.InnerException }
  @{ ok = $false; cancelled = ($code -eq 1223); message = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
`;

export async function runEventHunt(exe: string, source: EventHuntSource, opts: EventHuntOptions, signal: AbortSignal): Promise<EventHuntResult> {
  const started = Date.now();
  const rules = join(dirname(exe), 'rules');
  if (!existsSync(rules)) throw new EventHuntError('engine_failed');
  const work = join(subDir('temp'), 'hayabusa', randomUUID());
  await mkdir(work, { recursive: true, mode: 0o700 });
  const out = join(work, 'results.jsonl');
  try {
    if (source.kind === 'live') {
      if (process.platform !== 'win32') throw new EventHuntError('unsupported_platform');
      const res = await runPowerShellJson<{ ok: boolean; exitCode?: number; cancelled?: boolean }>(LIVE_SCRIPT, {
        timeoutMs: 60 * 60_000,
        args: { EXE: exe, OUT: out, RULES: rules, CWD: work, LEVEL: opts.minLevel, OFFSET: opts.days ? `${opts.days}d` : '' },
      });
      if (!res.ok) throw new EventHuntError(res.error);
      if (!res.data?.ok) throw new EventHuntError(res.data?.cancelled ? 'elevation_cancelled' : 'engine_run_failed');
      if (res.data.exitCode !== 0) throw new EventHuntError('engine_run_failed');
    } else {
      const input = source.kind === 'file' ? ['-f', source.path] : ['-d', source.path];
      await new Promise<void>((resolve, reject) => {
        execFile(exe, hayabusaArgs(input, out, rules, opts), { cwd: work, timeout: 30 * 60_000, windowsHide: true, maxBuffer: 16 * 1024 * 1024, signal, env: { ...process.env, NO_COLOR: '1' } }, (err) => {
          const e = err as (NodeJS.ErrnoException & { killed?: boolean }) | null;
          if (!e) return resolve();
          if (e.name === 'AbortError' || signal.aborted) return reject(new EventHuntError('cancelled'));
          if (e.killed) return reject(new EventHuntError('timeout'));
          if (e.code === 'ENOENT' || e.code === 'EACCES') return reject(new EventHuntError('engine_missing'));
          reject(new EventHuntError('engine_run_failed'));
        });
      });
    }
    const { summary, rows } = await readResults(out);
    return { ...summary, rows, source: { kind: source.kind, path: source.kind === 'live' ? null : source.path }, durationMs: Date.now() - started };
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}
