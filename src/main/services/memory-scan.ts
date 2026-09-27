// Memory implant scan with the bundled HollowsHunter (hasherezade, BSD-2-Clause): looks inside the
// memory of running programs for injected or replaced code (process hollowing, reflective DLLs,
// shellcode, in-memory patches). Read-only: /ofilter 2 writes no dumps, and Blazma never uses the
// engine's /kill or /suspend options. Runs unelevated, so it covers the programs of the current user.

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { parseHollowsSummary, type MemoryScanSummary } from '../../core/hollows';
import { subDir } from './paths';

export class MemoryScanError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export const HOLLOWS_ARGS = ['/quiet', '/json', '/ofilter', '2'] as const;

export async function runMemoryScan(exe: string, signal: AbortSignal): Promise<MemoryScanSummary & { durationMs: number }> {
  if (process.platform !== 'win32') throw new MemoryScanError('unsupported_platform');
  const started = Date.now();
  const work = join(subDir('temp'), 'hollows', randomUUID());
  await mkdir(work, { recursive: true });
  try {
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(exe, [...HOLLOWS_ARGS], { cwd: work, timeout: 15 * 60_000, windowsHide: true, maxBuffer: 16 * 1024 * 1024, signal }, (err, out) => {
        const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
        if (e?.name === 'AbortError' || signal.aborted) return reject(new MemoryScanError('cancelled'));
        if (e?.killed) return reject(new MemoryScanError('timeout'));
        if (e?.code === 'ENOENT' || e?.code === 'EACCES') return reject(new MemoryScanError('engine_missing'));
        // Exit code 1 = "detected" (PESIEVE_DETECTED); the summary is on stdout either way.
        resolve(String(out ?? ''));
      });
    });
    const summary = parseHollowsSummary(stdout);
    if (!summary) throw new MemoryScanError('engine_failed');
    return { ...summary, durationMs: Date.now() - started };
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}
