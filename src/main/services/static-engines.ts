// Runs the bundled static-analysis engines (capa, Detect It Easy) on a file.
// Both only READ the file (they never execute it). Absolute executable paths from services/bundled.ts,
// argument arrays (no shell), timeouts and output caps; a failure never breaks the analysis.

import { execFile } from 'node:child_process';
import type { CapaRun, DieRun } from '../../shared/api';
import { parseCapa } from '../../core/capa';
import { parseDie } from '../../core/die';

function runJson(exe: string, args: string[], timeoutMs: number, maxBuffer: number, signal: AbortSignal): Promise<{ code: number; json: unknown; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(exe, args, { timeout: timeoutMs, windowsHide: true, maxBuffer, encoding: 'utf8', signal, env: { ...process.env, NO_COLOR: '1' } }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
      if (e?.name === 'AbortError' || signal.aborted) return reject(Object.assign(new Error('cancelled'), { code: 'cancelled' }));
      if (e?.killed) return reject(Object.assign(new Error('timeout'), { code: 'timeout' }));
      if (e?.code === 'ENOENT' || e?.code === 'EACCES') return reject(Object.assign(new Error('engine_missing'), { code: 'engine_missing' }));
      let json: unknown = null;
      const text = (stdout ?? '').trim();
      const start = text.indexOf('{');
      if (start >= 0) {
        try {
          json = JSON.parse(text.slice(start));
        } catch {
          json = null;
        }
      }
      resolve({ code: typeof e?.code === 'number' ? e.code : 0, json, stderr: String(stderr ?? '') });
    });
  });
}

export async function runCapa(exe: string, path: string, signal: AbortSignal): Promise<CapaRun> {
  const started = Date.now();
  const r = await runJson(exe, ['-j', path], 180_000, 64 * 1024 * 1024, signal);
  if (!r.json) {
    const unsupported = /unsupported|invalid file|not a supported|file type/i.test(r.stderr);
    return { ran: false, reason: unsupported ? 'engine_unsupported_file' : 'engine_failed' };
  }
  return { ran: true, ...parseCapa(r.json), durationMs: Date.now() - started };
}

export async function runDie(exe: string, path: string, signal: AbortSignal): Promise<DieRun> {
  const r = await runJson(exe, ['-j', path], 60_000, 8 * 1024 * 1024, signal);
  if (!r.json) return { ran: false, reason: 'engine_failed' };
  return { ran: true, ...parseDie(r.json) };
}
