// Nmap integration. Nmap is NOT bundled: the user installs it (nmap.org); Blazma finds it and runs it
// with fixed profiles (see core/nmap.ts) against the user's own networks only, after an explicit
// authorization confirmation. No NSE scripts, no custom flags, no public targets.

import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { NMAP_PROFILES, nmapFindings, nmapProgress, nmapTargetAllowed, parseNmapXml, type NmapProfile } from '../../core/nmap';
import { macInfo } from '../../core/oui';
import type { NmapInfo, NmapResult } from '../../shared/api';
import { subDir } from './paths';

export class NmapError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const TIMEOUT: Record<NmapProfile, number> = { hosts: 5 * 60_000, quick: 20 * 60_000, standard: 60 * 60_000 };

export function findNmap(): string | null {
  const candidates = process.platform === 'win32'
    ? [
      join(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Nmap', 'nmap.exe'),
      join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Nmap', 'nmap.exe'),
    ]
    : ['/usr/bin/nmap', '/usr/local/bin/nmap', '/opt/homebrew/bin/nmap'];
  return candidates.find((p) => existsSync(p)) ?? null;
}

export async function nmapInfo(): Promise<NmapInfo> {
  const exe = findNmap();
  if (!exe) return { installed: false, version: null };
  const out = await new Promise<string>((resolve) => {
    const c = spawn(exe, ['--version'], { windowsHide: true });
    let s = '';
    c.stdout.on('data', (d) => (s += d));
    c.on('error', () => resolve(''));
    c.on('close', () => resolve(s));
    setTimeout(() => c.kill(), 15_000);
  });
  return { installed: true, version: /Nmap version (\S+)/.exec(out)?.[1] ?? null };
}

export function parseNmapRequest(target: unknown, profile: unknown, authorized: unknown, attachedCidrs: string[]): { target: string; profile: NmapProfile } {
  if (authorized !== true) throw new NmapError('authorization_required');
  if (profile !== 'hosts' && profile !== 'quick' && profile !== 'standard') throw new NmapError('invalid_input');
  if (typeof target !== 'string') throw new NmapError('invalid_target');
  const t = target.trim();
  if (!nmapTargetAllowed(t, attachedCidrs)) throw new NmapError('nmap_target_not_local');
  return { target: t, profile };
}

export async function runNmap(target: string, profile: NmapProfile, signal: AbortSignal, progress?: (pct: number) => void): Promise<NmapResult> {
  const exe = findNmap();
  if (!exe) throw new NmapError('nmap_missing');
  if (signal.aborted) throw new NmapError('cancelled');
  const work = join(subDir('temp'), 'nmap', randomUUID());
  await mkdir(work, { recursive: true, mode: 0o700 });
  const xml = join(work, 'scan.xml');
  const started = Date.now();
  try {
    const args = [...NMAP_PROFILES[profile], '--stats-every', '2s', '--no-stylesheet', '-oX', xml, target];
    const code = await new Promise<number>((resolve, reject) => {
      const child = spawn(exe, args, { windowsHide: true });
      const kill = () => child.kill();
      signal.addEventListener('abort', kill, { once: true });
      const timer = setTimeout(kill, TIMEOUT[profile]);
      let buf = '';
      child.stdout.on('data', (d: Buffer) => {
        buf += d.toString('utf8');
        const lines = buf.split(/\r?\n/);
        buf = lines.pop() ?? '';
        for (const l of lines) {
          const pct = nmapProgress(l);
          if (pct !== null) progress?.(pct);
        }
      });
      child.stderr.on('data', () => {});
      child.on('error', (e: NodeJS.ErrnoException) => reject(new NmapError(e.code === 'ENOENT' ? 'nmap_missing' : 'engine_run_failed')));
      child.on('close', (c) => {
        clearTimeout(timer);
        signal.removeEventListener('abort', kill);
        resolve(c ?? -1);
      });
    });
    if (signal.aborted) throw new NmapError('cancelled');
    if (code !== 0 || !existsSync(xml)) throw new NmapError('engine_run_failed');
    const run = parseNmapXml(await readFile(xml, 'utf8'));
    // Fill in the manufacturer from Blazma's offline registry when Nmap didn't name one.
    for (const h of run.hosts) if (h.mac && !h.vendor) h.vendor = macInfo(h.mac)?.vendor ?? null;
    return { target, profile, run, findings: nmapFindings(run), durationMs: Date.now() - started };
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}
