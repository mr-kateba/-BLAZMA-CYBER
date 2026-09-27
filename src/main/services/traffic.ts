// Network traffic analysis: capture files chosen by the user, and short live captures.
//
// Blazma only OBSERVES: it never transmits, spoofs, injects or decrypts anything. Live capture is
// always an explicit, time-limited action started by the user:
//  - Wireshark's dumpcap (user-installed, with Npcap) when present — runs unelevated, cancellable.
//  - Otherwise Windows' built-in pktmon, which needs administrator rights: one pktmon run is started
//    through a Windows UAC prompt after the user confirmed in Blazma (the app itself stays unelevated).
// The capture file is analysed and then deleted unless the user chooses to keep it.

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createReadStream, existsSync } from 'node:fs';
import { copyFile, mkdir, rm, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { CaptureReader } from '../../core/traffic/pcap';
import { TrafficAnalyzer } from '../../core/traffic/analyzer';
import { validateAbsolutePath } from '../../core/validation';
import type { CaptureEnvironment, CaptureInterface, TrafficResult } from '../../shared/api';
import { subDir } from './paths';
import { runPowerShellJson } from './powershell';

export class TrafficError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const MAX_FILE = 4 * 1024 * 1024 * 1024;
export const CAPTURE_SECONDS = [15, 30, 60, 120, 300] as const;

const sys32 = () => join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
function wiresharkDirs(): string[] {
  return [
    join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Wireshark'),
    join(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Wireshark'),
    join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Wireshark'),
  ];
}
function findWireshark(exe: string): string | null {
  if (process.platform !== 'win32') return null;
  for (const d of wiresharkDirs()) if (existsSync(join(d, exe))) return join(d, exe);
  return null;
}

export function captureEnvironment(): CaptureEnvironment {
  const win = process.platform === 'win32';
  const npcap = win && ['Npcap\\wpcap.dll', 'wpcap.dll'].some((f) => existsSync(join(sys32(), f)));
  const dumpcap = findWireshark('dumpcap.exe');
  const pktmon = win && existsSync(join(sys32(), 'pktmon.exe'));
  return {
    platform: win ? 'windows' : 'other',
    dumpcap: !!dumpcap && npcap,
    npcap,
    wireshark: !!findWireshark('Wireshark.exe'),
    pktmon,
  };
}

function run(file: string, args: string[], opts: { timeout: number; signal?: AbortSignal }): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: opts.timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024, signal: opts.signal, encoding: 'utf8' }, (err, stdout) => {
      const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
      if (e && (e.name === 'AbortError' || opts.signal?.aborted)) return resolve({ code: -2, stdout });
      if (e && (e.code === 'ENOENT' || e.code === 'EACCES')) return reject(new TrafficError('engine_missing'));
      resolve({ code: e ? (typeof e.code === 'number' ? e.code : -1) : 0, stdout });
    });
  });
}

/** `dumpcap -D` lines: "1. \Device\NPF_{GUID} (Wi-Fi)". The index is what dumpcap accepts. */
export function parseDumpcapInterfaces(out: string): CaptureInterface[] {
  const list: CaptureInterface[] = [];
  for (const line of out.split(/\r?\n/)) {
    const m = /^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?\s*$/.exec(line.trim());
    if (m) list.push({ id: m[1]!, name: m[3] ?? m[2]!, loopback: /loopback/i.test(line) });
  }
  return list;
}

export async function captureInterfaces(): Promise<CaptureInterface[]> {
  const dumpcap = findWireshark('dumpcap.exe');
  if (!dumpcap) return [];
  const r = await run(dumpcap, ['-D'], { timeout: 20_000 });
  return parseDumpcapInterfaces(r.stdout);
}

/** Streams a capture file through the analyzer; never loads the whole file into memory. */
export async function analyzeCaptureFile(path: string, signal: AbortSignal, progress?: (done: number, total: number) => void): Promise<Omit<TrafficResult, 'source' | 'durationMs'> & { format: string | null; size: number }> {
  const st = await stat(path).catch(() => null);
  if (!st || !st.isFile()) throw new TrafficError('file_not_found');
  if (st.size > MAX_FILE) throw new TrafficError('file_too_large');
  const reader = new CaptureReader();
  const analyzer = new TrafficAnalyzer();
  let done = 0;
  let last = 0;
  for await (const chunk of createReadStream(path, { highWaterMark: 1024 * 1024 })) {
    if (signal.aborted) throw new TrafficError('cancelled');
    const buf = chunk as Buffer;
    for (const f of reader.push(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength))) analyzer.add(f);
    if (reader.error) break;
    done += buf.byteLength;
    if (done - last > 4 * 1024 * 1024) {
      last = done;
      progress?.(done, st.size);
    }
  }
  if (reader.error && reader.detectedFormat === null) throw new TrafficError('not_a_capture');
  progress?.(st.size, st.size);
  return { report: analyzer.finish(), readError: reader.error, format: reader.detectedFormat, size: st.size };
}

export async function analyzeFile(rawPath: unknown, signal: AbortSignal, progress?: (done: number, total: number) => void): Promise<TrafficResult> {
  const v = validateAbsolutePath(rawPath);
  if (!v.ok) throw new TrafficError(v.reason);
  const started = Date.now();
  const r = await analyzeCaptureFile(v.path, signal, progress);
  return { report: r.report, readError: r.readError, source: { kind: 'file', name: basename(v.path), sizeBytes: r.size, backend: null, seconds: null, keptPath: null }, durationMs: Date.now() - started };
}

// Elevated pktmon run. All values come from Blazma (BLAZMA_ARG_*), never from the renderer. The
// elevated PowerShell receives one command line built here; paths are single-quoted with ' doubled
// (no double quotes in scripts), the duration is a validated integer.
export const PKTMON_SCRIPT = `
$ErrorActionPreference = 'Stop'
$sq = [string][char]39
function Q([string]$s) { $sq + $s.Replace($sq, $sq + $sq) + $sq }
$pk = Q $env:BLAZMA_ARG_PKTMON
$etl = Q $env:BLAZMA_ARG_ETL
$out = Q $env:BLAZMA_ARG_OUT
$sec = [int]$env:BLAZMA_ARG_SECONDS
$cmd = '& ' + $pk + ' stop | Out-Null; & ' + $pk + ' start --capture --comp nics --pkt-size 1600 --file-size 256 --file-name ' + $etl + ' | Out-Null; Start-Sleep -Seconds ' + $sec + '; & ' + $pk + ' stop | Out-Null; & ' + $pk + ' etl2pcap ' + $etl + ' --out ' + $out + ' | Out-Null'
try {
  $ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  $p = Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cmd) -Verb RunAs -WindowStyle Hidden -Wait -PassThru
  @{ ok = $true; exitCode = $p.ExitCode } | ConvertTo-Json -Compress
} catch {
  $e = $_.Exception
  $code = 0
  while ($e) { if ($e.NativeErrorCode) { $code = $e.NativeErrorCode }; $e = $e.InnerException }
  @{ ok = $false; cancelled = ($code -eq 1223); message = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
`;

export interface LiveOptions {
  seconds: (typeof CAPTURE_SECONDS)[number];
  backend: 'pktmon' | 'dumpcap';
  iface: string | null;
  keep: boolean;
}

export function parseLiveOptions(raw: unknown): LiveOptions {
  const o = (raw ?? {}) as Record<string, unknown>;
  if (!CAPTURE_SECONDS.includes(o.seconds as never)) throw new TrafficError('invalid_input');
  if (o.backend !== 'pktmon' && o.backend !== 'dumpcap') throw new TrafficError('invalid_input');
  if (o.iface !== null && o.iface !== undefined && !(typeof o.iface === 'string' && /^\d{1,3}$/.test(o.iface))) throw new TrafficError('invalid_input');
  return { seconds: o.seconds as LiveOptions['seconds'], backend: o.backend, iface: (o.iface as string | null | undefined) ?? null, keep: o.keep === true };
}

/**
 * Captures for `seconds`, analyses, and deletes the capture — unless `keep`, in which case the
 * .pcapng stays in Blazma's captures folder (the user can open it in Wireshark or add it to a case).
 */
export async function liveCapture(opts: LiveOptions, signal: AbortSignal, progress?: (done: number, total: number) => void): Promise<TrafficResult> {
  if (process.platform !== 'win32') throw new TrafficError('unsupported_platform');
  const env = captureEnvironment();
  const started = Date.now();
  const work = join(subDir('temp'), 'capture', randomUUID());
  await mkdir(work, { recursive: true, mode: 0o700 });
  const out = join(work, 'capture.pcapng');
  const tick = setInterval(() => progress?.(Math.min(opts.seconds, Math.round((Date.now() - started) / 1000)), opts.seconds), 1000);
  try {
    if (opts.backend === 'dumpcap') {
      const dumpcap = findWireshark('dumpcap.exe');
      if (!dumpcap || !env.npcap) throw new TrafficError('engine_missing');
      const r = await run(dumpcap, ['-i', opts.iface ?? '1', '-a', `duration:${opts.seconds}`, '-a', 'filesize:262144', '-s', '1600', '-q', '-w', out], { timeout: (opts.seconds + 60) * 1000, signal });
      // Cancel = stop early and analyse what was captured so far.
      if (r.code !== 0 && r.code !== -2) throw new TrafficError('capture_failed');
    } else {
      if (!env.pktmon) throw new TrafficError('engine_missing');
      const res = await runPowerShellJson<{ ok: boolean; exitCode?: number; cancelled?: boolean }>(PKTMON_SCRIPT, {
        timeoutMs: (opts.seconds + 180) * 1000,
        args: { PKTMON: join(sys32(), 'pktmon.exe'), ETL: join(work, 'capture.etl'), OUT: out, SECONDS: String(opts.seconds) },
      });
      if (!res.ok) throw new TrafficError(res.error);
      if (!res.data?.ok) throw new TrafficError(res.data?.cancelled ? 'capture_elevation_cancelled' : 'capture_failed');
    }
    if (!existsSync(out)) throw new TrafficError('capture_failed');
    const r = await analyzeCaptureFile(out, new AbortController().signal);
    let keptPath: string | null = null;
    if (opts.keep) {
      const dir = subDir('captures');
      await mkdir(dir, { recursive: true });
      keptPath = join(dir, `capture-${new Date().toISOString().replace(/[:.]/g, '-')}.pcapng`);
      await copyFile(out, keptPath);
    }
    return {
      report: r.report,
      readError: r.readError,
      source: { kind: 'live', name: null, sizeBytes: r.size, backend: opts.backend, seconds: opts.seconds, keptPath },
      durationMs: Date.now() - started,
    };
  } finally {
    clearInterval(tick);
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}

/** Opens a capture in the user's Wireshark (only files Blazma kept, or a path the user picked). */
export async function openInWireshark(path: string): Promise<void> {
  const exe = findWireshark('Wireshark.exe');
  if (!exe) throw new TrafficError('engine_missing');
  const { spawn } = await import('node:child_process');
  const child = spawn(exe, [path], { detached: true, stdio: 'ignore', windowsHide: false });
  child.on('error', () => {});
  child.unref();
}
