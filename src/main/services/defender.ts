// Microsoft Defender adapter.
//
// - Scans run through MpCmdRun.exe located by absolute path (never PATH), with argument arrays
//   (never a shell). Custom (file/folder) scans use -DisableRemediation so Defender only REPORTS;
//   the user decides whether to quarantine. Quick/full scans follow Defender's own policy
//   (MpCmdRun does not support -DisableRemediation for them); the UI says so.
// - Threat history is read with a fixed, read-only PowerShell script.
// - Nothing here changes Defender configuration.

import { execFile } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { runPowerShellJson } from './powershell';

import type { DefenderScanKind, DefenderScanResult, DefenderThreat } from '../../shared/api';
export type { DefenderScanKind, DefenderScanResult, DefenderThreat };

export class DefenderError extends Error {
  constructor(readonly code: string, readonly detail?: string) {
    super(code);
  }
}

/** Parses "4.18.24090.11-0" style folder names for sorting. */
export function platformVersionKey(name: string): number[] {
  return name.split(/[.-]/).map((p) => Number.parseInt(p, 10) || 0);
}

function compareVersions(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Locates MpCmdRun.exe: newest platform folder first, then the Program Files copy. */
export function findMpCmdRun(env: NodeJS.ProcessEnv = process.env, exists = existsSync, list = readdirSync): string | null {
  if (process.platform !== 'win32' && !env.BLAZMA_TEST_DEFENDER) return null;
  const candidates: string[] = [];
  const platformDir = join(env.ProgramData || 'C:\\ProgramData', 'Microsoft', 'Windows Defender', 'Platform');
  try {
    const versions = (list(platformDir) as string[])
      .filter((n) => /^\d+(\.\d+)+(-\d+)?$/.test(n))
      .sort((a, b) => compareVersions(platformVersionKey(b), platformVersionKey(a)));
    for (const v of versions) candidates.push(join(platformDir, v, 'MpCmdRun.exe'));
  } catch {
    /* platform folder missing or unreadable */
  }
  candidates.push(join(env.ProgramFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe'));
  return candidates.find((c) => exists(c)) ?? null;
}

/** Extracts threat names from MpCmdRun output ("Threat : Virus:DOS/EICAR_Test_File"). */
export function parseThreats(output: string): string[] {
  const out = new Set<string>();
  for (const m of output.matchAll(/^\s*Threat\s*:\s*(.+?)\s*$/gim)) out.add(m[1]!);
  return [...out];
}

export function buildScanArgs(kind: DefenderScanKind, target?: string): string[] {
  switch (kind) {
    case 'quick':
      return ['-Scan', '-ScanType', '1'];
    case 'full':
      return ['-Scan', '-ScanType', '2'];
    case 'path':
      if (!target) throw new DefenderError('invalid_input');
      // Target is a separate argv element: no quoting/concatenation, so no injection.
      return ['-Scan', '-ScanType', '3', '-File', target, '-DisableRemediation'];
  }
}

const TIMEOUTS: Record<DefenderScanKind, number> = {
  path: 15 * 60_000,
  quick: 60 * 60_000,
  full: 12 * 60 * 60_000,
};

export function runDefenderScan(kind: DefenderScanKind, target: string | null, signal: AbortSignal): Promise<DefenderScanResult> {
  if (process.platform !== 'win32') return Promise.reject(new DefenderError('unsupported_platform'));
  const exe = findMpCmdRun();
  if (!exe) return Promise.reject(new DefenderError('defender_unavailable'));
  const args = buildScanArgs(kind, target ?? undefined);
  const started = Date.now();

  return new Promise((resolve, reject) => {
    execFile(
      exe,
      args,
      { timeout: TIMEOUTS[kind], windowsHide: true, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8', signal },
      (err, stdout, stderr) => {
        const text = `${stdout ?? ''}\n${stderr ?? ''}`;
        if (err) {
          const e = err as NodeJS.ErrnoException & { code?: string | number; killed?: boolean };
          if (e.name === 'AbortError' || signal.aborted) return reject(new DefenderError('cancelled'));
          if (e.killed) return reject(new DefenderError('timeout'));
          // MpCmdRun returns 2 when threats were found: that is a RESULT, not an error.
          if ((e as { code?: unknown }).code === 2) {
            return resolve({ kind, target, status: 'threats_found', threats: parseThreats(text), exitCode: 2, durationMs: Date.now() - started });
          }
          return reject(new DefenderError('defender_scan_failed', text.trim().slice(0, 400)));
        }
        const threats = parseThreats(text);
        resolve({
          kind,
          target,
          status: threats.length ? 'threats_found' : 'no_threats',
          threats,
          exitCode: 0,
          durationMs: Date.now() - started,
        });
      },
    );
  });
}

const THREAT_HISTORY_SCRIPT = `
$names = @{}
Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = @{ n = [string]$_.ThreatName; s = [int]$_.SeverityID } }
$rows = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 100 | ForEach-Object {
  $i = $names[[string]$_.ThreatID]
  @{
    id = [string]$_.ThreatID
    name = if ($i) { $i.n } else { $null }
    severity = if ($i) { $i.s } else { $null }
    detected = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') } else { $null }
    resources = @($_.Resources | ForEach-Object { [string]$_ })
    success = [bool]$_.ActionSuccess
  }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
`;

export async function getThreatHistory(): Promise<DefenderThreat[]> {
  if (process.platform !== 'win32') throw new DefenderError('unsupported_platform');
  const res = await runPowerShellJson<unknown>(THREAT_HISTORY_SCRIPT, { timeoutMs: 30_000 });
  if (!res.ok) throw new DefenderError(res.error === 'powershell_failed' ? 'defender_history_unavailable' : res.error, res.detail);
  const rows = Array.isArray(res.data) ? res.data : res.data ? [res.data] : [];
  return rows.map((r) => {
    const x = r as Record<string, unknown>;
    return {
      id: String(x.id ?? ''),
      name: typeof x.name === 'string' ? x.name : null,
      severity: typeof x.severity === 'number' ? x.severity : null,
      detected: typeof x.detected === 'string' ? x.detected : null,
      resources: Array.isArray(x.resources) ? x.resources.map(String) : [],
      actionSuccess: Boolean(x.success),
    };
  });
}

export const __defenderScriptsForTest = { THREAT_HISTORY_SCRIPT };
