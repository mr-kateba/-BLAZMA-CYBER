// HollowsHunter (hasherezade, BSD-2-Clause) memory-implant scan results (pure).
// Input: stdout of `hollows_hunter.exe /quiet /json /ofilter 2` — the summary written by
// HHScanReport::toJSON (scan_time_ms, scanned_count, failed_count, suspicious_count, suspicious[]).
// Findings are leads: games, anti-cheat, security products and .NET runtimes can modify memory too.

export type ImplantIndicator = 'replaced' | 'hdr_modified' | 'patched' | 'iat_hooked' | 'implanted_pe' | 'implanted_shc' | 'unreachable_file' | 'other';
export const INDICATORS: readonly ImplantIndicator[] = ['implanted_pe', 'implanted_shc', 'replaced', 'hdr_modified', 'patched', 'iat_hooked', 'unreachable_file', 'other'];
const STRONG: ImplantIndicator[] = ['implanted_pe', 'implanted_shc', 'replaced'];
const MODIFIED: ImplantIndicator[] = ['hdr_modified', 'patched', 'iat_hooked'];

export interface SuspiciousProcess {
  pid: number;
  name: string;
  managed: boolean;
  indicators: Partial<Record<ImplantIndicator, number>>;
  severity: 'high' | 'medium' | 'low';
}

export interface MemoryScanSummary {
  scanned: number | null;
  failed: number | null;
  scanTimeMs: number | null;
  suspicious: SuspiciousProcess[];
}

const n = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);

/** Returns null when the output does not contain HollowsHunter's JSON summary (never guessed as "clean"). */
export function parseHollowsSummary(stdout: string): MemoryScanSummary | null {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(stdout.slice(start, end + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (n(o.scanned_count) === null && !Array.isArray(o.suspicious)) return null;
  const suspicious = (Array.isArray(o.suspicious) ? o.suspicious : []).flatMap((raw) => {
    const p = (raw ?? {}) as Record<string, unknown>;
    const pid = n(p.pid);
    if (pid === null) return [];
    const indicators: Partial<Record<ImplantIndicator, number>> = {};
    for (const k of INDICATORS) {
      const v = n(p[k]);
      if (v) indicators[k] = v;
    }
    const has = (list: ImplantIndicator[]) => list.some((k) => (indicators[k] ?? 0) > 0);
    return [{
      pid,
      name: typeof p.name === 'string' && p.name.trim() ? p.name.trim().slice(0, 260) : '?',
      managed: p.is_managed === 1 || p.is_managed === true,
      indicators,
      severity: has(STRONG) ? 'high' : has(MODIFIED) ? 'medium' : 'low',
    } satisfies SuspiciousProcess];
  });
  const order = { high: 0, medium: 1, low: 2 } as const;
  suspicious.sort((a, b) => order[a.severity] - order[b.severity] || a.name.localeCompare(b.name));
  return { scanned: n(o.scanned_count), failed: n(o.failed_count), scanTimeMs: n(o.scan_time_ms), suspicious };
}
