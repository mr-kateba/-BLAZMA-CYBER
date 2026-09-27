import { describe, expect, it } from 'vitest';
import { parseHollowsSummary } from '../src/core/hollows';
import { HOLLOWS_ARGS } from '../src/main/services/memory-scan';

// Layout of HHScanReport::toJSON (hollows_hunter v0.4.1.1, hh_report.cpp), with the padding it prints.
const CLEAN = '{\n "scan_date_time" : "2026-09-27 18:00:00",\n "scan_timestamp" : 1790532000,\n "scan_time_ms" : 41234,\n "scanned_count" : 87,\n "failed_count" : 2,\n "suspicious_count" : 0\n}\n';
const DETECTED = `[*] Scan started\n{
 "scan_date_time" : "2026-09-27 18:00:00",
 "scan_timestamp" : 1790532000,
 "scan_time_ms" : 52000,
 "scanned_count" : 90,
 "failed_count" : 0,
 "suspicious_count" : 3,
 "suspicious" : [
  {
   "pid" : 4120,
   "is_managed" : 0,
   "name" : "svchost.exe",
   "replaced" : 1,
   "hdr_modified" : 1,
   "patched" : 0,
   "implanted_pe" : 0,
   "implanted_shc" : 0,
   "unreachable_file" : 0,
   "other" : 0
  },
  {
   "pid" : 900,
   "is_managed" : 1,
   "name" : "Game.exe",
   "replaced" : 0,
   "hdr_modified" : 0,
   "patched" : 12,
   "implanted_pe" : 0,
   "implanted_shc" : 0,
   "unreachable_file" : 0,
   "other" : 0
  },
  {
   "pid" : 77,
   "is_managed" : 0,
   "name" : "notepad.exe",
   "replaced" : 0,
   "hdr_modified" : 0,
   "patched" : 0,
   "implanted_pe" : 0,
   "implanted_shc" : 1,
   "unreachable_file" : 0,
   "other" : 0
  }
 ]
}
`;

describe('HollowsHunter summary', () => {
  it('clean scan', () => {
    expect(parseHollowsSummary(CLEAN)).toEqual({ scanned: 87, failed: 2, scanTimeMs: 41234, suspicious: [] });
  });

  it('suspicious processes with plain-language severity (hidden code first)', () => {
    const r = parseHollowsSummary(DETECTED)!;
    expect(r.scanned).toBe(90);
    expect(r.suspicious.map((p) => [p.name, p.severity])).toEqual([['notepad.exe', 'high'], ['svchost.exe', 'high'], ['Game.exe', 'medium']]);
    expect(r.suspicious.find((p) => p.pid === 4120)!.indicators).toEqual({ replaced: 1, hdr_modified: 1 });
    expect(r.suspicious.find((p) => p.pid === 900)).toMatchObject({ managed: true, indicators: { patched: 12 } });
  });

  it('anything else is a failure, never "clean"', () => {
    expect(parseHollowsSummary('')).toBeNull();
    expect(parseHollowsSummary('Access denied')).toBeNull();
    expect(parseHollowsSummary('{"hello": 1}')).toBeNull();
    expect(parseHollowsSummary('{ broken')).toBeNull();
  });

  it('never asks the engine to kill, suspend or dump', () => {
    expect(HOLLOWS_ARGS).toEqual(['/quiet', '/json', '/ofilter', '2']);
    expect(HOLLOWS_ARGS.join(' ')).not.toMatch(/kill|suspend|minidmp|dmode/);
  });
});
