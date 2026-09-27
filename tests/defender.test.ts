import { describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));

import { buildScanArgs, findMpCmdRun, parseThreats, platformVersionKey, __defenderScriptsForTest } from '../src/main/services/defender';
import { assertSafeScript } from '../src/main/services/powershell';

describe('Defender adapter', () => {
  it('picks the newest platform MpCmdRun, then falls back to Program Files', () => {
    const env = { BLAZMA_TEST_DEFENDER: '1', ProgramData: 'C:\\PD', ProgramFiles: 'C:\\PF' } as NodeJS.ProcessEnv;
    const list = () => ['4.18.2301.6-0', '4.18.24090.11-0', 'junk', '4.18.23110.3-0'] as never;
    const newest = join('C:\\PD', 'Microsoft', 'Windows Defender', 'Platform', '4.18.24090.11-0', 'MpCmdRun.exe');
    expect(findMpCmdRun(env, (p) => p === newest, list)).toBe(newest);
    const pf = join('C:\\PF', 'Windows Defender', 'MpCmdRun.exe');
    expect(findMpCmdRun(env, (p) => p === pf, list)).toBe(pf);
    expect(findMpCmdRun(env, () => false, list)).toBeNull();
    expect(platformVersionKey('4.18.24090.11-0')).toEqual([4, 18, 24090, 11, 0]);
  });

  it('parses threat names from MpCmdRun output', () => {
    const out = `Scan starting...\nScan finished.\nScanning C:\\t\\eicar.com found 1 threats.\n\n----------------------------- Threat information ------------------------------\nThreat                  : Virus:DOS/EICAR_Test_File\nResources               : 1 total\n    file                : C:\\t\\eicar.com\n`;
    expect(parseThreats(out)).toEqual(['Virus:DOS/EICAR_Test_File']);
    expect(parseThreats('Scan finished.\n')).toEqual([]);
  });

  it('builds argument arrays with the target as a single, unmodified argument', () => {
    const evil = 'C:\\x\\a" & calc.exe & ".txt';
    const args = buildScanArgs('path', evil);
    expect(args).toEqual(['-Scan', '-ScanType', '3', '-File', evil, '-DisableRemediation']);
    expect(buildScanArgs('quick')).toEqual(['-Scan', '-ScanType', '1']);
    expect(buildScanArgs('full')).toEqual(['-Scan', '-ScanType', '2']);
    expect(() => buildScanArgs('path')).toThrow();
  });

  it('threat history script is a safe fixed script', () => {
    expect(() => assertSafeScript(__defenderScriptsForTest.THREAT_HISTORY_SCRIPT)).not.toThrow();
    expect(__defenderScriptsForTest.THREAT_HISTORY_SCRIPT).toContain('ConvertTo-Json -InputObject');
  });
});
