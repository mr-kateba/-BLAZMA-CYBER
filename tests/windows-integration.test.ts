// Real-Windows integration tests: run the actual PowerShell scripts, MpCmdRun and Authenticode
// checks on a Windows machine (CI: GitHub Actions windows-latest). Skipped on other platforms.
// Targets are local only (localhost, system files, temp files); nothing external is contacted.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { __resetWindowsFactsCache, getWindowsFacts, verifySignature } from '../src/main/services/windows-security';
import * as forensics from '../src/main/services/forensics';
import { findMpCmdRun, getThreatHistory, runDefenderScan } from '../src/main/services/defender';
import { NetToolsService } from '../src/main/services/nettools';
import { NetworkGate } from '../src/core/network-gate';

const WIN = process.platform === 'win32';
const SYS = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');

describe.runIf(WIN)('Windows integration (real PowerShell / Defender / Authenticode)', () => {
  let work: string;
  beforeAll(() => {
    work = mkdtempSync(join(tmpdir(), 'blazma-win-'));
    __resetWindowsFactsCache();
  });
  afterAll(() => rmSync(work, { recursive: true, force: true }));

  it('system facts and security status come from real queries', async () => {
    const f = await getWindowsFacts();
    expect(f.security.platformSupported).toBe(true);
    expect(f.osCaption).toMatch(/Windows/);
    expect(f.osBuild).toMatch(/^\d+$/);
    expect(f.physicalCores).toBeGreaterThan(0);
    expect(f.processCount).toBeGreaterThan(0);
    expect(f.security.firewall).toMatchObject({ available: true });
    // Defender may be absent/disabled on some machines; then the reason must be the honest one.
    if (!f.security.defender.available) expect(f.security.defender).toMatchObject({ reason: 'defender_unavailable' });
    console.log('Windows facts:', JSON.stringify({ os: f.osCaption, build: f.osBuild, defender: f.security.defender }));
  }, 60_000);

  it('Authenticode: a Windows binary is signed, an unsigned script is not', async () => {
    const signed = await verifySignature(join(SYS, 'notepad.exe'));
    expect(signed).toMatchObject({ checked: true, status: 'valid' });
    expect(signed.publisher).toMatch(/Microsoft/);

    // Hostile file name: spaces, Arabic, quotes and PowerShell sub-expression syntax. It reaches the
    // script only via an environment variable, so it must be treated as a literal path.
    const odd = join(work, "تجربة $(Write-Output pwned) 'x' ;.ps1");
    writeFileSync(odd, 'Write-Output hello\r\n');
    const unsigned = await verifySignature(odd);
    expect(unsigned).toMatchObject({ checked: true, status: 'not_signed' });
  }, 60_000);

  it('forensics collectors return real rows via PowerShell', async () => {
    const procs = await forensics.processes();
    expect(procs.source).toBe('powershell');
    expect(procs.rows.length).toBeGreaterThan(5);
    for (const [name, fn] of Object.entries({
      connections: forensics.connections, services: forensics.services, drivers: forensics.drivers, startup: forensics.startup,
      tasks: forensics.tasks, users: forensics.users, software: forensics.software, usb: forensics.usb,
    })) {
      const r = await fn();
      expect(Array.isArray(r.rows), name).toBe(true);
      console.log(`forensics.${name}: ${r.rows.length} rows${r.partial ? ` (partial: ${r.partial})` : ''}`);
    }
    expect((await forensics.services()).rows.length).toBeGreaterThan(10);
    expect((await forensics.users()).rows.length).toBeGreaterThan(0);
    const ev = await forensics.events('System', [1, 2, 3, 4], 20);
    expect(ev.rows.length).toBeGreaterThan(0);
  }, 300_000);

  it('network toolkit: adapters, routes and localhost ping (Offline Mode on — nothing external)', async () => {
    const svc = new NetToolsService(new NetworkGate(() => true, () => {}));
    expect((await svc.adapters()).length).toBeGreaterThan(0);
    expect((await svc.routes()).length).toBeGreaterThan(0);
    expect(Array.isArray(await svc.neighbors())).toBe(true);
    const p = await svc.ping('127.0.0.1', 2);
    expect(p.received).toBeGreaterThan(0);
  }, 120_000);

  it('Defender: MpCmdRun detects the EICAR test file in a report-only scan', async (ctx) => {
    const facts = await getWindowsFacts();
    const d = facts.security.defender;
    if (!d.available || d.antivirusEnabled !== 'on') ctx.skip();
    expect(findMpCmdRun()).toBeTruthy();
    await expect(getThreatHistory()).resolves.toBeInstanceOf(Array);

    const file = join(work, 'eicar.com');
    try {
      // EICAR assembled at runtime from two halves: never stored contiguously in source.
      writeFileSync(file, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    } catch {
      console.log('Real-time protection blocked writing the EICAR file (detected on write).');
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
    if (!existsSync(file)) {
      console.log('Real-time protection removed the EICAR file (detected on write).');
      return;
    }
    const r = await runDefenderScan('path', file, new AbortController().signal);
    expect(r.status).toBe('threats_found');
    expect(r.threats.join(' ')).toMatch(/EICAR/i);
  }, 300_000);
});
