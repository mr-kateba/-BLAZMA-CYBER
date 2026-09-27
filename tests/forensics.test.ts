import { describe, expect, it, vi } from 'vitest';
import { tmpdir } from 'node:os';
import { createServer, type Server } from 'node:net';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));

import { SCRIPTS, EVENT_LOGS, connections, events, processes, signatures } from '../src/main/services/forensics';
import { NET_SCRIPTS, NetToolsService, isLocalName, tcpProbe } from '../src/main/services/nettools';
import { NetworkGate, OfflineModeError, type NetworkActivityEntry } from '../src/core/network-gate';
import { assertSafeScript } from '../src/main/services/powershell';

describe('forensics scripts are fixed, read-only and injection-safe', () => {
  const all = { ...SCRIPTS, ...NET_SCRIPTS };
  it('contain no double quotes and no interpolation leftovers', () => {
    for (const [name, s] of Object.entries(all)) {
      expect(() => assertSafeScript(s), name).not.toThrow();
      expect(s, name).not.toMatch(/\$\{/);
    }
  });
  it('only query — no cmdlets that change system state', () => {
    const writes = /\b(Set-|Remove-|New-|Stop-|Start-Process|Restart-|Disable-|Enable-|Invoke-Expression|Add-MpPreference|Set-MpPreference|Uninstall-|Register-|Unregister-)/i;
    for (const [name, s] of Object.entries(all)) expect(s, name).not.toMatch(writes);
  });
  it('take parameters from environment variables only', () => {
    expect(SCRIPTS.events).toContain('$env:BLAZMA_ARG_LOG');
    expect(SCRIPTS.signatures).toContain('$env:BLAZMA_ARG_LIST');
    expect(NET_SCRIPTS.PING_SCRIPT).toContain('$env:BLAZMA_ARG_TARGET');
  });
  it('registry paths reach PowerShell with single backslashes', () => {
    expect(SCRIPTS.software).toContain("'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'");
    expect(SCRIPTS.usb).toContain("'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR'");
    expect(SCRIPTS.users).toContain("Split('\\')");
    // Local Administrators group by well-known SID (works on localized Windows, e.g. Arabic)
    expect(SCRIPTS.users).toContain('S-1-5-32-544');
  });
  it('validates event log names against an allow-list', async () => {
    await expect(events('System; Remove-Item C:\\', [2], 10)).rejects.toMatchObject({ code: 'invalid_input' });
    expect(EVENT_LOGS).toContain('Security');
  });
  it('rejects bad signature path lists before touching PowerShell', async () => {
    await expect(signatures('C:\\x.exe')).rejects.toMatchObject({ code: 'invalid_input' });
  });
});

describe.skipIf(process.platform !== 'linux')('Linux /proc collectors (real system)', () => {
  it('lists real processes including this test runner', async () => {
    const r = await processes();
    expect(r.source).toBe('procfs');
    expect(r.rows.length).toBeGreaterThan(3);
    const me = r.rows.find((p) => p.pid === process.pid)!;
    expect(me).toBeTruthy();
    expect(me.ppid).toBe(process.ppid);
    expect(me.path).toBe(process.execPath);
  });
  it('lists real sockets and attributes our own listener to our PID', async () => {
    const srv: Server = createServer();
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const port = (srv.address() as { port: number }).port;
    try {
      const r = await connections();
      const mine = r.rows.find((c) => c.localPort === port && c.state === 'LISTEN');
      expect(mine).toMatchObject({ protocol: 'TCP', localAddress: '127.0.0.1', pid: process.pid });
    } finally {
      srv.close();
    }
  });
});

describe('Network Toolkit', () => {
  const offlineGate = () => {
    const log: NetworkActivityEntry[] = [];
    return { gate: new NetworkGate(() => true, (e) => log.push(e)), log };
  };

  it('classifies local names', () => {
    expect(isLocalName('nas')).toBe(true);
    expect(isLocalName('printer.local')).toBe(true);
    expect(isLocalName('router.home.arpa')).toBe(true);
    expect(isLocalName('example.com')).toBe(false);
  });

  it('rejects invalid targets and port specs (no injection surface)', async () => {
    const svc = new NetToolsService(offlineGate().gate);
    await expect(svc.resolveTarget('8.8.8.8; calc')).rejects.toMatchObject({ code: 'invalid_target' });
    await expect(svc.resolveTarget('-oProxyCommand=x')).rejects.toMatchObject({ code: 'invalid_target' });
    const s = new AbortController().signal;
    await expect(svc.portCheck('127.0.0.1', '1-70000', s)).rejects.toMatchObject({ code: 'invalid_ports' });
    await expect(svc.portCheck('127.0.0.1', '1-5000', s)).rejects.toMatchObject({ code: 'too_many_ports' });
  });

  it('checks ports on localhost: open vs closed (real TCP)', async () => {
    const srv: Server = createServer((c) => c.end());
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const open = (srv.address() as { port: number }).port;
    const closedSrv: Server = createServer();
    await new Promise<void>((r) => closedSrv.listen(0, '127.0.0.1', r));
    const closed = (closedSrv.address() as { port: number }).port;
    await new Promise<void>((r) => closedSrv.close(() => r()));
    try {
      const { gate, log } = offlineGate();
      // Localhost is not external: works even in Offline Mode and is not logged as external activity.
      const r = await new NetToolsService(gate).portCheck('127.0.0.1', `${open},${closed}`, new AbortController().signal);
      expect(r.results.find((x) => x.port === open)!.state).toBe('open');
      expect(r.results.find((x) => x.port === closed)!.state).toBe('closed');
      expect(log).toHaveLength(0);
    } finally {
      srv.close();
    }
  });

  it('public targets go through the gate (blocked in Offline Mode, logged)', async () => {
    const { gate, log } = offlineGate();
    const probe = vi.fn(tcpProbe);
    const svc = new NetToolsService(gate, probe);
    await expect(svc.portCheck('8.8.8.8', '53', new AbortController().signal)).rejects.toBeInstanceOf(OfflineModeError);
    expect(probe).not.toHaveBeenCalled();
    expect(log[0]).toMatchObject({ module: 'networkToolkit', service: 'port-check', host: '8.8.8.8', outcome: 'blocked_offline' });
  });

  it('discovery refuses subnets that are not attached to this machine', async () => {
    const svc = new NetToolsService(offlineGate().gate);
    await expect(svc.discover('203.0.113.0/24', new AbortController().signal)).rejects.toMatchObject({ code: 'subnet_not_local' });
    await expect(svc.discover('10.0.0.0/8', new AbortController().signal)).rejects.toMatchObject({ code: 'subnet_not_local' });
    for (const s of svc.localSubnets()) expect(Number(s.cidr.split('/')[1])).toBeGreaterThanOrEqual(24);
  });

  it('discovery counts "connection refused" as a live host', async () => {
    const svc = new NetToolsService(offlineGate().gate, async (h, port) => (h.endsWith('.10') && port === 445 ? { state: 'closed', latencyMs: 1 } : { state: 'filtered', latencyMs: null }));
    const subnet = svc.localSubnets()[0];
    if (!subnet) return; // no private interface in this environment
    const r = await svc.discover(subnet.cidr, new AbortController().signal);
    expect(r.alive.map((a) => a.address)).toContain(subnet.cidr.split('.').slice(0, 3).join('.') + '.10');
  }, 30_000); // Windows: the neighbor table comes from a PowerShell process (slow cold start)

  it('reports missing tools honestly (no ping in this environment → tool_not_installed)', async () => {
    if (process.platform === 'win32') return;
    const svc = new NetToolsService(offlineGate().gate);
    try {
      const r = await svc.ping('127.0.0.1', 1, new AbortController().signal);
      expect(r.sent).toBe(1); // ping exists: it must return a real result
    } catch (e) {
      expect((e as { code?: string }).code).toBe('tool_not_installed');
    }
  });

  it('routes and neighbors come from the real system on Linux', async () => {
    if (process.platform !== 'linux') return;
    const svc = new NetToolsService(offlineGate().gate);
    expect(Array.isArray(await svc.routes())).toBe(true);
    const ad = await svc.adapters();
    expect(ad.some((a) => a.internal)).toBe(true);
  });
});
