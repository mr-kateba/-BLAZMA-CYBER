import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { NMAP_PROFILES, nmapFindings, nmapProgress, nmapTargetAllowed, parseNmapXml } from '../src/core/nmap';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));
const { findNmap, parseNmapRequest, runNmap, NmapError } = await import('../src/main/services/nmap');

const fixture = (name: string) => readFileSync(join(__dirname, 'fixtures', 'nmap', name), 'utf8');

describe('nmap XML', () => {
  it('reads a real Nmap 7.94 result (service, product, version, cpe, closed port)', () => {
    const run = parseNmapXml(fixture('local.xml'));
    expect(run).toMatchObject({ version: '7.94SVN', hostsUp: 1, hostsDown: 0 });
    expect(run.startedAt).toBe(new Date(1790551762 * 1000).toISOString());
    expect(run.finishedAt).toBe(new Date(1790551768 * 1000).toISOString());
    expect(run.hosts).toHaveLength(1);
    const h = run.hosts[0]!;
    expect(h).toMatchObject({ address: '127.0.0.1', mac: null, vendor: null, hostnames: [], state: 'up' });
    expect(h.ports.map((p) => [p.port, p.state, p.service])).toEqual([[18021, 'open', 'tcpwrapped'], [18080, 'open', 'http'], [18099, 'closed', null]]);
    expect(h.ports[1]).toMatchObject({ product: 'SimpleHTTPServer', version: '0.6', extra: 'Python 3.11.15', cpe: ['cpe:/a:python:simplehttpserver:0.6'] });
  });

  it('reads MAC, manufacturer, names and sorts hosts by address', () => {
    const run = parseNmapXml(fixture('lan.xml'));
    expect(run).toMatchObject({ hostsUp: 2, hostsDown: 253 });
    expect(run.hosts.map((h) => h.address)).toEqual(['192.168.1.1', '192.168.1.20', '192.168.1.99']);
    expect(run.hosts[0]).toMatchObject({ mac: '00:11:22:33:44:55', vendor: 'Cimsys & Co' });
    expect(run.hosts[1]).toMatchObject({ mac: '3C:2E:FF:11:22:33', vendor: null, hostnames: ['nas.lan'] });
    expect(run.hosts[1]!.ports.map((p) => p.port)).toEqual([23, 445, 6379]);
    expect(run.hosts[2]!.state).toBe('down');
  });

  it('never throws on garbage and reports progress lines', () => {
    expect(parseNmapXml('not xml at all')).toEqual({ version: null, startedAt: null, finishedAt: null, hostsUp: 0, hostsDown: 0, hosts: [] });
    expect(parseNmapXml('<host><address addr="1.2.3.4" addrtype="ipv4"/>')).toMatchObject({ hosts: [] });
    expect(nmapProgress('Connect Scan Timing: About 42.50% done; ETC: 23:30 (0:00:05 remaining)')).toBe(42.5);
    expect(nmapProgress('Nmap scan report for 192.168.1.1')).toBeNull();
  });
});

describe('service findings', () => {
  it('flags open risky services only, most severe first', () => {
    const f = nmapFindings(parseNmapXml(fixture('lan.xml')));
    expect(f.map((x) => `${x.severity}:${x.risk}:${x.host}:${x.port}`)).toEqual([
      'high:cleartext_remote:192.168.1.20:23',
      'high:database:192.168.1.20:6379',
      'low:file_sharing:192.168.1.20:445',
    ]);
    // A filtered RDP port is not an open service.
    expect(f.some((x) => x.port === 3389)).toBe(false);
    expect(nmapFindings(parseNmapXml(fixture('local.xml')))).toEqual([]);
  });
});

describe('what Blazma lets Nmap scan', () => {
  const attached = ['192.168.1.0/24'];

  it('allows only local addresses and attached /24 networks', () => {
    for (const ok of ['192.168.1.20', '10.0.0.5', '172.16.3.4', '169.254.1.1', '127.0.0.1', '100.64.0.1', '192.168.1.0/24']) expect(nmapTargetAllowed(ok, attached)).toBe(true);
    for (const bad of ['8.8.8.8', '1.1.1.1', '10.0.0.0/8', '192.168.2.0/24', 'example.com', '192.168.1.1-254', '-oX', '192.168.1.1 8.8.8.8', '']) expect(nmapTargetAllowed(bad, attached)).toBe(false);
  });

  it('validates the whole request and requires authorization', () => {
    expect(parseNmapRequest(' 192.168.1.20 ', 'quick', true, attached)).toEqual({ target: '192.168.1.20', profile: 'quick' });
    const code = (fn: () => unknown) => {
      try {
        fn();
        return null;
      } catch (e) {
        return e instanceof NmapError ? e.code : 'other';
      }
    };
    expect(code(() => parseNmapRequest('192.168.1.20', 'quick', false, attached))).toBe('authorization_required');
    expect(code(() => parseNmapRequest('192.168.1.20', '-sU', true, attached))).toBe('invalid_input');
    expect(code(() => parseNmapRequest(42, 'quick', true, attached))).toBe('invalid_target');
    expect(code(() => parseNmapRequest('45.33.32.156', 'quick', true, attached))).toBe('nmap_target_not_local');
  });

  it('uses fixed, unprivileged profiles without scripts', () => {
    for (const args of Object.values(NMAP_PROFILES)) {
      expect(args).toContain('-n');
      expect(args.join(' ')).not.toMatch(/--script|-sC|-sS|-sU|-O\b|-A\b|--privileged/);
    }
    expect(NMAP_PROFILES.quick).toContain('-sT');
    expect(NMAP_PROFILES.standard).toContain('-sT');
  });
});

// Real engine: runs only where Nmap is installed (it is not bundled). Scans a localhost server only.
const nmap = findNmap();
describe.skipIf(!nmap)('real nmap against localhost', () => {
  let server: Server;
  let port = 0;
  beforeAll(async () => {
    server = createServer((s) => {
      s.on('error', () => {});
      s.write('SSH-2.0-OpenSSH_9.6\r\n');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as { port: number }).port;
  });
  afterAll(() => server.close());

  it('reports the version and finds the listening port', async () => {
    const run$ = promisify(execFile);
    expect((await run$(nmap!, ['--version'])).stdout).toMatch(/Nmap version/);
    // The quick profile's arguments, narrowed to the one test port for speed (async: the server must keep answering).
    const xml = (await run$(nmap!, ['-sT', '-T4', '-n', '-p', String(port), '-sV', '--version-light', '--open', '-oX', '-', '127.0.0.1'])).stdout;
    const run = parseNmapXml(xml);
    expect(run.hosts[0]?.ports.find((p) => p.port === port)).toMatchObject({ state: 'open', service: 'ssh', product: 'OpenSSH', version: '9.6' });
  }, 60_000);

  it('runs a fixed profile end-to-end and honours cancel', async () => {
    const r = await runNmap('127.0.0.1', 'hosts', new AbortController().signal);
    expect(r).toMatchObject({ target: '127.0.0.1', profile: 'hosts', findings: [] });
    expect(r.run.hosts[0]).toMatchObject({ address: '127.0.0.1', state: 'up' });
    const ac = new AbortController();
    ac.abort();
    await expect(runNmap('127.0.0.1', 'standard', ac.signal)).rejects.toMatchObject({ code: 'cancelled' });
  }, 60_000);
});
