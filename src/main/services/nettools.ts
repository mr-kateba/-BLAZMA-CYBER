// Network Toolkit — diagnostics for networks and systems you own or are authorized to test.
//
// Safety rules:
//  - Targets are validated (IP or hostname); tools receive them as separate argv elements or
//    BLAZMA_ARG_* env vars — never inside a command string.
//  - Anything aimed at a PUBLIC address goes through NetworkGate (blocked in Offline Mode, logged).
//  - Port checks are capped (<= 1024 ports, bounded concurrency, short timeouts).
//  - Device discovery only works on a private IPv4 subnet (<= /24) that is directly attached to
//    one of this computer's own interfaces.
//  - The renderer asks the user to confirm authorization before port checks and discovery.

import { execFile } from 'node:child_process';
import { lookup, Resolver } from 'node:dns/promises';
import { Socket } from 'node:net';
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import type {
  AdapterRow, DiscoveryResult, DnsLookupResult, NeighborRow, PingResult, PortCheckResult, PortResult, RouteRow, TaskProgress, TraceResult,
} from '../../shared/api';
import { NetworkGate } from '../../core/network-gate';
import { classifyIP, isHostname, isIP, isIPv4, parsePortList } from '../../core/validation';
import { networkOf, parsePingOutput, parseProcArp, parseProcRoute, subnetHosts, wellKnownService } from '../../core/netparse';
import { runPowerShellJson } from './powershell';
import { macInfo } from '../../core/oui';

function withMaker(mac: string | null) {
  const m = macInfo(mac);
  return m ? { kind: m.kind, vendor: m.vendor } : null;
}

export class NetToolsError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

type Progress = (p: Omit<TaskProgress, 'taskId'>) => void;
const isWin = () => process.platform === 'win32';

const PING_SCRIPT = `
$r = @(Test-Connection -ComputerName $env:BLAZMA_ARG_TARGET -Count ([int]$env:BLAZMA_ARG_COUNT) -ErrorAction SilentlyContinue | ForEach-Object {
  @{ rtt = [int]$_.ResponseTime; status = [int]$_.StatusCode }
})
ConvertTo-Json -InputObject $r -Compress
`;
const TRACE_SCRIPT = `
$t = Test-NetConnection -ComputerName $env:BLAZMA_ARG_TARGET -TraceRoute -Hops 30 -WarningAction SilentlyContinue -ErrorAction Stop
@{ hops = @($t.TraceRoute | ForEach-Object { [string]$_ }); ok = [bool]$t.PingSucceeded } | ConvertTo-Json -Compress
`;
const ADAPTERS_SCRIPT = `
$cfg = @{}
Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
  $cfg[[string]$_.InterfaceAlias] = @{
    gw = if ($_.IPv4DefaultGateway) { [string]$_.IPv4DefaultGateway.NextHop } else { $null }
    dns = @($_.DNSServer | ForEach-Object { $_.ServerAddresses } | ForEach-Object { [string]$_ })
  }
}
$rows = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
  $c = $cfg[[string]$_.Name]
  @{ name = [string]$_.Name; desc = [string]$_.InterfaceDescription; status = [string]$_.Status; mac = [string]$_.MacAddress; speed = [string]$_.LinkSpeed; gw = if ($c) { $c.gw } else { $null }; dns = if ($c) { $c.dns } else { @() } }
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
`;
const ROUTES_SCRIPT = `
$rows = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -notlike 'ff00::*' } | ForEach-Object {
  @{ dest = [string]$_.DestinationPrefix; gw = [string]$_.NextHop; iface = [string]$_.InterfaceAlias; metric = [int]$_.RouteMetric }
})
ConvertTo-Json -InputObject $rows -Compress
`;
const NEIGHBORS_SCRIPT = `
$rows = @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | ForEach-Object {
  @{ ip = [string]$_.IPAddress; mac = [string]$_.LinkLayerAddress; state = [string]$_.State; iface = [string]$_.InterfaceAlias }
})
ConvertTo-Json -InputObject $rows -Compress
`;
export const NET_SCRIPTS = { PING_SCRIPT, TRACE_SCRIPT, ADAPTERS_SCRIPT, ROUTES_SCRIPT, NEIGHBORS_SCRIPT };

/** Names that are clearly local-network names: resolving them is not an external lookup. */
export function isLocalName(name: string): boolean {
  const n = name.toLowerCase().replace(/\.$/, '');
  return !n.includes('.') || /\.(local|lan|home|internal|home\.arpa|localdomain)$/.test(n) || n === 'localhost';
}

function arr<T>(v: unknown): T[] {
  return v == null ? [] : Array.isArray(v) ? (v as T[]) : [v as T];
}

function runTool(cmd: string, args: string[], timeoutMs: number, signal?: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: timeoutMs, windowsHide: true, encoding: 'utf8', env: { ...process.env, LANG: 'C', LC_ALL: 'C' }, signal, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      if (err) {
        const e = err as NodeJS.ErrnoException & { killed?: boolean };
        if (e.name === 'AbortError') return reject(new NetToolsError('cancelled'));
        if (e.code === 'ENOENT') return reject(new NetToolsError('tool_not_installed'));
        if (e.killed) return reject(new NetToolsError('timeout'));
        // ping/traceroute exit non-zero on packet loss: output is still a valid result
        return resolve(stdout ?? '');
      }
      resolve(stdout);
    });
  });
}

/** TCP connect probe: open (connected), closed (refused), filtered (timeout/unreachable). */
export function tcpProbe(address: string, port: number, timeoutMs: number): Promise<{ state: PortResult['state']; latencyMs: number | null }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new Socket();
    let settled = false;
    const finish = (state: PortResult['state'], latency: number | null) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ state, latencyMs: latency });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish('open', Date.now() - start));
    sock.once('timeout', () => finish('filtered', null));
    sock.once('error', (e: NodeJS.ErrnoException) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered', e.code === 'ECONNREFUSED' ? Date.now() - start : null));
    sock.connect({ host: address, port });
  });
}

async function pool<T, R>(items: T[], size: number, signal: AbortSignal | undefined, fn: (x: T) => Promise<R>, onDone?: (n: number) => void): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  let done = 0;
  const workers = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) {
      if (signal?.aborted) throw new NetToolsError('cancelled');
      const i = next++;
      out[i] = await fn(items[i]!);
      onDone?.(++done);
    }
  });
  await Promise.all(workers);
  return out;
}

export class NetToolsService {
  private readonly resolver: Resolver;
  constructor(private readonly gate: NetworkGate, private readonly probe = tcpProbe) {
    this.resolver = new Resolver({ timeout: 4000, tries: 2 });
  }

  /** Validates and resolves a target. Public-name resolution is gated (it is a DNS query to your resolver). */
  async resolveTarget(raw: unknown): Promise<{ input: string; address: string; isPublic: boolean }> {
    if (typeof raw !== 'string') throw new NetToolsError('invalid_target');
    const input = raw.trim().toLowerCase();
    if (!input || input.length > 253 || !isHostname(input)) throw new NetToolsError('invalid_target');
    let address = input;
    if (!isIP(input)) {
      const doLookup = async () => {
        try {
          return (await lookup(input, { verbatim: true })).address;
        } catch {
          throw new NetToolsError('dns_not_found');
        }
      };
      address = isLocalName(input)
        ? await doLookup()
        : await this.gate.run({ module: 'networkToolkit', service: 'dns', host: 'system-resolver', dataKind: 'privacy.data.domain' }, doLookup);
    }
    return { input, address, isPublic: classifyIP(address) === 'public' };
  }

  /** Runs `fn` through the gate only when the target is public. */
  private guarded<T>(t: { address: string; isPublic: boolean }, service: string, fn: () => Promise<T>): Promise<T> {
    return t.isPublic ? this.gate.run({ module: 'networkToolkit', service, host: t.address, dataKind: 'privacy.data.ip_address' }, fn) : fn();
  }

  async ping(raw: unknown, countRaw: unknown, signal?: AbortSignal): Promise<PingResult> {
    const count = typeof countRaw === 'number' && Number.isInteger(countRaw) ? Math.min(Math.max(countRaw, 1), 20) : 4;
    const t = await this.resolveTarget(raw);
    return this.guarded(t, 'ping', async () => {
      let rtts: Array<number | null>;
      let received: number;
      if (isWin()) {
        const r = await runPowerShellJson<unknown>(PING_SCRIPT, { args: { TARGET: t.address, COUNT: String(count) }, timeoutMs: 15_000 + count * 2000 });
        if (!r.ok) throw new NetToolsError(r.error);
        const rows = arr<{ rtt: number; status: number }>(r.data);
        const ok = rows.filter((x) => x.status === 0);
        rtts = [...ok.map((x) => x.rtt), ...new Array(count - ok.length).fill(null)];
        received = ok.length;
      } else {
        const out = await runTool('ping', ['-n', '-c', String(count), '-W', '2', '--', t.address], 10_000 + count * 3000, signal);
        const p = parsePingOutput(out);
        rtts = [...p.rtts, ...new Array(Math.max(0, count - p.rtts.length)).fill(null)];
        received = p.received;
      }
      const ok = rtts.filter((x): x is number => x !== null);
      return {
        target: t.input,
        address: t.address,
        sent: count,
        received,
        rtts,
        min: ok.length ? Math.min(...ok) : null,
        avg: ok.length ? Math.round((ok.reduce((a, b) => a + b, 0) / ok.length) * 100) / 100 : null,
        max: ok.length ? Math.max(...ok) : null,
      };
    });
  }

  async traceroute(raw: unknown, signal?: AbortSignal): Promise<TraceResult> {
    const t = await this.resolveTarget(raw);
    return this.guarded(t, 'traceroute', async () => {
      if (isWin()) {
        const r = await runPowerShellJson<{ hops: unknown; ok: boolean }>(TRACE_SCRIPT, { args: { TARGET: t.address }, timeoutMs: 180_000 });
        if (!r.ok) throw new NetToolsError(r.error);
        const hops = arr<string>(r.data.hops).map((h, i) => ({ hop: i + 1, address: h && h !== '0.0.0.0' ? h : null, rttMs: null }));
        return { target: t.input, address: t.address, hops, reached: !!r.data.ok || hops.at(-1)?.address === t.address };
      }
      const out = await runTool('traceroute', ['-n', '-q', '1', '-w', '2', '-m', '30', '--', t.address], 120_000, signal);
      const hops = out
        .split('\n')
        .map((l) => /^\s*(\d+)\s+(\S+)(?:\s+([\d.]+)\s*ms)?/.exec(l))
        .filter((m): m is RegExpExecArray => !!m)
        .map((m) => ({ hop: Number(m[1]), address: m[2] === '*' ? null : m[2]!, rttMs: m[3] ? Number(m[3]) : null }));
      return { target: t.input, address: t.address, hops, reached: hops.at(-1)?.address === t.address };
    });
  }

  async dnsLookup(raw: unknown): Promise<DnsLookupResult> {
    if (typeof raw !== 'string') throw new NetToolsError('invalid_target');
    const name = raw.trim().toLowerCase().replace(/\.$/, '');
    if (!isHostname(name) || isIP(name)) throw new NetToolsError('invalid_target');
    const empty = (e: NodeJS.ErrnoException) => {
      if (['ENODATA', 'ENOTFOUND', 'ENOTIMP'].includes(String(e.code))) return [] as never[];
      throw new NetToolsError(e.code === 'ETIMEOUT' ? 'timeout' : 'dns_error');
    };
    const r = this.resolver;
    const run = async () => {
      const [a, aaaa, cname, mx, txt, ns] = await Promise.all([
        r.resolve4(name).catch(empty),
        r.resolve6(name).catch(empty),
        r.resolveCname(name).catch(empty),
        r.resolveMx(name).catch(empty),
        r.resolveTxt(name).catch(empty),
        r.resolveNs(name).catch(empty),
      ]);
      return {
        name,
        server: r.getServers()[0] ?? null,
        records: {
          A: a,
          AAAA: aaaa,
          CNAME: cname,
          MX: mx.sort((x, y) => x.priority - y.priority).map((m) => `${m.priority} ${m.exchange}`),
          TXT: txt.map((c) => c.join('')),
          NS: ns,
        },
      };
    };
    return isLocalName(name) ? run() : this.gate.run({ module: 'networkToolkit', service: 'dns', host: r.getServers()[0] ?? 'system-resolver', dataKind: 'privacy.data.domain' }, run);
  }

  async reverseLookup(raw: unknown): Promise<{ address: string; names: string[] }> {
    if (typeof raw !== 'string' || !isIP(raw.trim())) throw new NetToolsError('invalid_target');
    const address = raw.trim().toLowerCase();
    const run = async () => ({
      address,
      names: await this.resolver.reverse(address).catch((e: NodeJS.ErrnoException) => {
        if (['ENOTFOUND', 'ENODATA'].includes(String(e.code))) return [];
        throw new NetToolsError('dns_error');
      }),
    });
    return classifyIP(address) === 'public'
      ? this.gate.run({ module: 'networkToolkit', service: 'dns', host: this.resolver.getServers()[0] ?? 'system-resolver', dataKind: 'privacy.data.ip_address' }, run)
      : run();
  }

  async portCheck(raw: unknown, spec: unknown, signal: AbortSignal, progress?: Progress): Promise<PortCheckResult> {
    if (typeof spec !== 'string') throw new NetToolsError('invalid_ports');
    let ports: number[];
    try {
      ports = parsePortList(spec, 1024);
    } catch (e) {
      throw new NetToolsError((e as Error).message === 'too_many_ports' ? 'too_many_ports' : 'invalid_ports');
    }
    if (ports.length === 0) throw new NetToolsError('invalid_ports');
    const t = await this.resolveTarget(raw);
    const started = Date.now();
    return this.guarded(t, 'port-check', async () => {
      const results = await pool(ports, 64, signal, async (port) => {
        const r = await this.probe(t.address, port, 1500);
        return { port, state: r.state, service: wellKnownService(port), latencyMs: r.latencyMs };
      }, (n) => progress?.({ processedBytes: n, totalBytes: ports.length, stage: 'scanning' }));
      return { target: t.input, address: t.address, results, durationMs: Date.now() - started };
    });
  }

  /** Local IPv4 subnets eligible for discovery: private, <= /24, attached to this machine. */
  localSubnets(): Array<{ cidr: string; interface: string; address: string }> {
    const out: Array<{ cidr: string; interface: string; address: string }> = [];
    for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
      for (const a of addrs ?? []) {
        if (a.internal || a.family !== 'IPv4' || !isIPv4(a.address)) continue;
        const scope = classifyIP(a.address);
        if (scope !== 'private' && scope !== 'cgnat' && scope !== 'link-local') continue;
        let cidr = networkOf(a.address, a.netmask);
        // Wider networks are narrowed to the /24 around this machine (bounded discovery).
        if (Number(cidr.split('/')[1]) < 24) cidr = networkOf(a.address, '255.255.255.0');
        if (!out.some((x) => x.cidr === cidr)) out.push({ cidr, interface: name, address: a.address });
      }
    }
    return out;
  }

  async discover(cidr: unknown, signal: AbortSignal, progress?: Progress): Promise<DiscoveryResult> {
    const subnet = this.localSubnets().find((s) => s.cidr === cidr);
    if (!subnet) throw new NetToolsError('subnet_not_local');
    const hosts = subnetHosts(subnet.cidr).filter((h) => h !== subnet.address);
    const started = Date.now();
    const PORTS = [445, 80, 443, 22, 3389, 139, 8080, 53];
    const alive = await pool(hosts, 64, signal, async (h) => {
      for (const port of PORTS) {
        const r = await this.probe(h, port, 600);
        // Any answer — including "connection refused" — proves a host exists at this address.
        if (r.state !== 'filtered') return h;
      }
      return null;
    }, (n) => progress?.({ processedBytes: n, totalBytes: hosts.length, stage: 'scanning' }));
    const neigh = await this.neighbors().catch(() => [] as NeighborRow[]);
    const macOf = (ip: string) => neigh.find((x) => x.address === ip)?.mac ?? null;
    const found = new Set(alive.filter((x): x is string => !!x));
    // Hosts that answered ARP during probing but have every probed port filtered still exist.
    for (const n of neigh) if (n.mac && hosts.includes(n.address)) found.add(n.address);
    return {
      subnet: subnet.cidr,
      interface: subnet.interface,
      probed: hosts.length,
      alive: [...found]
        .sort((a, b) => Number(a.split('.')[3]) - Number(b.split('.')[3]))
        .map((address) => ({ address, mac: macOf(address), maker: withMaker(macOf(address)) })),
      durationMs: Date.now() - started,
    };
  }

  async adapters(): Promise<AdapterRow[]> {
    const ifs = os.networkInterfaces();
    const base = Object.entries(ifs).map(([name, addrs]) => ({
      name,
      description: null as string | null,
      status: (addrs ?? []).length ? 'Up' : null,
      mac: (addrs ?? []).find((a) => a.mac && a.mac !== '00:00:00:00:00:00')?.mac ?? null,
      speed: null as string | null,
      ipv4: (addrs ?? []).filter((a) => a.family === 'IPv4').map((a) => `${a.address}/${a.cidr?.split('/')[1] ?? ''}`),
      ipv6: (addrs ?? []).filter((a) => a.family === 'IPv6').map((a) => a.address),
      gateway: null as string | null,
      dns: [] as string[],
      internal: (addrs ?? []).every((a) => a.internal),
    }));
    if (!isWin()) {
      const routes = await this.routes().catch(() => []);
      for (const b of base) b.gateway = routes.find((r) => r.interface === b.name && r.destination === '0.0.0.0/0')?.gateway ?? null;
      const dns = await readFile('/etc/resolv.conf', 'utf8').then((t) => [...t.matchAll(/^nameserver\s+(\S+)/gm)].map((m) => m[1]!)).catch(() => []);
      for (const b of base) if (!b.internal) b.dns = dns;
      return base;
    }
    const r = await runPowerShellJson<unknown>(ADAPTERS_SCRIPT, { timeoutMs: 30_000 });
    if (!r.ok) return base;
    const win = arr<Record<string, unknown>>(r.data);
    const merged = win.map((w) => {
      const b = base.find((x) => x.name === w.name);
      return {
        name: String(w.name ?? '?'),
        description: typeof w.desc === 'string' ? w.desc : null,
        status: typeof w.status === 'string' ? w.status : null,
        mac: typeof w.mac === 'string' && w.mac ? w.mac.replace(/-/g, ':').toLowerCase() : b?.mac ?? null,
        speed: typeof w.speed === 'string' ? w.speed : null,
        ipv4: b?.ipv4 ?? [],
        ipv6: b?.ipv6 ?? [],
        gateway: typeof w.gw === 'string' && w.gw ? w.gw : null,
        dns: arr<string>(w.dns).map(String),
        internal: false,
      };
    });
    return [...merged, ...base.filter((b) => b.internal)];
  }

  async routes(): Promise<RouteRow[]> {
    if (!isWin()) return parseProcRoute(await readFile('/proc/net/route', 'utf8').catch(() => ''));
    const r = await runPowerShellJson<unknown>(ROUTES_SCRIPT, { timeoutMs: 30_000 });
    if (!r.ok) throw new NetToolsError(r.error);
    return arr<Record<string, unknown>>(r.data).map((x) => ({
      destination: String(x.dest ?? ''),
      gateway: typeof x.gw === 'string' && !/^(0\.0\.0\.0|::)$/.test(x.gw) ? x.gw : null,
      interface: typeof x.iface === 'string' ? x.iface : null,
      metric: typeof x.metric === 'number' ? x.metric : null,
    }));
  }

  async neighbors(): Promise<NeighborRow[]> {
    if (!isWin()) return parseProcArp(await readFile('/proc/net/arp', 'utf8').catch(() => '')).map((n) => ({ ...n, maker: withMaker(n.mac) }));
    const r = await runPowerShellJson<unknown>(NEIGHBORS_SCRIPT, { timeoutMs: 30_000 });
    if (!r.ok) throw new NetToolsError(r.error);
    return arr<Record<string, unknown>>(r.data).map((x) => {
      const mac = typeof x.mac === 'string' ? x.mac.replace(/-/g, ':').toLowerCase() : null;
      return {
        address: String(x.ip ?? ''),
        mac,
        maker: withMaker(mac),
        state: typeof x.state === 'string' ? x.state : null,
        interface: typeof x.iface === 'string' ? x.iface : null,
      };
    });
  }
}
