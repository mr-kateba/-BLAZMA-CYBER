// Nmap (user-installed) — scan profiles, target rules, XML parsing and service findings (pure).
//
// Blazma runs Nmap only with FIXED argument lists (no scripts, no custom flags from the user) and
// only against addresses on the user's own networks: a private / link-local / loopback address, or
// the /24 the computer is attached to. Connect scans (-sT) need no administrator rights or Npcap.

import { classifyIP, isIPv4 } from './validation';

export type NmapProfile = 'hosts' | 'quick' | 'standard';

/** Fixed arguments per profile. The target and output file are appended by the caller. */
export const NMAP_PROFILES: Record<NmapProfile, string[]> = {
  // Who is on the network (no port scan).
  hosts: ['-sn', '-T4', '-n'],
  // The 100 most common ports, with a light service/version probe.
  quick: ['-sT', '-T4', '-n', '--top-ports', '100', '-sV', '--version-light', '--open'],
  // The 1,000 most common ports with standard version detection.
  standard: ['-sT', '-T4', '-n', '--top-ports', '1000', '-sV', '--open'],
};

/** Accepts a single local address, or a /24 CIDR the caller has confirmed is attached. */
export function nmapTargetAllowed(target: string, attachedCidrs: string[]): boolean {
  if (isIPv4(target)) {
    const scope = classifyIP(target);
    return scope === 'private' || scope === 'link-local' || scope === 'loopback' || scope === 'cgnat';
  }
  return attachedCidrs.includes(target);
}

// --------------------------------------------------------------------------------- XML parsing

export interface NmapPort {
  protocol: string;
  port: number;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  extra: string | null;
  cpe: string[];
}

export interface NmapHost {
  address: string;
  mac: string | null;
  /** Manufacturer as Nmap reports it (only on the local segment). */
  vendor: string | null;
  hostnames: string[];
  state: string;
  ports: NmapPort[];
}

export interface NmapRun {
  version: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  hostsUp: number;
  hostsDown: number;
  hosts: NmapHost[];
}

function decode(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#45;/g, '-').replace(/&amp;/g, '&');
}

function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(/([\w:-]+)="([^"]*)"/g)) out[m[1]!] = decode(m[2]!);
  return out;
}

const iso = (epoch: string | undefined) => (epoch && /^\d+$/.test(epoch) ? new Date(Number(epoch) * 1000).toISOString() : null);
const nn = (v: string | undefined) => (v && v.trim() ? v.trim().slice(0, 200) : null);

export function parseNmapXml(xml: string): NmapRun {
  const run = attrs(/<nmaprun\b[^>]*>/.exec(xml)?.[0] ?? '');
  const finished = attrs(/<finished\b[^>]*>/.exec(xml)?.[0] ?? '');
  const hostsTag = attrs(/<hosts\b[^>]*>/.exec(xml)?.[0] ?? '');
  const hosts: NmapHost[] = [];
  for (const m of xml.matchAll(/<host\b[^>]*>([\s\S]*?)<\/host>/g)) {
    const body = m[1]!;
    let address: string | null = null;
    let mac: string | null = null;
    let vendor: string | null = null;
    for (const a of body.matchAll(/<address\b[^>]*\/>/g)) {
      const at = attrs(a[0]);
      if (at.addrtype === 'ipv4' || at.addrtype === 'ipv6') address ??= at.addr ?? null;
      if (at.addrtype === 'mac') {
        mac = at.addr ?? null;
        vendor = nn(at.vendor);
      }
    }
    if (!address) continue;
    const ports: NmapPort[] = [];
    for (const p of body.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
      const pa = attrs(p[1]!);
      const st = attrs(/<state\b[^>]*>/.exec(p[2]!)?.[0] ?? '');
      const sv = attrs(/<service\b[^>]*>/.exec(p[2]!)?.[0] ?? '');
      ports.push({
        protocol: pa.protocol ?? 'tcp',
        port: Number(pa.portid),
        state: st.state ?? 'unknown',
        service: nn(sv.name),
        product: nn(sv.product),
        version: nn(sv.version),
        extra: nn(sv.extrainfo),
        cpe: [...p[2]!.matchAll(/<cpe>([^<]+)<\/cpe>/g)].map((c) => decode(c[1]!)).slice(0, 5),
      });
    }
    hosts.push({
      address,
      mac,
      vendor,
      hostnames: [...body.matchAll(/<hostname\b[^>]*\/>/g)].map((h) => attrs(h[0]).name).filter((x): x is string => !!x),
      state: attrs(/<status\b[^>]*>/.exec(body)?.[0] ?? '').state ?? 'unknown',
      ports: ports.filter((p) => Number.isInteger(p.port)).sort((a, b) => a.port - b.port),
    });
  }
  return {
    version: nn(run.version),
    startedAt: iso(run.start),
    finishedAt: iso(finished.time),
    hostsUp: Number(hostsTag.up ?? hosts.filter((h) => h.state === 'up').length) || 0,
    hostsDown: Number(hostsTag.down ?? 0) || 0,
    hosts: hosts.sort((a, b) => ipSortKey(a.address) - ipSortKey(b.address)),
  };
}

function ipSortKey(ip: string): number {
  return isIPv4(ip) ? ip.split('.').reduce((n, o) => n * 256 + Number(o), 0) : Number.MAX_SAFE_INTEGER;
}

/** Progress lines Nmap prints with --stats-every: "… About 42.50% done …". */
export function nmapProgress(line: string): number | null {
  const m = /About (\d+(?:\.\d+)?)% done/.exec(line);
  return m ? Math.min(100, Number(m[1])) : null;
}

// ---------------------------------------------------------------------------------- findings

export type ServiceRisk = 'cleartext_remote' | 'remote_desktop' | 'file_sharing' | 'database' | 'remote_admin' | 'camera_stream' | 'docker_api';

export interface NmapFinding {
  risk: ServiceRisk;
  severity: 'high' | 'medium' | 'low';
  host: string;
  port: number;
  service: string;
}

const RISKS: Array<{ risk: ServiceRisk; severity: NmapFinding['severity']; ports: number[]; names: RegExp }> = [
  { risk: 'cleartext_remote', severity: 'high', ports: [23], names: /^telnet$/ },
  { risk: 'cleartext_remote', severity: 'medium', ports: [21], names: /^ftp$/ },
  { risk: 'docker_api', severity: 'high', ports: [2375], names: /^docker$/ },
  { risk: 'database', severity: 'high', ports: [3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 5984], names: /^(mysql|postgresql|ms-sql-s|oracle(-tns)?|mongod(b)?|redis|elasticsearch|memcache(d)?|couchdb)$/ },
  { risk: 'remote_admin', severity: 'high', ports: [5900, 5901, 5902], names: /^vnc/ },
  { risk: 'remote_desktop', severity: 'medium', ports: [3389], names: /^ms-wbt-server$/ },
  { risk: 'file_sharing', severity: 'low', ports: [445, 139], names: /^(microsoft-ds|netbios-ssn)$/ },
  { risk: 'camera_stream', severity: 'low', ports: [554], names: /^rtsp$/ },
];

/** Open services worth a look on a home or office network, with the reason as an id. */
export function nmapFindings(run: NmapRun): NmapFinding[] {
  const out: NmapFinding[] = [];
  for (const h of run.hosts) {
    for (const p of h.ports) {
      if (p.state !== 'open') continue;
      const rule = RISKS.find((r) => (p.service && r.names.test(p.service)) || r.ports.includes(p.port));
      if (rule) out.push({ risk: rule.risk, severity: rule.severity, host: h.address, port: p.port, service: p.service ?? String(p.port) });
    }
  }
  const order = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}
