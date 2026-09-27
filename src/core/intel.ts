// Pure parsers for intelligence sources. No network here: the main process fetches through
// NetworkGate and hands raw payloads to these functions, which makes them fully unit-testable.
//
// Formats:
//  - RDAP (RFC 9083) for IP networks and domains, IANA RDAP bootstrap (RFC 9224)
//  - Team Cymru IP-to-ASN DNS TXT responses
//  - VirusTotal v3, AbuseIPDB v2, Shodan host, ipinfo.io JSON, Tor bulk exit list

import type { AsnInfo, DomainRdap, GeoInfo, IpRdap, ReputationResult } from '../shared/api';
import { isIPv4, isIPv6 } from './validation';

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

// ---------------------------------------------------------------- IP address math

export function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
}

/** Expands an IPv6 address to 8 groups (handles ::, embedded IPv4). */
export function expandIPv6(ip: string): number[] {
  let s = ip.toLowerCase();
  if (s.includes('.')) {
    const last = s.lastIndexOf(':');
    const v4 = s.slice(last + 1).split('.').map(Number) as [number, number, number, number];
    s = `${s.slice(0, last)}:${((v4[0] << 8) | v4[1]).toString(16)}:${((v4[2] << 8) | v4[3]).toString(16)}`;
  }
  const [head, tail] = s.split('::') as [string, string | undefined];
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail !== undefined ? new Array(8 - h.length - t.length).fill('0') : [];
  return [...h, ...fill, ...t].map((g) => Number.parseInt(g || '0', 16));
}

function ipv6ToBigInt(ip: string): bigint {
  return expandIPv6(ip).reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

/** True when `ip` is inside `cidr` (same family only). */
export function cidrContains(cidr: string, ip: string): boolean {
  const [base, lenStr] = cidr.split('/');
  if (!base || lenStr === undefined) return false;
  const len = Number(lenStr);
  if (isIPv4(ip) && isIPv4(base)) {
    if (len === 0) return true;
    const mask = len === 32 ? 0xffffffff : (~((1 << (32 - len)) - 1)) >>> 0;
    return ((ipv4ToInt(ip) & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0);
  }
  if (isIPv6(ip) && isIPv6(base)) {
    if (len === 0) return true;
    const shift = BigInt(128 - len);
    return ipv6ToBigInt(ip) >> shift === ipv6ToBigInt(base) >> shift;
  }
  return false;
}

// ---------------------------------------------------------------- RDAP bootstrap (RFC 9224)

/** Finds the RDAP base URL for an IP (longest matching prefix) in an IANA ipv4/ipv6 bootstrap file. */
export function rdapBaseForIp(bootstrap: unknown, ip: string): string | null {
  let best: { len: number; url: string } | null = null;
  for (const svc of arr(obj(bootstrap).services)) {
    const [prefixes, urls] = arr(svc) as [unknown, unknown];
    const url = arr(urls).map(String).find((u) => u.startsWith('https://'));
    if (!url) continue;
    for (const p of arr(prefixes).map(String)) {
      const len = Number(p.split('/')[1] ?? -1);
      if (cidrContains(p, ip) && (!best || len > best.len)) best = { len, url };
    }
  }
  return best ? withSlash(best.url) : null;
}

/** Finds the RDAP base URL for a domain from the IANA dns bootstrap (by TLD). */
export function rdapBaseForDomain(bootstrap: unknown, domain: string): string | null {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
  // Try the longest registered suffix first (bootstrap entries are TLDs, but be future-proof).
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    for (const svc of arr(obj(bootstrap).services)) {
      const [tlds, urls] = arr(svc) as [unknown, unknown];
      if (arr(tlds).map((x) => String(x).toLowerCase()).includes(suffix)) {
        const url = arr(urls).map(String).find((u) => u.startsWith('https://'));
        if (url) return withSlash(url);
      }
    }
  }
  return null;
}

const withSlash = (u: string) => (u.endsWith('/') ? u : `${u}/`);

// ---------------------------------------------------------------- RDAP objects (RFC 9083)

/** Reads a jCard property (e.g. 'fn', 'email') from an RDAP entity. */
export function vcardProp(entity: unknown, prop: string): string | null {
  const card = arr(obj(entity).vcardArray)[1];
  for (const item of arr(card)) {
    const a = arr(item);
    if (a[0] === prop) {
      const v = a[3];
      if (typeof v === 'string' && v.trim()) return v.trim();
      if (Array.isArray(v)) return v.filter(Boolean).join(' ').trim() || null;
    }
  }
  return null;
}

/** Depth-first search for an entity with a given role (entities can be nested). */
export function findEntity(root: unknown, role: string, depth = 0): Json | null {
  if (depth > 4) return null;
  for (const e of arr(obj(root).entities)) {
    const roles = arr(obj(e).roles).map(String);
    if (roles.includes(role)) return obj(e);
  }
  for (const e of arr(obj(root).entities)) {
    const found = findEntity(e, role, depth + 1);
    if (found) return found;
  }
  return null;
}

function eventDate(root: unknown, action: string): string | null {
  for (const ev of arr(obj(root).events)) {
    const e = obj(ev);
    if (String(e.eventAction).toLowerCase() === action) return str(e.eventDate);
  }
  return null;
}

export function parseIpRdap(json: unknown, source: string | null): IpRdap {
  const o = obj(json);
  const cidrs = arr(o.cidr0_cidrs)
    .map((c) => {
      const x = obj(c);
      const p = str(x.v4prefix) ?? str(x.v6prefix);
      return p && typeof x.length === 'number' ? `${p}/${x.length}` : null;
    })
    .filter((x): x is string => !!x);
  const registrant = findEntity(o, 'registrant');
  const abuse = findEntity(o, 'abuse');
  return {
    handle: str(o.handle),
    name: str(o.name),
    type: str(o.type),
    country: str(o.country),
    startAddress: str(o.startAddress),
    endAddress: str(o.endAddress),
    cidrs,
    registrant: registrant ? vcardProp(registrant, 'fn') : null,
    abuseEmail: abuse ? vcardProp(abuse, 'email') : null,
    registered: eventDate(o, 'registration'),
    lastChanged: eventDate(o, 'last changed'),
    source,
  };
}

export function parseDomainRdap(json: unknown, source: string | null): DomainRdap {
  const o = obj(json);
  const registrar = findEntity(o, 'registrar');
  const abuse = registrar ? findEntity(registrar, 'abuse') ?? findEntity(o, 'abuse') : findEntity(o, 'abuse');
  const ianaId = registrar
    ? arr(registrar.publicIds).map(obj).find((p) => /iana/i.test(String(p.type)))?.identifier
    : undefined;
  const secure = obj(o.secureDNS);
  return {
    ldhName: str(o.ldhName)?.toLowerCase() ?? null,
    handle: str(o.handle),
    registrar: registrar ? vcardProp(registrar, 'fn') : null,
    registrarIanaId: ianaId !== undefined ? String(ianaId) : null,
    created: eventDate(o, 'registration'),
    expires: eventDate(o, 'expiration'),
    updated: eventDate(o, 'last changed'),
    status: arr(o.status).map(String),
    nameservers: arr(o.nameservers).map((n) => str(obj(n).ldhName)?.toLowerCase()).filter((x): x is string => !!x),
    dnssec: typeof secure.delegationSigned === 'boolean' ? secure.delegationSigned : null,
    abuseEmail: abuse ? vcardProp(abuse, 'email') : null,
    source,
  };
}

// ---------------------------------------------------------------- Team Cymru (DNS)

/** Builds the Team Cymru origin query name for an IP. */
export function cymruOriginName(ip: string): string {
  if (isIPv4(ip)) return `${ip.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  const nibbles = expandIPv6(ip).map((g) => g.toString(16).padStart(4, '0')).join('').split('');
  return `${nibbles.reverse().join('.')}.origin6.asn.cymru.com`;
}

/** "15169 | 8.8.8.0/24 | US | arin | 2023-12-28" */
export function parseCymruOrigin(txt: string[][]): AsnInfo | null {
  const line = txt.map((chunks) => chunks.join('')).find((l) => l.includes('|'));
  if (!line) return null;
  const [asns, prefix, cc, registry, allocated] = line.split('|').map((x) => x.trim());
  const asn = Number((asns ?? '').split(/\s+/)[0]);
  if (!Number.isInteger(asn) || asn <= 0) return null;
  return { asn, prefix: prefix || null, country: cc || null, registry: registry || null, allocated: allocated || null, name: null };
}

/** "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US" → AS name */
export function parseCymruAsName(txt: string[][]): string | null {
  const line = txt.map((c) => c.join('')).find((l) => l.includes('|'));
  if (!line) return null;
  const parts = line.split('|').map((x) => x.trim());
  return parts[4] || null;
}

// ---------------------------------------------------------------- Email security records

export function pickSpf(txt: string[]): string | null {
  return txt.find((t) => /^v=spf1(\s|$)/i.test(t.trim())) ?? null;
}

export function pickDmarc(txt: string[]): string | null {
  return txt.find((t) => /^v=DMARC1\s*;/i.test(t.trim())) ?? null;
}

// ---------------------------------------------------------------- Geolocation (ipinfo.io)

export function parseIpinfo(json: unknown): GeoInfo {
  const o = obj(json);
  return {
    provider: 'ipinfo.io',
    city: str(o.city),
    region: str(o.region),
    country: str(o.country),
    loc: str(o.loc),
    timezone: str(o.timezone),
    org: str(o.org),
  };
}

// ---------------------------------------------------------------- Tor exit list

export function parseTorExitList(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (s && !s.startsWith('#') && (isIPv4(s) || isIPv6(s))) out.add(s.toLowerCase());
  }
  return out;
}

// ---------------------------------------------------------------- Reputation services

export type VtKind = 'ip' | 'domain' | 'hash';

export function vtPath(kind: VtKind, value: string): string {
  const coll = kind === 'ip' ? 'ip_addresses' : kind === 'domain' ? 'domains' : 'files';
  return `https://www.virustotal.com/api/v3/${coll}/${encodeURIComponent(value)}`;
}

export function vtGuiLink(kind: VtKind, value: string): string {
  const seg = kind === 'ip' ? 'ip-address' : kind === 'domain' ? 'domain' : 'file';
  return `https://www.virustotal.com/gui/${seg}/${encodeURIComponent(value)}`;
}

export function parseVirusTotal(json: unknown, kind: VtKind, value: string): ReputationResult {
  const a = obj(obj(obj(json).data).attributes);
  const stats = obj(a.last_analysis_stats);
  const date = num(a.last_analysis_date);
  return {
    service: 'virustotal',
    found: true,
    malicious: num(stats.malicious) ?? 0,
    suspicious: num(stats.suspicious) ?? 0,
    harmless: num(stats.harmless) ?? 0,
    undetected: num(stats.undetected) ?? 0,
    reputation: num(a.reputation) ?? null,
    tags: arr(a.tags).map(String).slice(0, 30),
    names: arr(a.names).map(String).slice(0, 10),
    typeDescription: str(a.type_description),
    lastAnalysis: date ? new Date(date * 1000).toISOString() : null,
    link: vtGuiLink(kind, value),
  };
}

export function parseAbuseIpdb(json: unknown): ReputationResult {
  const d = obj(obj(json).data);
  return {
    service: 'abuseipdb',
    found: true,
    abuseScore: num(d.abuseConfidenceScore) ?? 0,
    totalReports: num(d.totalReports) ?? 0,
    lastReported: str(d.lastReportedAt),
    usageType: str(d.usageType),
    isp: str(d.isp),
    isTor: typeof d.isTor === 'boolean' ? d.isTor : null,
  };
}

export function parseShodanHost(json: unknown): ReputationResult {
  const o = obj(json);
  const vulns = Array.isArray(o.vulns) ? o.vulns.map(String) : Object.keys(obj(o.vulns));
  return {
    service: 'shodan',
    found: true,
    ports: arr(o.ports).filter((p): p is number => typeof p === 'number').sort((a, b) => a - b),
    hostnames: arr(o.hostnames).map(String).slice(0, 20),
    vulns: vulns.slice(0, 50),
    tags: arr(o.tags).map(String),
    isp: str(o.isp) ?? str(o.org),
  };
}
