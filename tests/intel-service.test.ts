import { describe, expect, it, vi } from 'vitest';
import ipRdap from './fixtures/rdap-ip.json';
import domainRdap from './fixtures/rdap-domain.json';
import { NetworkGate, type NetworkActivityEntry } from '../src/core/network-gate';
import { IntelService, normalizeDomainInput } from '../src/main/services/intel';
import type { ApiKeyService, TlsInfo } from '../src/shared/api';

// Public test addresses (RFC 5737 / 3849 are "private-ish" by our classifier only if reserved; these are public ranges used as fixtures).
const PUBLIC_IP = '8.8.8.8';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function makeFetch(routes: Record<string, () => Response>) {
  return vi.fn(async (url: string, _init?: RequestInit) => {
    for (const [prefix, r] of Object.entries(routes)) if (url.startsWith(prefix)) return r();
    return new Response('not found', { status: 404 });
  });
}

const BOOT_V4 = { services: [[['8.0.0.0/8'], ['https://rdap.arin.net/registry/']]] };
const BOOT_DNS = { services: [[['com'], ['https://rdap.verisign.com/com/v1/']]] };

function resolverMock(over: Partial<Record<string, (...a: any[]) => Promise<any>>> = {}) {
  const enodata = () => Promise.reject(Object.assign(new Error('no data'), { code: 'ENODATA' }));
  return {
    getServers: () => ['192.0.2.53'],
    reverse: vi.fn(async () => ['dns.google']),
    resolve4: vi.fn(async () => ['93.184.215.14']),
    resolve6: vi.fn(enodata),
    resolveMx: vi.fn(async () => [{ exchange: 'mx2.example.com', priority: 20 }, { exchange: 'mx1.example.com', priority: 10 }]),
    resolveTxt: vi.fn(async (name: string) => {
      if (name.endsWith('.origin.asn.cymru.com')) return [['15169 | 8.8.8.0/24 | US | arin | 2023-12-28']];
      if (name.startsWith('AS')) return [['15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US']];
      if (name.startsWith('_dmarc.')) return [['v=DMARC1; p=reject']];
      return [['v=spf1 -all'], ['some-verification=1']];
    }),
    resolveNs: vi.fn(async () => ['B.IANA-SERVERS.NET', 'a.iana-servers.net']),
    resolveCname: vi.fn(enodata),
    resolveSoa: vi.fn(async () => ({ nsname: 'ns.icann.org', hostmaster: 'noc.dns.icann.org', serial: 2026092700 })),
    resolveCaa: vi.fn(enodata),
    ...over,
  };
}

const tlsInfo: TlsInfo = {
  host: 'example.com', port: 443, protocol: 'TLSv1.3', authorized: true, authorizationError: null, subject: 'Example — example.com',
  issuer: 'Test CA — Test Issuing CA', validFrom: '2026-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z', daysRemaining: 96,
  sans: ['example.com', 'www.example.com'], fingerprint256: 'AA:BB', serialNumber: '01',
};

function build(opts: { offline?: boolean; keys?: Partial<Record<ApiKeyService, string>>; routes?: Record<string, () => Response>; resolver?: any; tls?: any } = {}) {
  const log: NetworkActivityEntry[] = [];
  const fetchMock = makeFetch(opts.routes ?? {});
  const gate = new NetworkGate(() => !!opts.offline, (e) => log.push(e), fetchMock);
  const resolver = opts.resolver ?? resolverMock();
  const tls = opts.tls ?? vi.fn(async () => tlsInfo);
  const svc = new IntelService({ gate, secret: (s) => opts.keys?.[s] ?? null, resolver, tls });
  return { svc, log, fetchMock, resolver, tls };
}

const ALL_IP = { reverseDns: true, rdap: true, asn: true, geo: true, tor: true, reputation: ['virustotal', 'abuseipdb', 'shodan'] as const };

describe('IP intelligence', () => {
  it('rejects invalid input', async () => {
    const { svc } = build();
    await expect(svc.ip('999.1.1.1', { ...ALL_IP, reputation: [] })).rejects.toMatchObject({ code: 'invalid_ip' });
    await expect(svc.ip('8.8.8.8; rm -rf /', { ...ALL_IP, reputation: [] })).rejects.toMatchObject({ code: 'invalid_ip' });
  });

  it('Offline Mode: nothing leaves the machine, every source says why', async () => {
    const { svc, fetchMock, resolver, log } = build({ offline: true, keys: { virustotal: 'k'.repeat(64) } });
    const r = await svc.ip(PUBLIC_IP, { ...ALL_IP, reputation: ['virustotal'] });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(resolver.reverse).not.toHaveBeenCalled();
    expect(r.sources.every((s) => !s.ok && s.error === 'offline_mode')).toBe(true);
    expect(r.scope).toBe('public');
    expect(log.every((e) => e.outcome === 'blocked_offline')).toBe(true);
  });

  it('never sends private IPs to external services', async () => {
    const { svc, fetchMock, resolver } = build({ keys: { virustotal: 'k'.repeat(64) } });
    const r = await svc.ip('192.168.1.10', { ...ALL_IP, reputation: ['virustotal'] });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(resolver.reverse).toHaveBeenCalled(); // local resolver only
    expect(r.scope).toBe('private');
    expect(r.sources.filter((s) => s.id !== 'reverse_dns').every((s) => s.error === 'not_public_ip')).toBe(true);
  });

  it('collects RDAP (following a redirect), ASN, geolocation, Tor and reputation', async () => {
    const { svc, log } = build({
      keys: { virustotal: 'v'.repeat(64), abuseipdb: 'a'.repeat(80) },
      routes: {
        'https://data.iana.org/rdap/ipv4.json': () => json(BOOT_V4),
        'https://rdap.arin.net/registry/ip/8.8.8.8': () => new Response(null, { status: 301, headers: { location: 'https://rdap.arin.net/registry/ip/8.8.8.0' } }),
        'https://rdap.arin.net/registry/ip/8.8.8.0': () => json(ipRdap),
        'https://ipinfo.io/8.8.8.8/json': () => json({ city: 'Mountain View', region: 'California', country: 'US', org: 'AS15169 Google LLC', timezone: 'America/Los_Angeles', loc: '37.4,-122.1' }),
        'https://check.torproject.org/torbulkexitlist': () => new Response('185.220.101.1\n'),
        'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8': () => json({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20 } } } }),
        'https://api.abuseipdb.com/api/v2/check': () => json({ data: { abuseConfidenceScore: 0, totalReports: 3, usageType: 'Content Delivery Network', isTor: false } }),
      },
    });
    const r = await svc.ip(PUBLIC_IP, { ...ALL_IP, reputation: ['virustotal', 'abuseipdb', 'shodan'] });
    expect(r.reverseDns).toEqual(['dns.google']);
    expect(r.rdap?.name).toBe('TEST-NET-1');
    expect(r.rdap?.source).toBe('rdap.arin.net');
    expect(r.asn).toEqual({ asn: 15169, prefix: '8.8.8.0/24', country: 'US', registry: 'arin', allocated: '2023-12-28', name: 'GOOGLE - Google LLC, US' });
    expect(r.geo?.city).toBe('Mountain View');
    expect(r.tor).toBe(false);
    expect(r.reputation.map((x) => x.service).sort()).toEqual(['abuseipdb', 'virustotal']);
    expect(r.sources.find((s) => s.id === 'reputation:shodan')).toMatchObject({ ok: false, error: 'api_key_missing' });
    // Network Activity: hosts only, never the API key
    expect(JSON.stringify(log)).not.toContain('v'.repeat(64));
    expect(log.some((e) => e.host === 'rdap.arin.net')).toBe(true);
    expect(log.some((e) => e.service === 'team-cymru' && e.host === '192.0.2.53')).toBe(true);
  });

  it('reports API errors per source without failing the lookup', async () => {
    const { svc } = build({
      keys: { virustotal: 'v'.repeat(64) },
      routes: {
        'https://data.iana.org/rdap/ipv4.json': () => json(BOOT_V4),
        'https://rdap.arin.net/': () => new Response(null, { status: 302, headers: { location: 'http://insecure.example/x' } }),
        'https://www.virustotal.com/': () => json({ error: 'WrongCredentials' }, 401),
        'https://ipinfo.io/': () => json({}, 429),
      },
    });
    const r = await svc.ip(PUBLIC_IP, { reverseDns: false, rdap: true, asn: false, geo: true, tor: false, reputation: ['virustotal'] });
    const err = (id: string) => r.sources.find((s) => s.id === id)?.error;
    expect(err('rdap')).toBe('insecure_redirect');
    expect(err('reputation:virustotal')).toBe('api_key_invalid');
    expect(err('geo')).toBe('rate_limited');
    expect(r.rdap).toBeNull();
  });

  it('distinguishes a rejected API key from a server that refuses unauthenticated requests', async () => {
    const { svc } = build({
      routes: {
        'https://data.iana.org/rdap/ipv4.json': () => json(BOOT_V4),
        'https://rdap.arin.net/': () => json({}, 403),
      },
    });
    const r = await svc.ip(PUBLIC_IP, { reverseDns: false, rdap: true, asn: false, geo: false, tor: false, reputation: [] });
    expect(r.sources[0]).toMatchObject({ id: 'rdap', ok: false, error: 'remote_forbidden' });
    expect(r.rdap).toBeNull();
  });

  it('reports DNS server failures as errors instead of empty results', async () => {
    const resolver = resolverMock({ reverse: vi.fn(async () => { throw Object.assign(new Error('x'), { code: 'ESERVFAIL' }); }) });
    const { svc } = build({ resolver });
    const r = await svc.ip(PUBLIC_IP, { reverseDns: true, rdap: false, asn: false, geo: false, tor: false, reputation: [] });
    expect(r.sources[0]).toMatchObject({ id: 'reverse_dns', ok: false, error: 'dns_error' });
    expect(r.reverseDns).toBeNull();
  });
});

describe('Domain intelligence', () => {
  it('normalizes input (URLs, IDN, case) and rejects junk', () => {
    expect(normalizeDomainInput('https://WWW.Example.com/path?q=1')).toBe('www.example.com');
    expect(normalizeDomainInput('example.com.')).toBe('example.com');
    expect(normalizeDomainInput('مثال.السعودية')).toMatch(/^xn--/);
    expect(normalizeDomainInput('not a domain')).toBeNull();
    expect(normalizeDomainInput('example.com; ls')).toBeNull();
  });

  it('collects DNS, email security, RDAP, TLS and infrastructure', async () => {
    const { svc, tls } = build({
      routes: {
        'https://data.iana.org/rdap/dns.json': () => json(BOOT_DNS),
        'https://rdap.verisign.com/com/v1/domain/example.com': () => json(domainRdap),
      },
    });
    const r = await svc.domain('Example.COM', { dns: true, rdap: true, tls: true, infrastructure: true, reputation: [] });
    expect(r.domain).toBe('example.com');
    expect(r.dns?.a).toEqual(['93.184.215.14']);
    expect(r.dns?.mx[0]).toEqual({ exchange: 'mx1.example.com', priority: 10 });
    expect(r.dns?.ns).toEqual(['a.iana-servers.net', 'b.iana-servers.net']);
    expect(r.dns?.spf).toBe('v=spf1 -all');
    expect(r.dns?.dmarc).toBe('v=DMARC1; p=reject');
    expect(r.rdap?.registrar).toBe('RESERVED-Internet Assigned Numbers Authority');
    expect(r.rdap?.expires).toBe('2027-08-13T04:00:00Z');
    expect(r.tls?.issuer).toBe('Test CA — Test Issuing CA');
    expect(tls).toHaveBeenCalledWith('example.com', 443, 10000);
    expect(r.infrastructure[0]).toMatchObject({ ip: '93.184.215.14', asn: { asn: 15169 } });
    expect(r.sources.every((s) => s.ok)).toBe(true);
  });

  it('rejects invalid domains', async () => {
    const { svc } = build();
    await expect(svc.domain('bad domain!', { dns: true, rdap: false, tls: false, infrastructure: false, reputation: [] })).rejects.toMatchObject({ code: 'invalid_domain' });
  });
});

describe('Reputation lookups', () => {
  it('validates indicators and applicable services', async () => {
    const { svc } = build({ keys: { virustotal: 'v'.repeat(64) } });
    await expect(svc.reputation('hash', 'nothex', ['virustotal'])).rejects.toMatchObject({ code: 'invalid_hash' });
    await expect(svc.reputation('ip', '10.0.0.1', ['virustotal'])).rejects.toMatchObject({ code: 'not_public_ip' });
    await expect(svc.reputation('domain', 'example.com', ['shodan'])).rejects.toMatchObject({ code: 'no_service_selected' });
    await expect(svc.reputation('url', 'x', ['virustotal'])).rejects.toMatchObject({ code: 'invalid_input' });
  });
  it('looks up a file hash (hash only — never the file)', async () => {
    const sha = 'a'.repeat(64);
    const { svc, fetchMock } = build({
      keys: { virustotal: 'v'.repeat(64) },
      routes: { [`https://www.virustotal.com/api/v3/files/${sha}`]: () => json({ data: { attributes: { last_analysis_stats: { malicious: 12, suspicious: 0, harmless: 0, undetected: 50 } } } }) },
    });
    const r = await svc.reputation('hash', sha.toUpperCase(), ['virustotal']);
    expect(r.results[0]).toMatchObject({ service: 'virustotal', found: true, malicious: 12 });
    const [, init] = fetchMock.mock.calls[0]! as [string, RequestInit];
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.body).toBeUndefined();
  });
  it('treats 404 as "not found" rather than an error', async () => {
    const { svc } = build({ keys: { virustotal: 'v'.repeat(64) } });
    const r = await svc.reputation('hash', 'b'.repeat(64), ['virustotal']);
    expect(r.results[0]).toEqual({ service: 'virustotal', found: false });
    expect(r.sources[0]!.ok).toBe(true);
  });
});
