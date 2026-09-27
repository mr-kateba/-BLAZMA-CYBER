import { describe, expect, it } from 'vitest';
import ipRdap from './fixtures/rdap-ip.json';
import domainRdap from './fixtures/rdap-domain.json';
import {
  cidrContains, cymruOriginName, expandIPv6, parseAbuseIpdb, parseCymruAsName, parseCymruOrigin, parseDomainRdap, parseIpRdap,
  parseIpinfo, parseShodanHost, parseTorExitList, parseVirusTotal, pickDmarc, pickSpf, rdapBaseForDomain, rdapBaseForIp, vtPath,
} from '../src/core/intel';

describe('IP math', () => {
  it('matches IPv4 and IPv6 CIDRs', () => {
    expect(cidrContains('192.0.2.0/24', '192.0.2.77')).toBe(true);
    expect(cidrContains('192.0.2.0/24', '192.0.3.1')).toBe(false);
    expect(cidrContains('0.0.0.0/0', '8.8.8.8')).toBe(true);
    expect(cidrContains('2001:db8::/32', '2001:db8:1::5')).toBe(true);
    expect(cidrContains('2001:db8::/32', '2001:db9::1')).toBe(false);
    expect(cidrContains('2001:db8::/32', '192.0.2.1')).toBe(false);
  });
  it('expands IPv6', () => {
    expect(expandIPv6('2001:db8::1')).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6('::ffff:192.0.2.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]);
  });
});

describe('RDAP bootstrap', () => {
  const v4 = { services: [[['192.0.0.0/8'], ['https://rdap.arin.net/registry/', 'http://rdap.arin.net/registry/']], [['192.0.2.0/24'], ['https://more-specific.example/rdap']]] };
  const dns = { services: [[['com', 'net'], ['https://rdap.verisign.com/com/v1/']], [['sa'], ['http://insecure.example/']]] };
  it('uses the longest prefix and https only', () => {
    expect(rdapBaseForIp(v4, '192.0.2.10')).toBe('https://more-specific.example/rdap/');
    expect(rdapBaseForIp(v4, '192.10.0.1')).toBe('https://rdap.arin.net/registry/');
    expect(rdapBaseForIp(v4, '10.0.0.1')).toBeNull();
  });
  it('maps domains by TLD and refuses non-https servers', () => {
    expect(rdapBaseForDomain(dns, 'www.example.com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(rdapBaseForDomain(dns, 'example.sa')).toBeNull();
    expect(rdapBaseForDomain(dns, 'example.org')).toBeNull();
  });
});

describe('RDAP objects', () => {
  it('parses an IP network', () => {
    expect(parseIpRdap(ipRdap, 'rdap.arin.net')).toEqual({
      handle: 'NET-192-0-2-0-1', name: 'TEST-NET-1', type: 'IANA Special Use', country: 'US',
      startAddress: '192.0.2.0', endAddress: '192.0.2.255', cidrs: ['192.0.2.0/24'],
      registrant: 'Internet Assigned Numbers Authority', abuseEmail: 'abuse@iana.example',
      registered: '2010-01-15T00:00:00-05:00', lastChanged: '2013-08-30T08:58:34-04:00', source: 'rdap.arin.net',
    });
  });
  it('parses a domain', () => {
    expect(parseDomainRdap(domainRdap, 'rdap.verisign.com')).toEqual({
      ldhName: 'example.com', handle: '2336799_DOMAIN_COM-VRSN', registrar: 'RESERVED-Internet Assigned Numbers Authority',
      registrarIanaId: '376', created: '1995-08-14T04:00:00Z', expires: '2027-08-13T04:00:00Z', updated: '2026-08-14T07:01:39Z',
      status: ['client delete prohibited', 'client transfer prohibited', 'client update prohibited'],
      nameservers: ['a.iana-servers.net', 'b.iana-servers.net'], dnssec: true, abuseEmail: 'abuse@registrar.example', source: 'rdap.verisign.com',
    });
  });
  it('tolerates empty / malformed objects', () => {
    expect(parseIpRdap(null, null).cidrs).toEqual([]);
    expect(parseDomainRdap({ entities: 'x', events: 5 }, null).status).toEqual([]);
  });
});

describe('Team Cymru', () => {
  it('builds query names', () => {
    expect(cymruOriginName('192.0.2.1')).toBe('1.2.0.192.origin.asn.cymru.com');
    expect(cymruOriginName('2001:db8::1')).toMatch(/^1\.0\.0\.0\.(0\.){20}8\.b\.d\.0\.1\.0\.0\.2\.origin6\.asn\.cymru\.com$/);
  });
  it('parses origin and AS name (real response format)', () => {
    expect(parseCymruOrigin([['15169 | 8.8.8.0/24 | US | arin | 2023-12-28']])).toEqual({ asn: 15169, prefix: '8.8.8.0/24', country: 'US', registry: 'arin', allocated: '2023-12-28', name: null });
    expect(parseCymruOrigin([['13335 209242 | 1.1.1.0/24 | AU | apnic | 2011-08-11']])!.asn).toBe(13335);
    expect(parseCymruOrigin([['garbage']])).toBeNull();
    expect(parseCymruAsName([['15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US']])).toBe('GOOGLE - Google LLC, US');
  });
});

describe('email records', () => {
  it('picks SPF and DMARC', () => {
    expect(pickSpf(['google-site-verification=x', 'v=spf1 include:_spf.example.com ~all'])).toBe('v=spf1 include:_spf.example.com ~all');
    expect(pickSpf(['v=spf10 nope'])).toBeNull();
    expect(pickDmarc(['v=DMARC1; p=reject; rua=mailto:d@example.com'])).toBe('v=DMARC1; p=reject; rua=mailto:d@example.com');
  });
});

describe('providers', () => {
  it('parses ipinfo', () => {
    expect(parseIpinfo({ ip: '8.8.8.8', city: 'Mountain View', region: 'California', country: 'US', loc: '37.4,-122.1', org: 'AS15169 Google LLC', timezone: 'America/Los_Angeles' }))
      .toEqual({ provider: 'ipinfo.io', city: 'Mountain View', region: 'California', country: 'US', loc: '37.4,-122.1', timezone: 'America/Los_Angeles', org: 'AS15169 Google LLC' });
  });
  it('parses the Tor exit list', () => {
    const s = parseTorExitList('# comment\n185.220.101.1\nnot-an-ip\n2001:db8::5\n');
    expect(s.has('185.220.101.1')).toBe(true);
    expect(s.has('2001:db8::5')).toBe(true);
    expect(s.size).toBe(2);
  });
  it('parses VirusTotal', () => {
    const r = parseVirusTotal({ data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 10 }, reputation: -12, tags: ['peexe'], names: ['a.exe'], type_description: 'Win32 EXE', last_analysis_date: 1790000000 } } }, 'hash', 'abc');
    expect(r).toMatchObject({ service: 'virustotal', found: true, malicious: 3, suspicious: 1, harmless: 60, undetected: 10, reputation: -12, typeDescription: 'Win32 EXE', link: 'https://www.virustotal.com/gui/file/abc' });
    expect(r.lastAnalysis).toBe(new Date(1790000000 * 1000).toISOString());
    expect(vtPath('ip', '192.0.2.1')).toBe('https://www.virustotal.com/api/v3/ip_addresses/192.0.2.1');
  });
  it('parses AbuseIPDB and Shodan', () => {
    expect(parseAbuseIpdb({ data: { abuseConfidenceScore: 87, totalReports: 120, lastReportedAt: '2026-09-01T00:00:00+00:00', usageType: 'Data Center/Web Hosting/Transit', isp: 'Example Hosting', isTor: false } }))
      .toEqual({ service: 'abuseipdb', found: true, abuseScore: 87, totalReports: 120, lastReported: '2026-09-01T00:00:00+00:00', usageType: 'Data Center/Web Hosting/Transit', isp: 'Example Hosting', isTor: false });
    expect(parseShodanHost({ ports: [443, 22, 80], hostnames: ['h.example'], vulns: { 'CVE-2024-0001': {} }, tags: ['cloud'], org: 'Org' }))
      .toEqual({ service: 'shodan', found: true, ports: [22, 80, 443], hostnames: ['h.example'], vulns: ['CVE-2024-0001'], tags: ['cloud'], isp: 'Org' });
  });
});
