import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CaptureReader, type CapturedFrame } from '../src/core/traffic/pcap';
import { TrafficAnalyzer, type TrafficReport } from '../src/core/traffic/analyzer';
import { parsePacket, LINKTYPE } from '../src/core/traffic/packet';
import { parseDns, parseHttp, parseTls } from '../src/core/traffic/protocols';

const fixture = (name: string) => new Uint8Array(readFileSync(join(__dirname, 'fixtures', 'traffic', name)));

function readAll(bytes: Uint8Array, chunk = 997): { frames: CapturedFrame[]; reader: CaptureReader } {
  const reader = new CaptureReader();
  const frames: CapturedFrame[] = [];
  // Odd chunk size: records and blocks straddle chunk boundaries.
  for (let i = 0; i < bytes.length; i += chunk) frames.push(...reader.push(bytes.subarray(i, i + chunk)));
  return { frames, reader };
}

function analyze(name: string): TrafficReport {
  const a = new TrafficAnalyzer();
  for (const f of readAll(fixture(name)).frames) a.add(f);
  return a.finish();
}

describe('capture reader', () => {
  it('reads classic pcap and pcapng identically, across chunk boundaries', () => {
    const pcap = readAll(fixture('sample.pcap'));
    const ng = readAll(fixture('sample.pcapng'));
    expect(pcap.reader.error).toBeNull();
    expect(ng.reader.error).toBeNull();
    expect(pcap.reader.detectedFormat).toBe('pcap');
    expect(ng.reader.detectedFormat).toBe('pcapng');
    expect(pcap.frames).toHaveLength(133);
    expect(ng.frames).toHaveLength(133);
    expect(ng.frames.map((f) => f.data.length)).toEqual(pcap.frames.map((f) => f.data.length));
    expect(Math.round(ng.frames[0]!.ts)).toBe(Math.round(pcap.frames[0]!.ts));
    expect(pcap.frames[0]!.ts).toBeGreaterThan(1_700_000_000_000);
    expect(pcap.frames[0]!.linkType).toBe(LINKTYPE.ETHERNET);
  });

  it('refuses files that are not captures and stops on corrupt lengths', () => {
    const r = new CaptureReader();
    expect(r.push(new TextEncoder().encode('this is definitely not a pcap file'))).toEqual([]);
    expect(r.error).toBe('not_a_capture');
    const bad = fixture('sample.pcap').slice(0, 60);
    new DataView(bad.buffer).setUint32(24 + 8, 0x7fffffff, true); // absurd captured length
    const r2 = new CaptureReader();
    r2.push(bad);
    expect(r2.error).toBe('corrupt_capture');
  });
});

describe('packet parsing never throws', () => {
  it('handles random and truncated frames', () => {
    let seed = 7;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) & 0xff;
    for (let n = 0; n < 2000; n++) {
      const buf = new Uint8Array(n % 120).map(rnd);
      for (const lt of [0, 1, 101, 113, 228]) expect(() => parsePacket(buf, 0, buf.length, lt)).not.toThrow();
    }
    for (const f of readAll(fixture('sample.pcap')).frames) {
      for (let cut = 0; cut < f.data.length; cut += 7) expect(() => parsePacket(f.data.subarray(0, cut), 0, cut, 1)).not.toThrow();
    }
  });

  it('keeps secrets out of HTTP results', () => {
    const req = new TextEncoder().encode('GET /a?token=S1 HTTP/1.1\r\nHost: h.example\r\nCookie: c=S2\r\nAuthorization: Bearer S3\r\n\r\n');
    const h = parseHttp(req)!;
    expect(h).toMatchObject({ method: 'GET', path: '/a', host: 'h.example', redacted: true });
    expect(JSON.stringify(h)).not.toMatch(/S1|S2|S3/);
    expect(parseDns(new Uint8Array(5))).toBeNull();
    expect(parseTls(new Uint8Array([22, 3, 1, 0, 0]))).toBeNull();
  });
});

describe('traffic analyzer', () => {
  const r = analyze('sample.pcapng');

  it('counts everything and orders time', () => {
    expect(r.packets).toBe(133);
    expect(r.bytes).toBeGreaterThan(5000);
    expect(r.first).not.toBeNull();
    expect(r.last! - r.first!).toBeGreaterThan(1000);
    expect(r.truncated).toBe(false);
    expect(r.protocols.map((p) => p.name)).toEqual(expect.arrayContaining(['DNS', 'TLS', 'HTTP', 'FTP', 'DHCP', 'ARP']));
  });

  it('lists devices with manufacturer, addresses and DHCP names', () => {
    const pc = r.devices.find((d) => d.mac === '3C:2E:FF:11:22:33');
    expect(pc?.maker).toEqual({ kind: 'vendor', vendor: 'Apple' });
    expect(pc?.ips).toContain('192.168.1.10');
    const phone = r.devices.find((d) => d.mac === 'DA:A1:19:44:55:66');
    expect(phone?.maker?.kind).toBe('random');
    expect(phone?.names).toContain('Sara-iPhone');
  });

  it('reads DNS, HTTPS names and names external hosts', () => {
    expect(r.dns.queries).toBe(46);
    expect(r.dns.failures).toBe(45);
    expect(r.dns.names.find((n) => n.name === 'example.org')).toMatchObject({ count: 1, failed: 0, types: ['A'] });
    expect(r.tls.find((t) => t.name === 'example.org')).toMatchObject({ count: 1, versions: ['TLS 1.0'] });
    expect(r.external.find((e) => e.ip === '198.51.100.7')?.names).toContain('example.org');
    const https = r.conversations.find((c) => c.server === '198.51.100.7' && c.port === 443);
    expect(https).toMatchObject({ client: '192.168.1.10', protocol: 'TLS', encrypted: true, name: 'example.org' });
  });

  it('shows cleartext traffic without any secret', () => {
    const http = r.cleartext.find((c) => c.protocol === 'HTTP');
    expect(http).toMatchObject({ client: '192.168.1.10', server: '203.0.113.9', host: 'plain.example', detail: 'GET /login …' });
    expect(r.cleartext.find((c) => c.protocol === 'FTP')).toMatchObject({ client: '192.168.1.10', server: '203.0.113.9' });
    expect(JSON.stringify(r)).not.toMatch(/SECRET|U0VDUkVU/);
  });

  it('reports each pattern with its measurement, most severe first', () => {
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['port_scan', 'arp_conflict', 'multiple_dhcp', 'exposed_service', 'cleartext_login', 'plain_http', 'weak_tls', 'dns_failures']));
    expect(r.findings.find((f) => f.id === 'port_scan')?.vars).toEqual({ src: '192.168.1.66', dst: '192.168.1.10', ports: 30 });
    expect(r.findings.find((f) => f.id === 'arp_conflict')?.vars.ip).toBe('192.168.1.1');
    expect(r.findings.find((f) => f.id === 'multiple_dhcp')?.vars.servers).toBe('192.168.1.1, 192.168.1.66');
    expect(r.findings.find((f) => f.id === 'exposed_service')).toMatchObject({ severity: 'high', vars: { dst: '192.168.1.10', port: 3389, answered: 1 } });
    expect(r.findings.find((f) => f.id === 'weak_tls')?.vars).toMatchObject({ server: '198.51.100.7', version: 'TLS 1.0', name: 'example.org' });
    expect(r.findings.find((f) => f.id === 'dns_failures')?.vars).toMatchObject({ client: '192.168.1.20', names: 45 });
    const sev = r.findings.map((f) => ['high', 'medium', 'low', 'info'].indexOf(f.severity));
    expect([...sev].sort((a, b) => a - b)).toEqual(sev);
    expect(r.encryptedShare).not.toBeNull();
  });

  it('gives the same report for pcap and pcapng', () => {
    const a = analyze('sample.pcap');
    expect(a.findings).toEqual(r.findings);
    expect(a.devices.length).toBe(r.devices.length);
  });
});
