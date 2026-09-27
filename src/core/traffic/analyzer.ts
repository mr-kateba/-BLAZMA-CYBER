// Traffic analysis (pure): turns captured frames into a report — devices, conversations,
// protocols, DNS, HTTPS sites, cleartext traffic and observational findings.
//
// Honesty rules:
//  - Findings describe a measured PATTERN and its threshold, never a verdict ("port-scan pattern",
//    not "attacker"): legitimate scanners, backups and discovery tools produce the same shapes.
//  - Nothing is decrypted; secrets never enter the report (HTTP keeps an allowlist of headers).
//  - Memory is bounded: every table has a cap, and the report says when a cap was reached.

import { classifyIP } from '../validation';
import { macInfo, type MacKind } from '../oui';
import type { CapturedFrame } from './pcap';
import { isServicePort, parsePacket, type ParsedPacket } from './packet';

export type FindingSeverity = 'high' | 'medium' | 'low' | 'info';

export interface TrafficFinding {
  id: 'port_scan' | 'host_sweep' | 'arp_conflict' | 'multiple_dhcp' | 'exposed_service' | 'cleartext_login' | 'weak_tls' | 'dns_failures' | 'plain_http';
  severity: FindingSeverity;
  vars: Record<string, string | number>;
}

export interface TrafficDevice {
  mac: string;
  maker: { kind: MacKind; vendor: string | null } | null;
  ips: string[];
  names: string[];
  packets: number;
  bytesOut: number;
  bytesIn: number;
  first: number;
  last: number;
}

export interface TrafficConversation {
  client: string;
  server: string;
  port: number;
  transport: string;
  protocol: string;
  encrypted: boolean | null;
  packets: number;
  bytes: number;
  name: string | null;
}

export interface TrafficReport {
  packets: number;
  bytes: number;
  /** Frames whose link layer could not be read (e.g. Wi-Fi radio headers). */
  unreadable: number;
  first: number | null;
  last: number | null;
  /** A table hit its cap; totals stay exact but some rows were not kept. */
  truncated: boolean;
  protocols: Array<{ name: string; packets: number; bytes: number; encrypted: boolean | null }>;
  devices: TrafficDevice[];
  conversations: TrafficConversation[];
  external: Array<{ ip: string; packets: number; bytes: number; names: string[] }>;
  dns: { queries: number; failures: number; names: Array<{ name: string; count: number; failed: number; types: string[] }> };
  tls: Array<{ name: string; count: number; versions: string[] }>;
  cleartext: Array<{ protocol: string; client: string; server: string; host: string | null; detail: string | null; count: number }>;
  findings: TrafficFinding[];
  encryptedShare: number | null;
}

const CAP = { devices: 2000, conversations: 20000, external: 5000, dnsNames: 5000, tls: 3000, cleartext: 2000, sets: 2048, scanKeys: 20000 };
const TOP = { conversations: 300, external: 300, dns: 300, tls: 300, cleartext: 300 };
const LOGIN_PROTOCOLS = new Set(['FTP', 'Telnet', 'POP3', 'IMAP', 'SMTP', 'SNMP', 'LDAP', 'VNC', 'TFTP']);
const EXPOSED_PORTS = new Set([22, 23, 445, 1433, 3306, 3389, 5900]);
const WEAK_TLS = new Set(['SSL 3.0', 'TLS 1.0', 'TLS 1.1']);
const SCAN_PORTS = 25;
const SWEEP_HOSTS = 30;
const DNS_FAILURE_NAMES = 40;

function isLocal(ip: string | null): boolean {
  if (!ip) return false;
  const c = classifyIP(ip);
  return c === 'private' || c === 'link-local' || c === 'cgnat';
}

function addCapped<T>(set: Set<T>, v: T, cap = CAP.sets): void {
  if (set.size < cap || set.has(v)) set.add(v);
}

export class TrafficAnalyzer {
  private packets = 0;
  private bytes = 0;
  private unreadable = 0;
  private first: number | null = null;
  private last: number | null = null;
  private truncated = false;
  private encryptedBytes = 0;
  private classifiedBytes = 0;
  private protocols = new Map<string, { packets: number; bytes: number; encrypted: boolean | null }>();
  private devices = new Map<string, { ips: Set<string>; names: Set<string>; packets: number; bytesOut: number; bytesIn: number; first: number; last: number }>();
  private convs = new Map<string, TrafficConversation>();
  private external = new Map<string, { packets: number; bytes: number }>();
  private ipNames = new Map<string, Set<string>>();
  private dnsNames = new Map<string, { count: number; failed: number; types: Set<string> }>();
  private dnsQueries = 0;
  private dnsFailures = 0;
  private failedByClient = new Map<string, Set<string>>();
  private tls = new Map<string, { count: number; versions: Set<string> }>();
  private weakTls = new Map<string, string>();
  private cleartext = new Map<string, { protocol: string; client: string; server: string; host: string | null; detail: string | null; count: number }>();
  private synPorts = new Map<string, Set<number>>();
  private synHosts = new Map<string, Set<string>>();
  private arp = new Map<string, Set<string>>();
  private dhcpServers = new Set<string>();
  private exposed = new Map<string, { src: string; dst: string; port: number; answered: boolean }>();

  add(frame: CapturedFrame): void {
    const p = parsePacket(frame.data, frame.ts, frame.wireLength, frame.linkType);
    this.packets++;
    this.bytes += p.wireLength;
    if (p.ts > 0) {
      if (this.first === null || p.ts < this.first) this.first = p.ts;
      if (this.last === null || p.ts > this.last) this.last = p.ts;
    }
    if (p.network === 'other' && !p.ethSrc) {
      this.unreadable++;
      return;
    }
    this.protocol(p);
    this.device(p);
    if (p.arp) {
      if (p.arp.senderIp !== '0.0.0.0') {
        const set = this.arp.get(p.arp.senderIp) ?? new Set<string>();
        addCapped(set, p.arp.senderMac, 16);
        if (this.arp.size < CAP.devices || this.arp.has(p.arp.senderIp)) this.arp.set(p.arp.senderIp, set);
      }
      return;
    }
    if (!p.srcIp || !p.dstIp) return;
    this.conversation(p);
    this.externalHost(p);
    if (p.dns) this.dns(p);
    if (p.dhcp && (p.dhcp.messageType === 'OFFER' || p.dhcp.messageType === 'ACK')) addCapped(this.dhcpServers, p.dhcp.serverId ?? p.srcIp, 64);
    if (p.tls) this.tlsInfo(p);
    if (p.encrypted === false && (p.http || (LOGIN_PROTOCOLS.has(p.protocol) && p.confidence === 'header'))) this.clear(p);
    if (p.transport === 'TCP' && p.syn) this.syn(p);
  }

  private protocol(p: ParsedPacket): void {
    const e = this.protocols.get(p.protocol) ?? { packets: 0, bytes: 0, encrypted: p.encrypted };
    e.packets++;
    e.bytes += p.wireLength;
    if (e.encrypted === null) e.encrypted = p.encrypted;
    this.protocols.set(p.protocol, e);
    if (p.encrypted !== null && (p.transport === 'TCP' || p.transport === 'UDP')) {
      this.classifiedBytes += p.wireLength;
      if (p.encrypted) this.encryptedBytes += p.wireLength;
    }
  }

  private device(p: ParsedPacket): void {
    const touch = (mac: string | null, dir: 'out' | 'in', ip: string | null) => {
      const info = macInfo(mac);
      if (!info || info.kind === 'multicast' || info.kind === 'broadcast') return;
      let d = this.devices.get(info.mac);
      if (!d) {
        if (this.devices.size >= CAP.devices) {
          this.truncated = true;
          return;
        }
        d = { ips: new Set(), names: new Set(), packets: 0, bytesOut: 0, bytesIn: 0, first: p.ts, last: p.ts };
        this.devices.set(info.mac, d);
      }
      if (dir === 'out') {
        d.packets++;
        d.bytesOut += p.wireLength;
      } else d.bytesIn += p.wireLength;
      if (p.ts > 0) {
        d.first = d.first > 0 ? Math.min(d.first, p.ts) : p.ts;
        d.last = Math.max(d.last, p.ts);
      }
      if (ip && isLocal(ip)) addCapped(d.ips, ip, 16);
    };
    touch(p.ethSrc, 'out', p.srcIp);
    touch(p.ethDst, 'in', null);
    if (p.dhcp?.hostname && p.dhcp.clientMac) {
      const d = this.devices.get(p.dhcp.clientMac);
      if (d) addCapped(d.names, p.dhcp.hostname, 8);
    }
    if (p.dns && p.protocol === 'mDNS' && p.dns.isResponse && p.ethSrc) {
      const d = this.devices.get(p.ethSrc);
      const host = p.dns.answers.find((a) => (a.type === 'A' || a.type === 'AAAA') && a.name.endsWith('.local'))?.name;
      if (d && host) addCapped(d.names, host.replace(/\.local$/, ''), 8);
    }
  }

  /** Server side = the side on a well-known port (or the lower port); packets in both directions share one row. */
  private conversation(p: ParsedPacket): void {
    const ports = p.transport === 'TCP' || p.transport === 'UDP';
    let client = p.srcIp!;
    let server = p.dstIp!;
    let port = p.dstPort;
    if (ports) {
      const s = isServicePort(p.srcPort);
      const d = isServicePort(p.dstPort);
      const srcIsServer = (p.transport === 'TCP' && p.syn && p.ack) || (s && !d) || (s === d && p.srcPort < p.dstPort);
      if (srcIsServer) {
        client = p.dstIp!;
        server = p.srcIp!;
        port = p.srcPort;
      }
    } else port = 0;
    const key = `${p.transport}|${client}|${server}|${port}`;
    let c = this.convs.get(key);
    if (!c) {
      if (this.convs.size >= CAP.conversations) {
        this.truncated = true;
        return;
      }
      c = { client, server, port, transport: p.transport, protocol: p.protocol, encrypted: p.encrypted, packets: 0, bytes: 0, name: null };
      this.convs.set(key, c);
    }
    c.packets++;
    c.bytes += p.wireLength;
    if (p.confidence === 'header' && c.protocol !== p.protocol && (c.protocol === p.transport || PORT_LABELS.has(c.protocol))) {
      c.protocol = p.protocol;
      c.encrypted = p.encrypted;
    }
    if (p.tls?.sni) c.name = p.tls.sni;
    if (p.http?.host && p.http.kind === 'request') c.name = p.http.host;
  }

  private externalHost(p: ParsedPacket): void {
    for (const ip of [p.srcIp!, p.dstIp!]) {
      if (classifyIP(ip) !== 'public') continue;
      let e = this.external.get(ip);
      if (!e) {
        if (this.external.size >= CAP.external) {
          this.truncated = true;
          continue;
        }
        e = { packets: 0, bytes: 0 };
        this.external.set(ip, e);
      }
      e.packets++;
      e.bytes += p.wireLength;
    }
    if (p.tls?.sni) this.nameIp(p.dstIp!, p.tls.sni);
  }

  private nameIp(ip: string, name: string): void {
    const set = this.ipNames.get(ip) ?? new Set<string>();
    addCapped(set, name, 8);
    if (this.ipNames.size < CAP.external * 2 || this.ipNames.has(ip)) this.ipNames.set(ip, set);
  }

  private dns(p: ParsedPacket): void {
    const d = p.dns!;
    if (p.protocol !== 'DNS') return;
    const q = d.questions[0];
    if (!d.isResponse) {
      this.dnsQueries++;
      if (!q) return;
      let e = this.dnsNames.get(q.name);
      if (!e) {
        if (this.dnsNames.size >= CAP.dnsNames) {
          this.truncated = true;
          return;
        }
        e = { count: 0, failed: 0, types: new Set() };
        this.dnsNames.set(q.name, e);
      }
      e.count++;
      addCapped(e.types, q.type, 8);
      return;
    }
    for (const a of d.answers) if ((a.type === 'A' || a.type === 'AAAA') && a.data) this.nameIp(a.data, q?.name ?? a.name);
    if (d.rcode === 'NXDOMAIN' && q) {
      this.dnsFailures++;
      const e = this.dnsNames.get(q.name);
      if (e) e.failed++;
      // The response goes back to the device that asked.
      const set = this.failedByClient.get(p.dstIp!) ?? new Set<string>();
      addCapped(set, q.name, 512);
      if (this.failedByClient.size < CAP.devices || this.failedByClient.has(p.dstIp!)) this.failedByClient.set(p.dstIp!, set);
    }
  }

  private tlsInfo(p: ParsedPacket): void {
    const t = p.tls!;
    if (t.kind === 'client-hello' && t.sni) {
      let e = this.tls.get(t.sni);
      if (!e) {
        if (this.tls.size >= CAP.tls) {
          this.truncated = true;
          return;
        }
        e = { count: 0, versions: new Set() };
        this.tls.set(t.sni, e);
      }
      e.count++;
    }
    if (t.kind === 'server-hello' && t.version) {
      const name = [...(this.ipNames.get(p.srcIp!) ?? [])][0];
      if (name) addCapped(this.tls.get(name)?.versions ?? new Set(), t.version, 4);
      if (WEAK_TLS.has(t.version) && this.weakTls.size < 200) this.weakTls.set(`${p.srcIp}`, t.version);
    }
  }

  private clear(p: ParsedPacket): void {
    const serverSide = p.http ? p.http.kind === 'response' : isServicePort(p.srcPort) && !isServicePort(p.dstPort);
    const client = serverSide ? p.dstIp! : p.srcIp!;
    const server = serverSide ? p.srcIp! : p.dstIp!;
    const host = p.http?.host ?? null;
    const detail = p.http?.kind === 'request' ? `${p.http.method ?? ''} ${p.http.path ?? ''}${p.http.redacted ? ' …' : ''}`.trim() : null;
    const key = `${p.protocol}|${client}|${server}|${host ?? ''}`;
    let e = this.cleartext.get(key);
    if (!e) {
      if (this.cleartext.size >= CAP.cleartext) {
        this.truncated = true;
        return;
      }
      e = { protocol: p.protocol, client, server, host, detail, count: 0 };
      this.cleartext.set(key, e);
    }
    e.count++;
    if (!e.detail && detail) e.detail = detail;
  }

  private syn(p: ParsedPacket): void {
    if (!p.ack) {
      const pk = `${p.srcIp}|${p.dstIp}`;
      const ports = this.synPorts.get(pk) ?? new Set<number>();
      addCapped(ports, p.dstPort, 1024);
      if (this.synPorts.size < CAP.scanKeys || this.synPorts.has(pk)) this.synPorts.set(pk, ports);
      const hk = `${p.srcIp}|${p.dstPort}`;
      const hosts = this.synHosts.get(hk) ?? new Set<string>();
      addCapped(hosts, p.dstIp!, 1024);
      if (this.synHosts.size < CAP.scanKeys || this.synHosts.has(hk)) this.synHosts.set(hk, hosts);
    }
    // Connection attempts from the internet to a remote-access/database port on this network.
    const inbound = !p.ack ? { src: p.srcIp!, dst: p.dstIp!, port: p.dstPort } : { src: p.dstIp!, dst: p.srcIp!, port: p.srcPort };
    if (EXPOSED_PORTS.has(inbound.port) && classifyIP(inbound.src) === 'public' && isLocal(inbound.dst)) {
      const key = `${inbound.dst}|${inbound.port}`;
      const e = this.exposed.get(key) ?? { ...inbound, answered: false };
      if (p.ack) e.answered = true;
      if (this.exposed.size < 200 || this.exposed.has(key)) this.exposed.set(key, e);
    }
  }

  finish(): TrafficReport {
    const findings: TrafficFinding[] = [];
    for (const [k, ports] of this.synPorts) {
      if (ports.size < SCAN_PORTS) continue;
      const [src, dst] = k.split('|');
      findings.push({ id: 'port_scan', severity: 'high', vars: { src: src!, dst: dst!, ports: ports.size } });
    }
    for (const [k, hosts] of this.synHosts) {
      if (hosts.size < SWEEP_HOSTS) continue;
      const [src, port] = k.split('|');
      findings.push({ id: 'host_sweep', severity: 'medium', vars: { src: src!, port: Number(port), hosts: hosts.size } });
    }
    for (const [ip, macs] of this.arp) {
      if (macs.size > 1) findings.push({ id: 'arp_conflict', severity: 'high', vars: { ip, macs: [...macs].join(', ') } });
    }
    if (this.dhcpServers.size > 1) findings.push({ id: 'multiple_dhcp', severity: 'high', vars: { servers: [...this.dhcpServers].join(', ') } });
    for (const e of this.exposed.values()) {
      findings.push({ id: 'exposed_service', severity: e.answered ? 'high' : 'medium', vars: { src: e.src, dst: e.dst, port: e.port, answered: e.answered ? 1 : 0 } });
    }
    const logins = new Map<string, number>();
    for (const c of this.cleartext.values()) if (c.protocol !== 'HTTP') logins.set(c.protocol, (logins.get(c.protocol) ?? 0) + c.count);
    for (const [protocol, count] of logins) findings.push({ id: 'cleartext_login', severity: 'medium', vars: { protocol, count } });
    const httpHosts = new Set([...this.cleartext.values()].filter((c) => c.protocol === 'HTTP' && classifyIP(c.server) === 'public').map((c) => c.host ?? c.server));
    if (httpHosts.size > 0) findings.push({ id: 'plain_http', severity: 'low', vars: { hosts: httpHosts.size, examples: [...httpHosts].slice(0, 3).join(', ') } });
    for (const [server, version] of this.weakTls) {
      findings.push({ id: 'weak_tls', severity: 'medium', vars: { server, version, name: [...(this.ipNames.get(server) ?? [])][0] ?? '' } });
    }
    for (const [client, names] of this.failedByClient) {
      if (names.size >= DNS_FAILURE_NAMES) findings.push({ id: 'dns_failures', severity: 'medium', vars: { client, names: names.size, examples: [...names].slice(0, 3).join(', ') } });
    }
    const rank: Record<FindingSeverity, number> = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => rank[a.severity] - rank[b.severity]);

    const byBytes = <T extends { bytes: number }>(a: T, b: T) => b.bytes - a.bytes;
    return {
      packets: this.packets,
      bytes: this.bytes,
      unreadable: this.unreadable,
      first: this.first,
      last: this.last,
      truncated: this.truncated,
      protocols: [...this.protocols].map(([name, v]) => ({ name, ...v })).sort(byBytes),
      devices: [...this.devices]
        .map(([mac, d]) => {
          const m = macInfo(mac);
          return { mac, maker: m ? { kind: m.kind, vendor: m.vendor } : null, ips: [...d.ips].sort(), names: [...d.names], packets: d.packets, bytesOut: d.bytesOut, bytesIn: d.bytesIn, first: d.first, last: d.last };
        })
        .filter((d) => d.packets > 0)
        .sort((a, b) => b.bytesOut + b.bytesIn - (a.bytesOut + a.bytesIn)),
      conversations: [...this.convs.values()].sort(byBytes).slice(0, TOP.conversations).map((c) => ({ ...c, name: c.name ?? [...(this.ipNames.get(c.server) ?? [])][0] ?? null })),
      external: [...this.external].map(([ip, v]) => ({ ip, ...v, names: [...(this.ipNames.get(ip) ?? [])] })).sort(byBytes).slice(0, TOP.external),
      dns: {
        queries: this.dnsQueries,
        failures: this.dnsFailures,
        names: [...this.dnsNames].map(([name, v]) => ({ name, count: v.count, failed: v.failed, types: [...v.types] })).sort((a, b) => b.count - a.count).slice(0, TOP.dns),
      },
      tls: [...this.tls].map(([name, v]) => ({ name, count: v.count, versions: [...v.versions] })).sort((a, b) => b.count - a.count).slice(0, TOP.tls),
      cleartext: [...this.cleartext.values()].sort((a, b) => b.count - a.count).slice(0, TOP.cleartext),
      findings,
      encryptedShare: this.classifiedBytes > 0 ? this.encryptedBytes / this.classifiedBytes : null,
    };
  }
}

/** Labels that only came from a port number and may be upgraded once the payload is seen. */
const PORT_LABELS = new Set(['HTTPS', 'HTTP', 'OTHER']);
