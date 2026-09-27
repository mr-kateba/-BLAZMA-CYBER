// One captured frame → a structured summary (pure). Adapted from blazma.nt (MIT, same author).
// Never throws: a malformed frame yields a partial result, because a hostile or corrupt frame must
// not stop the analysis of a whole capture.

import { ipv4At, ipv6At, macAt, text, u16, u8 } from './bytes';
import { looksLikeHttp, looksLikeTls, parseDhcp, parseDns, parseHttp, parseTls, type DhcpInfo, type DnsInfo, type HttpInfo, type TlsInfo } from './protocols';

export const LINKTYPE = { NULL: 0, ETHERNET: 1, RAW: 101, LINUX_SLL: 113, IPV4: 228, IPV6: 229 } as const;

export type Transport = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'OTHER';

export interface ArpInfo {
  op: 'request' | 'reply' | 'other';
  senderMac: string;
  senderIp: string;
  targetIp: string;
}

export interface ParsedPacket {
  ts: number;
  wireLength: number;
  ethSrc: string | null;
  ethDst: string | null;
  network: 'IPv4' | 'IPv6' | 'ARP' | 'other';
  srcIp: string | null;
  dstIp: string | null;
  transport: Transport;
  srcPort: number;
  dstPort: number;
  syn: boolean;
  ack: boolean;
  rst: boolean;
  arp: ArpInfo | null;
  /** Application protocol label, e.g. "DNS", "TLS", "HTTP". */
  protocol: string;
  /** How the label was reached: packet contents, or only a well-known port. */
  confidence: 'header' | 'port' | 'none';
  /** true = known-encrypted (TLS, QUIC, SSH…), false = cleartext protocol, null = unknown. */
  encrypted: boolean | null;
  dns: DnsInfo | null;
  dhcp: DhcpInfo | null;
  tls: TlsInfo | null;
  http: HttpInfo | null;
}

const PORTS: Record<number, [string, boolean]> = {
  20: ['FTP-DATA', false], 21: ['FTP', false], 22: ['SSH', true], 23: ['Telnet', false], 25: ['SMTP', false],
  53: ['DNS', false], 67: ['DHCP', false], 68: ['DHCP', false], 69: ['TFTP', false], 80: ['HTTP', false],
  110: ['POP3', false], 123: ['NTP', false], 137: ['NetBIOS', false], 138: ['NetBIOS', false], 139: ['SMB', false],
  143: ['IMAP', false], 161: ['SNMP', false], 389: ['LDAP', false], 443: ['HTTPS', true], 445: ['SMB', false],
  465: ['SMTPS', true], 514: ['Syslog', false], 587: ['SMTP', false], 636: ['LDAPS', true], 853: ['DNS-over-TLS', true],
  993: ['IMAPS', true], 995: ['POP3S', true], 1194: ['OpenVPN', true], 1433: ['MSSQL', false], 1883: ['MQTT', false],
  1900: ['SSDP', false], 3306: ['MySQL', false], 3389: ['RDP', true], 5060: ['SIP', false], 5353: ['mDNS', false],
  5355: ['LLMNR', false], 5900: ['VNC', false], 8080: ['HTTP', false], 8443: ['HTTPS', true], 51820: ['WireGuard', true],
};

/** True for ports that name a well-known service (the server side of a conversation). */
export const isServicePort = (port: number): boolean => port in PORTS;

function empty(ts: number, wireLength: number): ParsedPacket {
  return {
    ts, wireLength, ethSrc: null, ethDst: null, network: 'other', srcIp: null, dstIp: null, transport: 'OTHER',
    srcPort: 0, dstPort: 0, syn: false, ack: false, rst: false, arp: null, protocol: 'OTHER', confidence: 'none',
    encrypted: null, dns: null, dhcp: null, tls: null, http: null,
  };
}

function byPort(p: ParsedPacket): void {
  const hint = PORTS[p.dstPort] ?? PORTS[p.srcPort];
  if (hint) {
    p.protocol = hint[0];
    p.confidence = 'port';
    p.encrypted = hint[1];
  } else p.protocol = p.transport;
}

function isQuic(b: Uint8Array, p: ParsedPacket): boolean {
  if (b.length < 5) return false;
  const first = u8(b, 0);
  if ((first & 0xc0) === 0xc0) {
    const v = u16(b, 1) * 65536 + u16(b, 3);
    return v === 1 || v === 0x6b3343cf || Math.floor(v / 256) === 0xff0000;
  }
  return (first & 0xc0) === 0x40 && (p.srcPort === 443 || p.dstPort === 443);
}

function app(p: ParsedPacket, payload: Uint8Array): void {
  const set = (protocol: string, encrypted: boolean) => {
    p.protocol = protocol;
    p.confidence = 'header';
    p.encrypted = encrypted;
  };
  if (payload.length === 0) return byPort(p);
  const port = (n: number) => p.srcPort === n || p.dstPort === n;
  if (p.transport === 'UDP') {
    if (port(53) || port(5353) || port(5355)) {
      const dns = parseDns(payload);
      if (dns) {
        p.dns = dns;
        return set(port(5353) ? 'mDNS' : port(5355) ? 'LLMNR' : 'DNS', false);
      }
    }
    if (port(67) || port(68)) {
      const dhcp = parseDhcp(payload);
      if (dhcp) {
        p.dhcp = dhcp;
        return set('DHCP', false);
      }
    }
    if (isQuic(payload, p)) return set('QUIC', true);
  }
  if (p.transport === 'TCP') {
    if (looksLikeTls(payload)) {
      p.tls = parseTls(payload);
      return set('TLS', true);
    }
    if (looksLikeHttp(payload)) {
      p.http = parseHttp(payload);
      if (p.http) return set('HTTP', false);
    }
    const head = text(payload, 0, 16);
    if (head.startsWith('SSH-')) return set('SSH', true);
    if (port(23) && u8(payload, 0) === 0xff) return set('Telnet', false);
    if (/^\d{3}[ -]/.test(head) || head.startsWith('* OK') || head.startsWith('+OK')) {
      const hint = PORTS[p.dstPort] ?? PORTS[p.srcPort];
      if (hint && !hint[1]) return set(hint[0], false);
    }
  }
  byPort(p);
}

function transport(p: ParsedPacket, b: Uint8Array, off: number, end: number, proto: number): void {
  if (proto === 6 && off + 20 <= b.length) {
    p.transport = 'TCP';
    p.srcPort = u16(b, off);
    p.dstPort = u16(b, off + 2);
    const flags = u8(b, off + 13);
    p.syn = (flags & 0x02) !== 0;
    p.rst = (flags & 0x04) !== 0;
    p.ack = (flags & 0x10) !== 0;
    const dataOff = (u8(b, off + 12) >> 4) * 4;
    if (dataOff >= 20) app(p, b.subarray(off + dataOff, Math.max(off + dataOff, Math.min(end, b.length))));
  } else if (proto === 17 && off + 8 <= b.length) {
    p.transport = 'UDP';
    p.srcPort = u16(b, off);
    p.dstPort = u16(b, off + 2);
    const ulen = u16(b, off + 4);
    app(p, b.subarray(off + 8, Math.max(off + 8, Math.min(ulen > 8 ? off + ulen : end, b.length))));
  } else if (proto === 1) {
    p.transport = 'ICMP';
    p.protocol = 'ICMP';
    p.confidence = 'header';
  } else if (proto === 58) {
    p.transport = 'ICMPv6';
    p.protocol = 'ICMPv6';
    p.confidence = 'header';
  } else p.protocol = 'OTHER';
}

function ipv4(p: ParsedPacket, b: Uint8Array, off: number): void {
  if (off + 20 > b.length) return;
  const ihl = (u8(b, off) & 0x0f) * 4;
  if (ihl < 20) return;
  p.network = 'IPv4';
  p.srcIp = ipv4At(b, off + 12);
  p.dstIp = ipv4At(b, off + 16);
  const total = u16(b, off + 2);
  // Only the first fragment carries the transport header.
  if ((u16(b, off + 6) & 0x1fff) !== 0) return;
  transport(p, b, off + ihl, total ? off + total : b.length, u8(b, off + 9));
}

function ipv6(p: ParsedPacket, b: Uint8Array, off: number): void {
  if (off + 40 > b.length) return;
  p.network = 'IPv6';
  p.srcIp = ipv6At(b, off + 8);
  p.dstIp = ipv6At(b, off + 24);
  let next = u8(b, off + 6);
  let cur = off + 40;
  const end = off + 40 + u16(b, off + 4);
  for (let guard = 0; (next === 0 || next === 43 || next === 60) && cur + 8 <= end && guard < 8; guard++) {
    next = u8(b, cur);
    cur += (u8(b, cur + 1) + 1) * 8;
  }
  transport(p, b, cur, end, next);
}

function arp(p: ParsedPacket, b: Uint8Array, off: number): void {
  if (off + 28 > b.length || u8(b, off + 4) !== 6 || u8(b, off + 5) !== 4) return;
  const op = u16(b, off + 6);
  p.network = 'ARP';
  p.transport = 'ARP';
  p.protocol = 'ARP';
  p.confidence = 'header';
  p.arp = { op: op === 1 ? 'request' : op === 2 ? 'reply' : 'other', senderMac: macAt(b, off + 8), senderIp: ipv4At(b, off + 14), targetIp: ipv4At(b, off + 24) };
  p.srcIp = p.arp.senderIp;
  p.dstIp = p.arp.targetIp;
}

function byEtherType(p: ParsedPacket, b: Uint8Array, type: number, off: number): void {
  if (type === 0x0800) ipv4(p, b, off);
  else if (type === 0x86dd) ipv6(p, b, off);
  else if (type === 0x0806) arp(p, b, off);
}

export function parsePacket(data: Uint8Array, ts: number, wireLength: number, linkType: number): ParsedPacket {
  const p = empty(ts, wireLength);
  try {
    if (linkType === LINKTYPE.ETHERNET) {
      if (data.length < 14) return p;
      p.ethDst = macAt(data, 0);
      p.ethSrc = macAt(data, 6);
      let type = u16(data, 12);
      let off = 14;
      for (let depth = 0; (type === 0x8100 || type === 0x88a8) && off + 4 <= data.length && depth < 2; depth++) {
        type = u16(data, off + 2);
        off += 4;
      }
      byEtherType(p, data, type, off);
    } else if (linkType === LINKTYPE.LINUX_SLL) {
      if (data.length < 16) return p;
      if (u16(data, 4) === 6) p.ethSrc = macAt(data, 6);
      byEtherType(p, data, u16(data, 14), 16);
    } else if (linkType === LINKTYPE.RAW || linkType === LINKTYPE.IPV4 || linkType === LINKTYPE.IPV6) {
      const v = u8(data, 0) >> 4;
      if (v === 4) ipv4(p, data, 0);
      else if (v === 6) ipv6(p, data, 0);
    } else if (linkType === LINKTYPE.NULL) {
      const family = data.length >= 4 ? (u8(data, 0) | (u8(data, 1) << 8)) : 0;
      if (family === 2) ipv4(p, data, 4);
      else if ([10, 23, 24, 28, 30].includes(family)) ipv6(p, data, 4);
    }
  } catch {
    // A partial result is fine — never let one bad frame escape as an exception.
  }
  return p;
}
