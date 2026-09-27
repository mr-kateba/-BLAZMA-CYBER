// Application-protocol parsers for captured traffic (pure). Adapted from blazma.nt (MIT, same
// author). Only what a protocol sends in the clear is read:
//  - DNS / mDNS names and answers
//  - DHCP message type, client MAC, requested address and host name (option 12)
//  - TLS: ClientHello SNI and version, ServerHello version, and — for TLS ≤ 1.2, where it is not
//    encrypted — certificate common names. Nothing is ever decrypted.
//  - HTTP: request line / status line and an ALLOWLIST of non-sensitive headers. Cookies,
//    authorization headers, query strings and bodies never enter the result.

import { ipv4At, ipv6At, macAt, printable, text, u16, u32, u8 } from './bytes';

// ------------------------------------------------------------------------------------------ DNS

export interface DnsInfo {
  isResponse: boolean;
  rcode: string;
  questions: Array<{ name: string; type: string }>;
  answers: Array<{ name: string; type: string; data: string }>;
}

const DNS_TYPES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY',
};
const RCODES: Record<number, string> = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

/** Reads a (possibly compressed) DNS name; guards against pointer loops. */
function readName(b: Uint8Array, start: number): { name: string; next: number } {
  const labels: string[] = [];
  let off = start;
  let next = -1;
  let jumps = 0;
  while (off < b.length) {
    const len = u8(b, off);
    if (len === 0) {
      off += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= b.length) break;
      const ptr = ((len & 0x3f) << 8) | u8(b, off + 1);
      if (next < 0) next = off + 2;
      if (++jumps > 16 || ptr >= b.length || ptr === off) break;
      off = ptr;
      continue;
    }
    if (len > 63 || off + 1 + len > b.length) break;
    labels.push(text(b, off + 1, off + 1 + len));
    off += 1 + len;
  }
  return { name: labels.join('.').toLowerCase(), next: next >= 0 ? next : off };
}

export function parseDns(b: Uint8Array): DnsInfo | null {
  if (b.length < 12) return null;
  const flags = u16(b, 2);
  const qd = u16(b, 4);
  const an = u16(b, 6);
  if (((flags >> 11) & 0x0f) > 5 || qd > 64 || an > 128) return null;
  let off = 12;
  const questions: DnsInfo['questions'] = [];
  for (let i = 0; i < qd && off < b.length; i++) {
    const { name, next } = readName(b, off);
    off = next;
    if (off + 4 > b.length) return null;
    const type = u16(b, off);
    off += 4;
    const n = printable(name);
    if (n) questions.push({ name: n, type: DNS_TYPES[type] ?? `TYPE${type}` });
  }
  const answers: DnsInfo['answers'] = [];
  for (let i = 0; i < an && off < b.length; i++) {
    const owner = readName(b, off);
    off = owner.next;
    if (off + 10 > b.length) break;
    const type = u16(b, off);
    const rdlen = u16(b, off + 8);
    off += 10;
    if (off + rdlen > b.length) break;
    let data = '';
    if (type === 1 && rdlen === 4) data = ipv4At(b, off);
    else if (type === 28 && rdlen === 16) data = ipv6At(b, off);
    else if (type === 5 || type === 12 || type === 2) data = printable(readName(b, off).name) ?? '';
    off += rdlen;
    const name = printable(owner.name);
    if (name) answers.push({ name, type: DNS_TYPES[type] ?? `TYPE${type}`, data });
  }
  if (questions.length === 0 && answers.length === 0) return null;
  return { isResponse: (flags & 0x8000) !== 0, rcode: RCODES[flags & 0x0f] ?? `RCODE${flags & 0x0f}`, questions, answers };
}

// ----------------------------------------------------------------------------------------- DHCP

export interface DhcpInfo {
  messageType: string;
  clientMac: string | null;
  requestedIp: string | null;
  /** Address the server offers/acknowledges (yiaddr). */
  yourIp: string | null;
  /** Option 54: the DHCP server that answered. */
  serverId: string | null;
  hostname: string | null;
}

const DHCP_TYPES: Record<number, string> = { 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM' };

export function parseDhcp(b: Uint8Array): DhcpInfo | null {
  if (b.length < 240) return null;
  const op = u8(b, 0);
  if ((op !== 1 && op !== 2) || u32(b, 236) !== 0x63825363) return null;
  const yiaddr = ipv4At(b, 16);
  const info: DhcpInfo = {
    messageType: 'UNKNOWN',
    clientMac: u8(b, 2) === 6 ? macAt(b, 28) : null,
    requestedIp: null,
    yourIp: yiaddr === '0.0.0.0' ? null : yiaddr,
    serverId: null,
    hostname: null,
  };
  let off = 240;
  while (off < b.length) {
    const code = u8(b, off);
    if (code === 255) break;
    if (code === 0) {
      off++;
      continue;
    }
    const len = u8(b, off + 1);
    const v = off + 2;
    if (v + len > b.length) break;
    if (code === 53 && len === 1) info.messageType = DHCP_TYPES[u8(b, v)] ?? 'UNKNOWN';
    else if (code === 50 && len === 4) info.requestedIp = ipv4At(b, v);
    else if (code === 54 && len === 4) info.serverId = ipv4At(b, v);
    else if (code === 12) info.hostname = printable(text(b, v, v + len), 63);
    off = v + len;
  }
  return info;
}

// ------------------------------------------------------------------------------------------ TLS

export interface TlsInfo {
  kind: 'client-hello' | 'server-hello' | 'certificate' | 'other';
  /** Negotiated or offered protocol version. */
  version: string | null;
  sni: string | null;
  certSubject: string | null;
  certIssuer: string | null;
}

const TLS_VERSIONS: Record<number, string> = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };

export function looksLikeTls(b: Uint8Array): boolean {
  if (b.length < 5) return false;
  const type = u8(b, 0);
  if (type < 20 || type > 23 || u8(b, 1) !== 3 || u8(b, 2) > 4) return false;
  const len = u16(b, 3);
  return len > 0 && len <= 18432;
}

/** Walks the extensions block; returns SNI and, when present, the supported_versions maximum. */
function readExtensions(b: Uint8Array, start: number, len: number, serverHello: boolean): { sni: string | null; version: number | null } {
  let off = start;
  const end = Math.min(start + len, b.length);
  let sni: string | null = null;
  let version: number | null = null;
  while (off + 4 <= end) {
    const type = u16(b, off);
    const elen = u16(b, off + 2);
    const v = off + 4;
    if (type === 0 && !serverHello && v + 5 <= end) {
      const nlen = u16(b, v + 3);
      if (nlen > 0 && nlen <= 253 && v + 5 + nlen <= end) {
        const name = text(b, v + 5, v + 5 + nlen);
        sni = /^[A-Za-z0-9.\-_*]+$/.test(name) ? name.toLowerCase() : null;
      }
    } else if (type === 43) {
      // supported_versions: ServerHello carries the chosen version; ClientHello a list.
      if (serverHello && elen === 2) version = u16(b, v);
      else if (!serverHello) {
        const listLen = u8(b, v);
        for (let i = 1; i + 1 <= listLen && v + i + 1 < end; i += 2) {
          const ver = u16(b, v + i);
          if ((ver & 0x0f0f) !== 0x0a0a && (version === null || ver > version)) version = ver; // skip GREASE
        }
      }
    }
    off = v + elen;
  }
  return { sni, version };
}

function commonNames(b: Uint8Array, start: number, end: number): string[] {
  const found: string[] = [];
  for (let i = start; i + 7 < end && found.length < 4; i++) {
    if (u8(b, i) === 0x06 && u8(b, i + 1) === 0x03 && u8(b, i + 2) === 0x55 && u8(b, i + 3) === 0x04 && u8(b, i + 4) === 0x03) {
      const tag = u8(b, i + 5);
      if (tag !== 0x13 && tag !== 0x0c && tag !== 0x16) continue;
      const len = u8(b, i + 6);
      if (len === 0 || len > 100 || i + 7 + len > end) continue;
      const v = printable(text(b, i + 7, i + 7 + len), 100);
      if (v) found.push(v);
      i += 6 + len;
    }
  }
  return found;
}

export function parseTls(b: Uint8Array): TlsInfo | null {
  if (!looksLikeTls(b)) return null;
  const empty: TlsInfo = { kind: 'other', version: null, sni: null, certSubject: null, certIssuer: null };
  if (u8(b, 0) !== 22) return empty;
  const end = Math.min(5 + u16(b, 3), b.length);
  const hsType = u8(b, 5);
  if (hsType === 1 || hsType === 2) {
    let off = 9; // record header (5) + handshake header (4)
    if (off + 34 > end) return { ...empty, kind: hsType === 1 ? 'client-hello' : 'server-hello' };
    const legacy = u16(b, off);
    off += 34; // version + random
    off += 1 + u8(b, off); // session id
    if (hsType === 1) {
      off += 2 + u16(b, off); // cipher suites
      off += 1 + u8(b, off); // compression methods
    } else off += 3; // chosen cipher suite + compression method
    const ext = off + 2 <= end ? readExtensions(b, off + 2, u16(b, off), hsType === 2) : { sni: null, version: null };
    const ver = hsType === 2 ? (ext.version ?? legacy) : Math.max(ext.version ?? 0, legacy);
    return { ...empty, kind: hsType === 1 ? 'client-hello' : 'server-hello', version: TLS_VERSIONS[ver] ?? null, sni: ext.sni };
  }
  if (hsType === 11) {
    // Certificate (TLS ≤ 1.2 only — TLS 1.3 encrypts it). DER lists the issuer before the subject.
    const names = commonNames(b, 5, end);
    return { ...empty, kind: 'certificate', certIssuer: names[0] ?? null, certSubject: names[1] ?? null };
  }
  return empty;
}

// ----------------------------------------------------------------------------------------- HTTP

export interface HttpInfo {
  kind: 'request' | 'response';
  method: string | null;
  /** Path without the query string (which often carries tokens). */
  path: string | null;
  status: number | null;
  host: string | null;
  userAgent: string | null;
  contentType: string | null;
  server: string | null;
  /** True when anything was withheld (query, non-allowlisted headers, body). */
  redacted: boolean;
}

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT'];

export function looksLikeHttp(b: Uint8Array): boolean {
  if (b.length < 6) return false;
  const head = text(b, 0, 8);
  return head.startsWith('HTTP/1') || METHODS.some((m) => head.startsWith(`${m} `));
}

export function parseHttp(b: Uint8Array): HttpInfo | null {
  if (!looksLikeHttp(b)) return null;
  const t = text(b, 0, 8192);
  const headEnd = t.indexOf('\r\n\r\n');
  const lines = (headEnd < 0 ? t : t.slice(0, headEnd)).split('\r\n');
  const first = lines[0] ?? '';
  const info: HttpInfo = { kind: 'request', method: null, path: null, status: null, host: null, userAgent: null, contentType: null, server: null, redacted: headEnd >= 0 && b.length > headEnd + 4 };
  if (first.startsWith('HTTP/')) {
    info.kind = 'response';
    const s = Number(first.split(' ')[1]);
    info.status = Number.isInteger(s) ? s : null;
  } else {
    const [method, raw] = first.split(' ');
    if (!method || !METHODS.includes(method)) return null;
    info.method = method;
    const p = raw ?? '/';
    const q = p.indexOf('?');
    info.path = (q < 0 ? p : p.slice(0, q)).slice(0, 300);
    if (q >= 0) info.redacted = true;
  }
  for (const line of lines.slice(1)) {
    const c = line.indexOf(':');
    if (c <= 0) continue;
    const name = line.slice(0, c).trim().toLowerCase();
    const value = line.slice(c + 1).trim().slice(0, 200);
    if (name === 'host') info.host = printable(value) ?? null;
    else if (name === 'user-agent') info.userAgent = printable(value, 200);
    else if (name === 'content-type') info.contentType = printable(value, 100);
    else if (name === 'server') info.server = printable(value, 100);
    // Everything else (cookies, authorization, tokens…) is dropped without being stored.
    else info.redacted = true;
  }
  return info;
}
