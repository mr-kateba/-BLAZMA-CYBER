// Outlook .msg → MIME (pure). A .msg is a CFB container of MAPI properties (MS-OXMSG). We rebuild an
// RFC 5322 / MIME message from it so the existing phishing analysis (src/core/email.ts) runs unchanged:
//   • the original internet headers (PR_TRANSPORT_MESSAGE_HEADERS) when Outlook kept them — these carry
//     Received and Authentication-Results; otherwise From/To/Subject/Date are rebuilt from properties
//     (and the analysis honestly reports that no authentication results are present);
//   • the plain-text and HTML bodies; attachments byte-exact (base64); embedded messages recursively.
//
// SECURITY: untrusted input. Values we write into headers are stripped of CR/LF and encoded (RFC 2047 /
// RFC 2231), so a crafted subject or file name can't inject headers or MIME parts. The boundary is
// random per conversion and never appears inside base64 content.

import { randomBytes } from 'node:crypto';
import { CfbError, readCfb, type CfbEntry } from './cfb';

const MAX_EMBED_DEPTH = 3;

/** Top-level `__properties_version1.0` header sizes (MS-OXMSG 2.4). */
const PROPS_HEADER = { top: 32, embedded: 24, child: 8 } as const;

function childMap(e: CfbEntry): Map<string, CfbEntry> {
  return new Map(e.children.map((c) => [c.name.toUpperCase(), c]));
}

const ENCODINGS: Record<number, string> = {
  65001: 'utf-8', 1200: 'utf-16le', 20127: 'us-ascii', 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5',
  20866: 'koi8-r', 28591: 'iso-8859-1', 28592: 'iso-8859-2', 28595: 'iso-8859-5', 28596: 'iso-8859-6', 28597: 'iso-8859-7',
  28598: 'iso-8859-8', 28599: 'iso-8859-9', 28605: 'iso-8859-15', 50220: 'iso-2022-jp', 51932: 'euc-jp',
};

export function decodeCodepage(bytes: Buffer, cp: number | null): string {
  const label = cp === null ? 'windows-1252' : (ENCODINGS[cp] ?? (cp >= 874 && cp <= 1258 ? `windows-${cp}` : 'windows-1252'));
  try {
    return new TextDecoder(label, { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder('windows-1252', { fatal: false }).decode(bytes);
  }
}

class PropertyBag {
  private readonly streams: Map<string, CfbEntry>;
  private readonly fixed = new Map<number, Buffer>(); // property id → 8-byte value

  constructor(readonly storage: CfbEntry, headerSize: number) {
    this.streams = childMap(storage);
    const props = this.streams.get('__PROPERTIES_VERSION1.0');
    if (props) {
      const b = props.data();
      for (let off = headerSize; off + 16 <= b.length; off += 16) this.fixed.set(b.readUInt32LE(off) >>> 16, b.subarray(off + 8, off + 16));
    }
  }

  private stream(id: number, type: string): Buffer | null {
    const s = this.streams.get(`__SUBSTG1.0_${id.toString(16).toUpperCase().padStart(4, '0')}${type}`);
    return s && s.kind === 'stream' ? s.data() : null;
  }

  storageOf(id: number, type: string): CfbEntry | null {
    const s = this.streams.get(`__SUBSTG1.0_${id.toString(16).toUpperCase().padStart(4, '0')}${type}`);
    return s && s.kind === 'storage' ? s : null;
  }

  int(id: number): number | null {
    const v = this.fixed.get(id);
    return v ? v.readInt32LE(0) : null;
  }

  /** PT_SYSTIME (FILETIME, 100 ns since 1601) → Date. */
  time(id: number): Date | null {
    const v = this.fixed.get(id);
    if (!v) return null;
    const ms = (v.readUInt32LE(4) * 2 ** 32 + v.readUInt32LE(0)) / 10_000 - 11_644_473_600_000;
    const d = new Date(ms);
    return Number.isFinite(ms) && ms > 0 && !Number.isNaN(d.getTime()) ? d : null;
  }

  str(id: number, codepage: number | null): string | null {
    const u = this.stream(id, '001F');
    if (u) return u.toString('utf16le').replace(/\0+$/, '');
    const a = this.stream(id, '001E');
    return a ? decodeCodepage(a, codepage).replace(/\0+$/, '') : null;
  }

  bin(id: number): Buffer | null {
    return this.stream(id, '0102');
  }

  children(prefix: string): CfbEntry[] {
    return [...this.streams.entries()].filter(([k, v]) => k.startsWith(prefix) && v.kind === 'storage').map(([, v]) => v);
  }
}

// ---------------------------------------------------------------- header helpers

const oneLine = (s: string) => s.replace(/[\r\n\0]+/g, ' ').trim();

/** RFC 2047 B-encoding when needed (non-ASCII or characters that would break the header). */
function encodeWord(s: string): string {
  const v = oneLine(s);
  return /^[\x20-\x7e]*$/.test(v) && !/=\?/.test(v) ? v : `=?UTF-8?B?${Buffer.from(v, 'utf8').toString('base64')}?=`;
}

function formatAddress(name: string | null, address: string | null): string | null {
  const addr = address ? oneLine(address).replace(/[<>"\s,;]/g, '') : '';
  const n = name ? oneLine(name).replace(/[<>"]/g, '') : '';
  if (!addr && !n) return null;
  if (!addr) return encodeWord(n);
  return n && n !== addr ? `"${encodeWord(n)}" <${addr}>` : `<${addr}>`;
}

/** RFC 2231 file name parameter (UTF-8, percent-encoded). */
function fileNameParam(name: string): string {
  const clean = oneLine(name).slice(0, 255) || 'attachment';
  return `filename*=utf-8''${encodeURIComponent(clean).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

/** Keeps the original internet headers but drops the MIME structure fields we rebuild ourselves. */
function cleanTransportHeaders(raw: string): string[] {
  const lines = raw.replace(/\0+$/, '').split(/\r?\n/);
  const out: string[] = [];
  let skipping = false;
  for (const line of lines) {
    if (!line.trim()) continue; // a blank line would end the header block early
    if (/^[ \t]/.test(line)) {
      if (!skipping && out.length) out.push(line);
      continue;
    }
    skipping = /^(content-type|content-transfer-encoding|content-disposition|mime-version)\s*:/i.test(line) || !line.includes(':');
    if (!skipping) out.push(line);
  }
  return out;
}

const b64lines = (b: Buffer) => (b.toString('base64').match(/.{1,76}/g) ?? []).join('\r\n');

function part(headers: string[], body: Buffer): string {
  return `${headers.join('\r\n')}\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64lines(body)}\r\n`;
}

// ---------------------------------------------------------------- conversion

function convert(storage: CfbEntry, headerSize: number, depth: number): string {
  const p = new PropertyBag(storage, headerSize);
  const cp = p.int(0x3ffd) ?? p.int(0x3fde); // PR_MESSAGE_CODEPAGE, PR_INTERNET_CPID
  const isMessage = p.str(0x001a, cp) !== null || p.str(0x0037, cp) !== null || p.str(0x007d, cp) !== null || p.children('__RECIP_VERSION1.0_').length > 0;
  if (!isMessage) throw Object.assign(new Error('not_an_email'), { code: 'not_an_email' });

  // ---- headers
  const head: string[] = [];
  const transport = p.str(0x007d, cp);
  if (transport && transport.trim()) head.push(...cleanTransportHeaders(transport));
  const has = (name: string) => head.some((l) => l.toLowerCase().startsWith(`${name}:`));

  if (!has('from')) {
    const smtp = p.str(0x5d01, cp) ?? p.str(0x5d02, cp);
    const email = p.str(0x0c1f, cp) ?? p.str(0x0065, cp);
    const from = formatAddress(p.str(0x0c1a, cp) ?? p.str(0x0042, cp), smtp ?? (email && email.includes('@') ? email : null));
    if (from) head.push(`From: ${from}`);
  }
  if (!has('to') || !has('cc')) {
    const to: string[] = [];
    const cc: string[] = [];
    for (const r of p.children('__RECIP_VERSION1.0_')) {
      const rb = new PropertyBag(r, PROPS_HEADER.child);
      const smtp = rb.str(0x39fe, cp) ?? rb.str(0x3003, cp);
      const a = formatAddress(rb.str(0x3001, cp), smtp && smtp.includes('@') ? smtp : null);
      if (!a) continue;
      const type = rb.int(0x0c15);
      if (type === 2) cc.push(a);
      else if (type !== 3) to.push(a); // Bcc stays out, like in a received message
    }
    if (!has('to') && to.length) head.push(`To: ${to.join(', ')}`);
    else if (!has('to')) {
      const display = p.str(0x0e04, cp);
      if (display) head.push(`To: ${encodeWord(display)}`);
    }
    if (!has('cc') && cc.length) head.push(`Cc: ${cc.join(', ')}`);
  }
  if (!has('subject')) {
    const subject = p.str(0x0037, cp);
    if (subject !== null) head.push(`Subject: ${encodeWord(subject)}`);
  }
  if (!has('date')) {
    const d = p.time(0x0e06) ?? p.time(0x0039); // delivery time, submit time
    if (d) head.push(`Date: ${d.toUTCString().replace('GMT', '+0000')}`);
  }
  if (!has('message-id')) {
    const id = p.str(0x1035, cp);
    if (id) head.push(`Message-ID: ${oneLine(id)}`);
  }

  // ---- bodies and attachments
  const boundary = `=_blazma_msg_${randomBytes(12).toString('hex')}`;
  const parts: string[] = [];
  const text = p.str(0x1000, cp);
  if (text && text.trim()) parts.push(part(['Content-Type: text/plain; charset=utf-8'], Buffer.from(text, 'utf8')));
  const htmlBin = p.bin(0x1013);
  const html = htmlBin ? decodeCodepage(htmlBin, p.int(0x3fde) ?? cp ?? 65001) : p.str(0x1013, cp);
  if (html && html.trim()) parts.push(part(['Content-Type: text/html; charset=utf-8'], Buffer.from(html.replace(/\0+$/, ''), 'utf8')));

  for (const a of p.children('__ATTACH_VERSION1.0_')) {
    const ab = new PropertyBag(a, PROPS_HEADER.child);
    const name = ab.str(0x3707, cp) ?? ab.str(0x3704, cp) ?? ab.str(0x3001, cp) ?? 'attachment';
    const method = ab.int(0x3705);
    const embedded = ab.storageOf(0x3701, '000D');
    if (method === 5 && embedded) {
      // Attached email: nested as message/rfc822, so its links and attachments are analyzed too.
      if (depth >= MAX_EMBED_DEPTH) continue;
      const inner = convert(embedded, PROPS_HEADER.embedded, depth + 1);
      parts.push(`Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64lines(Buffer.from(inner, 'utf8'))}\r\n`);
      continue;
    }
    const data = ab.bin(0x3701);
    if (!data) continue; // OLE objects / references without stored bytes: nothing honest to report
    const mime = oneLine(ab.str(0x370e, cp) ?? '').toLowerCase();
    const type = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mime) ? mime : 'application/octet-stream';
    parts.push(part([`Content-Type: ${type}`, `Content-Disposition: attachment; ${fileNameParam(name)}`], data));
  }

  head.push('MIME-Version: 1.0', `Content-Type: multipart/mixed; boundary="${boundary}"`);
  return `${head.join('\r\n')}\r\n\r\n${parts.map((x) => `--${boundary}\r\n${x}`).join('')}--${boundary}--\r\n`;
}

/** Converts an Outlook .msg (CFB) buffer into an equivalent MIME message. */
export function msgToMime(buf: Buffer): Buffer {
  let root: CfbEntry;
  try {
    root = readCfb(buf);
  } catch (e) {
    if (e instanceof CfbError) throw e;
    throw new CfbError('unreadable');
  }
  return Buffer.from(convert(root, PROPS_HEADER.top, 0), 'utf8');
}
