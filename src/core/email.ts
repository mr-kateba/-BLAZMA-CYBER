// Phishing email analysis (pure): parses a raw RFC 5322 / MIME message (.eml) and reports the facts
// that matter for "is this email trying to trick me?" — sender consistency, the authentication results
// recorded by the receiving mail server, where links really go, and risky attachments.
//
// SECURITY: the message is untrusted. Nothing is rendered or executed; HTML is only scanned with regular
// expressions for links. Sizes, part counts and nesting depth are capped.

import { createHash } from 'node:crypto';

export const MAX_EMAIL_BYTES = 25 * 1024 * 1024;
const MAX_PARTS = 200;
const MAX_DEPTH = 10;
const MAX_LINKS = 300;

export type Tone = 'red' | 'amber' | 'green';

export interface EmailSignal {
  key: string; // i18n: email.signal.*
  tone: Tone;
  vars?: Record<string, string | number>;
}

export interface EmailAddress {
  name: string | null;
  address: string | null;
  domain: string | null;
}

export interface EmailLink {
  text: string | null;
  href: string;
  host: string | null;
  flags: string[]; // i18n: email.linkFlag.*
}

export interface EmailAttachment {
  index: number;
  name: string;
  contentType: string;
  size: number;
  sha256: string;
  flags: string[]; // i18n: email.attFlag.*
}

export interface AuthResult {
  method: 'spf' | 'dkim' | 'dmarc';
  result: string; // pass, fail, softfail, neutral, none, temperror, permerror…
}

export interface ReceivedHop {
  from: string | null;
  by: string | null;
  date: string | null;
}

export interface EmailAnalysis {
  subject: string | null;
  date: string | null;
  messageId: string | null;
  from: EmailAddress | null;
  replyTo: EmailAddress | null;
  returnPath: EmailAddress | null;
  to: string | null;
  auth: AuthResult[];
  received: ReceivedHop[];
  links: EmailLink[];
  attachments: EmailAttachment[];
  textPreview: string;
  level: 'risky' | 'caution' | 'no_red_flags';
  signals: EmailSignal[];
}

interface Part {
  headers: Map<string, string[]>;
  body: Buffer;
}

// ---------------------------------------------------------------- low-level parsing

function splitHeadersBody(buf: Buffer): { head: string; body: Buffer } {
  const crlf = buf.indexOf('\r\n\r\n');
  const lf = buf.indexOf('\n\n');
  let cut = -1;
  let sep = 0;
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) {
    cut = crlf;
    sep = 4;
  } else if (lf >= 0) {
    cut = lf;
    sep = 2;
  }
  if (cut < 0) return { head: buf.toString('latin1'), body: Buffer.alloc(0) };
  return { head: buf.subarray(0, cut).toString('latin1'), body: buf.subarray(cut + sep) };
}

function parseHeaders(head: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const unfolded = head.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    map.set(k, [...(map.get(k) ?? []), v]);
  }
  return map;
}

function decodeCharset(bytes: Buffer, charset: string | null): string {
  const cs = (charset || 'utf-8').toLowerCase().replace(/^(x-|cp)/, (m) => (m === 'cp' ? 'windows-' : ''));
  try {
    return new TextDecoder(cs, { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }
}

/** RFC 2047 encoded words: =?charset?B|Q?text?= */
export function decodeWords(v: string): string {
  return v
    .replace(/\?=\s+=\?/g, '?==?')
    .replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_, cs: string, enc: string, text: string) => {
      const bytes =
        enc.toUpperCase() === 'B'
          ? Buffer.from(text, 'base64')
          : Buffer.from(text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return decodeCharset(bytes, cs.split('*')[0] ?? null);
    });
}

function headerParams(v: string): { value: string; params: Record<string, string> } {
  const [first, ...rest] = v.split(';');
  const params: Record<string, string> = {};
  for (const p of rest) {
    const i = p.indexOf('=');
    if (i < 0) continue;
    const k = p.slice(0, i).trim().toLowerCase();
    let val = p.slice(i + 1).trim();
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
    // RFC 2231: filename*=utf-8''name%20x
    if (k.endsWith('*')) {
      const m = /^([^']*)'[^']*'(.*)$/.exec(val);
      if (m) {
        // %XX are raw bytes in the declared charset (e.g. UTF-8 Arabic names).
        const bytes = Buffer.from(m[2]!.replace(/%([0-9A-Fa-f]{2})/g, (_x, h: string) => String.fromCharCode(parseInt(h, 16))), 'latin1');
        val = decodeCharset(bytes, m[1] || 'utf-8');
      }
      params[k.slice(0, -1)] = val;
    } else params[k] ??= decodeWords(val);
  }
  return { value: (first ?? '').trim().toLowerCase(), params };
}

function decodeBody(body: Buffer, cte: string): Buffer {
  const enc = cte.trim().toLowerCase();
  if (enc === 'base64') return Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (enc === 'quoted-printable') {
    const s = body.toString('latin1').replace(/=\r?\n/g, '');
    return Buffer.from(s.replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16))), 'latin1');
  }
  return body;
}

function walk(buf: Buffer, depth: number, out: Part[]): void {
  if (out.length >= MAX_PARTS || depth > MAX_DEPTH) return;
  const { head, body } = splitHeadersBody(buf);
  const headers = parseHeaders(head);
  const ct = headerParams(headers.get('content-type')?.[0] ?? 'text/plain');
  if (ct.value.startsWith('multipart/') && ct.params.boundary) {
    const b = `--${ct.params.boundary}`;
    const text = body.toString('latin1');
    const pieces = text.split(b).slice(1);
    for (const piece of pieces) {
      if (piece.startsWith('--')) break;
      walk(Buffer.from(piece.replace(/^\r?\n/, ''), 'latin1'), depth + 1, out);
      if (out.length >= MAX_PARTS) break;
    }
    return;
  }
  if (ct.value === 'message/rfc822' && depth < MAX_DEPTH) {
    walk(decodeBody(body, headers.get('content-transfer-encoding')?.[0] ?? ''), depth + 1, out);
    return;
  }
  out.push({ headers, body: decodeBody(body, headers.get('content-transfer-encoding')?.[0] ?? '') });
}

export function parseAddress(v: string | undefined): EmailAddress | null {
  if (!v) return null;
  const s = decodeWords(v).trim();
  const angle = /^(.*?)<([^>]*)>/.exec(s);
  let name: string | null = null;
  let address: string | null = null;
  if (angle) {
    name = angle[1]!.trim().replace(/^"|"$/g, '').trim() || null;
    address = angle[2]!.trim() || null;
  } else {
    const m = /[^\s<>"]+@[^\s<>"]+/.exec(s);
    address = m ? m[0] : null;
    name = address ? null : s || null;
  }
  const domain = address && address.includes('@') ? address.slice(address.lastIndexOf('@') + 1).toLowerCase().replace(/[>.\s]+$/, '') : null;
  return { name, address, domain };
}

const htmlDecode = (s: string) =>
  s
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_m, d: string) => String.fromCodePoint(Number(d)));

function hostOf(href: string): string | null {
  try {
    const u = new URL(href);
    return u.hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** Registrable-ish domain: last two labels (three for common second-level TLDs like co.uk / com.sa). */
export function baseDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const sld = parts[parts.length - 2]!;
  const tld = parts[parts.length - 1]!;
  const n = tld.length === 2 && /^(co|com|net|org|gov|edu|ac|gob|or|ne)$/.test(sld) ? 3 : 2;
  return parts.slice(-n).join('.');
}

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 't.ly', 'rb.gy', 'tiny.cc', 'buff.ly']);

export function linkFlags(href: string, text: string | null): string[] {
  const flags: string[] = [];
  const lower = href.trim().toLowerCase();
  if (/^(javascript|data|vbscript):/.test(lower)) return ['script'];
  let u: URL | null = null;
  try {
    u = new URL(href);
  } catch {
    return ['invalid'];
  }
  const host = u.hostname.toLowerCase();
  if (u.username || u.password) flags.push('userinfo');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) flags.push('ip');
  if (host.split('.').some((l) => l.startsWith('xn--'))) flags.push('punycode');
  if (SHORTENERS.has(host)) flags.push('shortener');
  if (u.protocol === 'http:') flags.push('http');
  // The visible text shows a different site than the real destination.
  const shown = text?.trim().toLowerCase().match(/(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,})(?:[/:?#]|\s|$)/);
  if (shown && shown[1] && baseDomain(shown[1]) !== baseDomain(host)) flags.push('mismatch');
  return flags;
}

function extractLinks(html: string[], texts: string[]): EmailLink[] {
  const links: EmailLink[] = [];
  const seen = new Set<string>();
  const add = (href: string, text: string | null) => {
    const h = htmlDecode(href).trim();
    if (!h || h.startsWith('#') || /^mailto:|^tel:|^cid:/i.test(h)) return;
    const key = `${h}\u0000${text ?? ''}`;
    if (seen.has(key) || links.length >= MAX_LINKS) return;
    seen.add(key);
    links.push({ text, href: h, host: hostOf(h), flags: linkFlags(h, text) });
  };
  for (const doc of html) {
    for (const m of doc.matchAll(/<a\b[^>]*?\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi)) {
      const href = m[2] ?? m[3] ?? m[4] ?? '';
      const text = htmlDecode((m[5] ?? '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 200) || null;
      add(href, text);
    }
  }
  for (const t of texts) for (const m of t.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)) add(m[0], null);
  return links;
}

const DANGEROUS = /\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|cpl|jar|ps1|psm1|lnk|reg|dll|chm|appx|msix|scf|url|iqy|one)$/i;
const MACRO = /\.(docm|xlsm|pptm|dotm|xltm|xlam|ppsm)$/i;
const CONTAINER = /\.(zip|rar|7z|gz|tar|cab|iso|img|vhd|vhdx|ace|arj)$/i;
const HTML = /\.(html?|shtml|xhtml|svg)$/i;

export function attachmentFlags(name: string): string[] {
  const f: string[] = [];
  const n = name.toLowerCase().trim();
  if (DANGEROUS.test(n)) f.push('executable');
  if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf)\.[a-z0-9]{2,5}$/i.test(n) && DANGEROUS.test(n)) f.push('double_extension');
  if (/[‮‭]/.test(name)) f.push('rtlo');
  if (MACRO.test(n)) f.push('macro');
  if (CONTAINER.test(n)) f.push('container');
  if (HTML.test(n)) f.push('html');
  return f;
}

function authResults(headers: Map<string, string[]>): AuthResult[] {
  // The top-most Authentication-Results header was added by the final receiving server.
  const first = headers.get('authentication-results')?.[0] ?? headers.get('arc-authentication-results')?.[0];
  if (!first) return [];
  const out: AuthResult[] = [];
  for (const method of ['spf', 'dkim', 'dmarc'] as const) {
    const m = new RegExp(`\\b${method}=([a-z]+)`, 'i').exec(first);
    if (m) out.push({ method, result: m[1]!.toLowerCase() });
  }
  return out;
}

function receivedHops(headers: Map<string, string[]>): ReceivedHop[] {
  return (headers.get('received') ?? []).slice(0, 30).map((r) => {
    const from = /\bfrom\s+([^\s;()]+)/i.exec(r)?.[1] ?? null;
    const by = /\bby\s+([^\s;()]+)/i.exec(r)?.[1] ?? null;
    const dateRaw = r.includes(';') ? r.slice(r.lastIndexOf(';') + 1).trim() : null;
    const d = dateRaw ? new Date(dateRaw) : null;
    return { from, by, date: d && !Number.isNaN(d.getTime()) ? d.toISOString() : null };
  });
}

// ---------------------------------------------------------------- analysis

/** `maxBytes` is larger only for messages rebuilt from .msg files (attachments grow ~4/3 as base64). */
export function analyzeEmail(raw: Buffer, maxBytes = MAX_EMAIL_BYTES): EmailAnalysis {
  if (raw.length > maxBytes) throw Object.assign(new Error('email_too_large'), { code: 'email_too_large' });
  const { head } = splitHeadersBody(raw);
  const headers = parseHeaders(head);
  if (!headers.has('from') && !headers.has('subject') && !headers.has('received')) {
    throw Object.assign(new Error('not_an_email'), { code: 'not_an_email' });
  }
  const parts: Part[] = [];
  walk(raw, 0, parts);

  const html: string[] = [];
  const texts: string[] = [];
  const attachments: EmailAttachment[] = [];
  for (const p of parts) {
    const ct = headerParams(p.headers.get('content-type')?.[0] ?? 'text/plain');
    const cd = headerParams(p.headers.get('content-disposition')?.[0] ?? '');
    const name = cd.params.filename ?? ct.params.name ?? null;
    const isAttachment = cd.value === 'attachment' || (name !== null && !ct.value.startsWith('text/'));
    if (isAttachment || (name && cd.value !== 'inline')) {
      const n = name ?? 'attachment';
      attachments.push({
        index: attachments.length,
        name: n,
        contentType: ct.value || 'application/octet-stream',
        size: p.body.length,
        sha256: createHash('sha256').update(p.body).digest('hex'),
        flags: attachmentFlags(n),
      });
    } else if (ct.value === 'text/html') html.push(decodeCharset(p.body, ct.params.charset ?? null));
    else if (ct.value.startsWith('text/')) texts.push(decodeCharset(p.body, ct.params.charset ?? null));
  }

  const h = (k: string) => (headers.get(k)?.[0] !== undefined ? decodeWords(headers.get(k)![0]!) : null);
  const from = parseAddress(headers.get('from')?.[0]);
  const replyTo = parseAddress(headers.get('reply-to')?.[0]);
  const returnPath = parseAddress(headers.get('return-path')?.[0]);
  const auth = authResults(headers);
  const links = extractLinks(html, texts);
  const plain = texts.join('\n').trim() || htmlDecode(html.join('\n').replace(/<style[\s\S]*?<\/style>|<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();

  // ---- signals
  const s: EmailSignal[] = [];
  const res = (m: AuthResult['method']) => auth.find((a) => a.method === m)?.result ?? null;
  const dmarc = res('dmarc');
  const spf = res('spf');
  const dkim = res('dkim');
  if (auth.length === 0) s.push({ key: 'noAuth', tone: 'amber' });
  if (dmarc === 'fail') s.push({ key: 'dmarcFail', tone: 'red' });
  else if (dmarc === 'pass') s.push({ key: 'dmarcPass', tone: 'green' });
  if (spf === 'fail' || spf === 'softfail') s.push({ key: 'spfFail', tone: dmarc === 'pass' ? 'amber' : 'red', vars: { result: spf } });
  if (dkim === 'fail') s.push({ key: 'dkimFail', tone: 'amber' });

  // Display name pretends to be another address ("support@bank.com" <x@evil.example>)
  const nameAddr = from?.name?.match(/[^\s<>"]+@([^\s<>"]+)/);
  if (nameAddr && from?.domain && baseDomain(nameAddr[1]!.toLowerCase()) !== baseDomain(from.domain)) {
    s.push({ key: 'displayNameSpoof', tone: 'red', vars: { shown: nameAddr[0], real: from.address ?? '' } });
  }
  if (replyTo?.domain && from?.domain && baseDomain(replyTo.domain) !== baseDomain(from.domain)) {
    s.push({ key: 'replyToDiffers', tone: 'amber', vars: { replyTo: replyTo.address ?? '' } });
  }
  if (returnPath?.domain && from?.domain && baseDomain(returnPath.domain) !== baseDomain(from.domain) && dmarc !== 'pass') {
    s.push({ key: 'returnPathDiffers', tone: 'amber', vars: { returnPath: returnPath.domain } });
  }

  const redLinkFlags = new Set(['mismatch', 'ip', 'userinfo', 'script']);
  const badLinks = links.filter((l) => l.flags.some((f) => redLinkFlags.has(f)));
  const cautionLinks = links.filter((l) => !badLinks.includes(l) && l.flags.some((f) => ['punycode', 'shortener', 'http'].includes(f)));
  if (badLinks.length) s.push({ key: 'deceptiveLinks', tone: 'red', vars: { count: badLinks.length } });
  if (cautionLinks.length) s.push({ key: 'suspiciousLinks', tone: 'amber', vars: { count: cautionLinks.length } });

  const dangerAtt = attachments.filter((a) => a.flags.some((f) => ['executable', 'double_extension', 'rtlo'].includes(f)));
  const riskyAtt = attachments.filter((a) => !dangerAtt.includes(a) && a.flags.some((f) => ['macro', 'container', 'html'].includes(f)));
  if (dangerAtt.length) s.push({ key: 'dangerousAttachment', tone: 'red', vars: { names: dangerAtt.map((a) => a.name).join(', ') } });
  if (riskyAtt.length) s.push({ key: 'riskyAttachment', tone: 'amber', vars: { names: riskyAtt.map((a) => a.name).join(', ') } });

  const order: Record<Tone, number> = { red: 0, amber: 1, green: 2 };
  s.sort((a, b) => order[a.tone] - order[b.tone]);
  const level = s.some((x) => x.tone === 'red') ? 'risky' : s.some((x) => x.tone === 'amber') ? 'caution' : 'no_red_flags';

  const date = h('date');
  const d = date ? new Date(date) : null;
  return {
    subject: h('subject'),
    date: d && !Number.isNaN(d.getTime()) ? d.toISOString() : null,
    messageId: h('message-id'),
    from,
    replyTo,
    returnPath,
    to: h('to'),
    auth,
    received: receivedHops(headers),
    links,
    attachments,
    textPreview: plain.slice(0, 2000),
    level,
    signals: s,
  };
}

/** Returns the decoded bytes of one attachment (for local static analysis). */
export function attachmentBytes(raw: Buffer, index: number): { name: string; bytes: Buffer } | null {
  const parts: Part[] = [];
  walk(raw, 0, parts);
  let i = 0;
  for (const p of parts) {
    const ct = headerParams(p.headers.get('content-type')?.[0] ?? 'text/plain');
    const cd = headerParams(p.headers.get('content-disposition')?.[0] ?? '');
    const name = cd.params.filename ?? ct.params.name ?? null;
    const isAttachment = cd.value === 'attachment' || (name !== null && !ct.value.startsWith('text/'));
    if (isAttachment || (name && cd.value !== 'inline')) {
      if (i === index) return { name: name ?? 'attachment', bytes: p.body };
      i++;
    }
  }
  return null;
}
