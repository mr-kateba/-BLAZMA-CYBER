// What does this QR code contain? (pure) — classifies the decoded text of a QR code (link, Wi-Fi
// login, 2FA setup code, payment request, phone/SMS/email, contact, plain text) and lists the facts a
// person should know before acting on it ("quishing": QR phishing on posters, parcels, parking meters).
//
// Nothing is opened or looked up here. Secrets inside a QR (Wi-Fi password, 2FA seed) are never
// returned — only the fact that the code contains one.

import { linkFlags } from './email';
import { classifyInput, type SmartAction } from './smart-input';

export type QrKind = 'url' | 'wifi' | 'otp' | 'payment' | 'email' | 'phone' | 'sms' | 'geo' | 'contact' | 'event' | 'text';
export type QrTone = 'red' | 'amber' | 'green';

export interface QrSignal {
  key: string; // i18n: qr.signal.*
  tone: QrTone;
  vars?: Record<string, string | number>;
}

export interface QrField {
  key: string; // i18n: qr.field.*
  value: string;
}

export interface QrContent {
  kind: QrKind;
  /** The decoded text, with secrets removed (null when the whole payload is a secret). */
  display: string | null;
  fields: QrField[];
  signals: QrSignal[];
  level: 'risky' | 'caution' | 'no_red_flags';
  /** Tools that can examine the content (pre-filled; the user starts them). */
  actions: SmartAction[];
}

const MAX = 4096;
const cut = (s: string, n = 300) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** Splits `KEY:value;KEY:value;;` payloads (WIFI:, MECARD:, MATMSG:) honoring backslash escapes. */
export function parseFieldList(body: string): Map<string, string> {
  const out = new Map<string, string>();
  let key = '';
  let val = '';
  let inKey = true;
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === '\\' && i + 1 < body.length) {
      if (inKey) key += body[++i];
      else val += body[++i];
    } else if (inKey && c === ':') inKey = false;
    else if (!inKey && c === ';') {
      if (key) out.set(key.toUpperCase(), val);
      key = '';
      val = '';
      inKey = true;
    } else if (inKey) key += c;
    else val += c;
  }
  if (key && !inKey) out.set(key.toUpperCase(), val);
  return out;
}

const CRYPTO_SCHEMES = /^(bitcoin|ethereum|litecoin|monero|dogecoin|bitcoincash|tron|solana|ripple|usdt|tether):/i;
const RISKY_LINK = new Set(['script', 'userinfo', 'ip', 'mismatch']);

function levelOf(signals: QrSignal[]): QrContent['level'] {
  return signals.some((s) => s.tone === 'red') ? 'risky' : signals.some((s) => s.tone === 'amber') ? 'caution' : 'no_red_flags';
}

function build(kind: QrKind, display: string | null, fields: QrField[], signals: QrSignal[], actions: SmartAction[] = []): QrContent {
  const order: Record<QrTone, number> = { red: 0, amber: 1, green: 2 };
  signals.sort((a, b) => order[a.tone] - order[b.tone]);
  return { kind, display, fields: fields.filter((f) => f.value !== ''), signals, level: levelOf(signals), actions };
}

function classifyUrl(text: string): QrContent {
  const flags = linkFlags(text, null);
  const signals: QrSignal[] = [];
  let host = '';
  try {
    host = new URL(text).hostname.toLowerCase();
  } catch {
    /* flags already say 'invalid' */
  }
  for (const f of flags) {
    if (f === 'invalid') continue;
    signals.push({ key: `link.${f}`, tone: RISKY_LINK.has(f) ? 'red' : 'amber', vars: { host } });
  }
  if (signals.length === 0) signals.push({ key: 'link.checkFirst', tone: 'green', vars: { host } });
  // Links to a bare IP aren't offered as links by the smart classifier; the IP itself still is.
  const actions = classifyInput(text)?.actions ?? (host ? classifyInput(host.replace(/^\[|\]$/g, ''))?.actions : undefined) ?? [];
  return build('url', cut(text, 2000), [{ key: 'host', value: host }], signals, actions);
}

export function classifyQrContent(raw: string): QrContent {
  const text = raw.replace(/\0/g, '').trim().slice(0, MAX);
  const lower = text.toLowerCase();

  if (/^https?:\/\//i.test(text)) return classifyUrl(text);

  if (/^(javascript|data|vbscript|file):/i.test(text)) {
    return build('url', cut(text), [], [{ key: 'link.script', tone: 'red', vars: { host: '' } }]);
  }

  if (lower.startsWith('wifi:')) {
    const f = parseFieldList(text.slice(5));
    const type = (f.get('T') ?? '').toUpperCase();
    const open = type === '' || type === 'NOPASS';
    const signals: QrSignal[] = [{ key: 'wifi.joins', tone: 'amber', vars: { ssid: f.get('S') ?? '' } }];
    if (open) signals.push({ key: 'wifi.open', tone: 'amber' });
    else if (type === 'WEP') signals.push({ key: 'wifi.wep', tone: 'amber' });
    return build('wifi', null, [
      { key: 'ssid', value: f.get('S') ?? '' },
      { key: 'security', value: open ? 'open' : type },
      { key: 'hidden', value: /^true$/i.test(f.get('H') ?? '') ? 'yes' : '' },
      { key: 'password', value: !open && f.get('P') ? 'present' : '' },
    ], signals);
  }

  if (lower.startsWith('otpauth://') || lower.startsWith('otpauth-migration://')) {
    let issuer = '';
    let account = '';
    try {
      const u = new URL(text);
      issuer = u.searchParams.get('issuer') ?? '';
      const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
      const i = label.indexOf(':');
      account = i >= 0 ? label.slice(i + 1).trim() : label;
      if (!issuer && i >= 0) issuer = label.slice(0, i).trim();
    } catch {
      /* keep empty */
    }
    return build('otp', null, [{ key: 'issuer', value: issuer }, { key: 'account', value: account }], [{ key: 'otp.secret', tone: 'red' }]);
  }

  if (CRYPTO_SCHEMES.test(text)) {
    const scheme = text.slice(0, text.indexOf(':')).toLowerCase();
    const rest = text.slice(scheme.length + 1).replace(/^\/\//, '');
    const [address = '', query = ''] = rest.split('?');
    const params = new URLSearchParams(query);
    return build('payment', cut(text), [
      { key: 'currency', value: scheme },
      { key: 'address', value: cut(address, 120) },
      { key: 'amount', value: params.get('amount') ?? params.get('value') ?? '' },
      { key: 'label', value: cut(params.get('label') ?? params.get('message') ?? '', 120) },
    ], [{ key: 'payment.irreversible', tone: 'amber' }]);
  }

  if (lower.startsWith('mailto:') || lower.startsWith('matmsg:')) {
    let to = '';
    let subject = '';
    if (lower.startsWith('mailto:')) {
      const [addr = '', q = ''] = text.slice(7).split('?');
      to = decodeURIComponent(addr);
      subject = new URLSearchParams(q).get('subject') ?? '';
    } else {
      const f = parseFieldList(text.slice(7));
      to = f.get('TO') ?? '';
      subject = f.get('SUB') ?? '';
    }
    const actions = classifyInput(to)?.actions ?? [];
    return build('email', cut(text), [{ key: 'to', value: cut(to, 200) }, { key: 'subject', value: cut(subject, 200) }], [{ key: 'email.compose', tone: 'green' }], actions);
  }

  if (lower.startsWith('tel:')) {
    return build('phone', cut(text), [{ key: 'number', value: cut(text.slice(4), 60) }], [{ key: 'phone.call', tone: 'green' }]);
  }

  if (lower.startsWith('smsto:') || lower.startsWith('sms:') || lower.startsWith('mmsto:')) {
    const body = text.slice(text.indexOf(':') + 1);
    let number = body;
    let message = '';
    if (lower.startsWith('sms:') && body.includes('?')) {
      number = body.slice(0, body.indexOf('?'));
      message = new URLSearchParams(body.slice(body.indexOf('?') + 1)).get('body') ?? '';
    } else if (body.includes(':')) {
      number = body.slice(0, body.indexOf(':'));
      message = body.slice(body.indexOf(':') + 1);
    }
    const short = /^\+?\d{3,6}$/.test(number.replace(/[\s-]/g, ''));
    const signals: QrSignal[] = [{ key: 'sms.sends', tone: 'amber' }];
    if (short) signals.push({ key: 'sms.shortCode', tone: 'amber' });
    return build('sms', cut(text), [{ key: 'number', value: cut(number, 60) }, { key: 'message', value: cut(message, 300) }], signals);
  }

  if (lower.startsWith('geo:')) {
    return build('geo', cut(text), [{ key: 'coordinates', value: cut(text.slice(4).split('?')[0] ?? '', 80) }], [{ key: 'geo.location', tone: 'green' }]);
  }

  if (lower.startsWith('begin:vcard') || lower.startsWith('mecard:')) {
    let name = '';
    if (lower.startsWith('mecard:')) name = parseFieldList(text.slice(7)).get('N') ?? '';
    else name = /^FN(?:;[^:]*)?:(.*)$/im.exec(text)?.[1]?.trim() ?? '';
    const signals: QrSignal[] = [{ key: 'contact.adds', tone: 'green' }];
    if (/^URL(?:;[^:]*)?:/im.test(text)) signals.push({ key: 'contact.hasLink', tone: 'amber' });
    return build('contact', cut(text, 1000), [{ key: 'name', value: cut(name, 120) }], signals);
  }

  if (lower.startsWith('begin:vevent') || lower.startsWith('begin:vcalendar')) {
    const summary = /^SUMMARY(?:;[^:]*)?:(.*)$/im.exec(text)?.[1]?.trim() ?? '';
    return build('event', cut(text, 1000), [{ key: 'summary', value: cut(summary, 200) }], [{ key: 'event.adds', tone: 'green' }]);
  }

  // Plain text: a bare domain or link-like text can still be checked.
  const smart = classifyInput(text);
  const signals: QrSignal[] = [];
  if (smart?.kind === 'domain' || smart?.kind === 'url') signals.push({ key: 'text.looksLikeLink', tone: 'amber' });
  if (/\bhttps?:\/\//i.test(text) && !smart) signals.push({ key: 'text.containsLink', tone: 'amber' });
  return build('text', cut(text, 2000), [], signals, smart?.actions ?? []);
}
