import { describe, expect, it } from 'vitest';
import { analyzeEmail, attachmentBytes, attachmentFlags, baseDomain, decodeWords, linkFlags, parseAddress } from '../src/core/email';

const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');
const subjectAr = `=?UTF-8?B?${b64('تنبيه: تم إيقاف حسابك')}?=`;

const PHISH = [
  'Received: from mail.paypa1-secure.example (mail.paypa1-secure.example [192.0.2.44]) by mx.google.com with ESMTPS id x; Mon, 21 Sep 2026 08:00:00 +0000',
  'Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail (p=REJECT) header.from=paypa1-secure.example',
  'From: "service@paypal.com" <alerts@paypa1-secure.example>',
  'Reply-To: recover.account@gmail.com',
  'Return-Path: <bounce@paypa1-secure.example>',
  'To: victim@example.com',
  `Subject: ${subjectAr}`,
  'Date: Mon, 21 Sep 2026 08:00:00 +0000',
  'Message-ID: <abc@paypa1-secure.example>',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="B1"',
  '',
  '--B1',
  'Content-Type: text/html; charset=utf-8',
  'Content-Transfer-Encoding: quoted-printable',
  '',
  '<p>Dear customer, <a href=3D"http://192.0.2.10/login">https://www.paypal.com/signin</a></p>',
  '<a href=3D"https://bit.ly/abc">track</a> <a href=3D"mailto:x@y.z">mail</a>',
  '--B1',
  'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
  'Content-Disposition: attachment; filename="invoice.pdf.exe"',
  'Content-Transfer-Encoding: base64',
  '',
  b64('MZ fake program bytes'),
  '--B1--',
  '',
].join('\r\n');

const LEGIT = [
  'Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=news.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
  'From: Example News <news@example.com>',
  'Subject: Weekly update',
  'Date: Tue, 22 Sep 2026 10:00:00 +0000',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Read more at https://www.example.com/articles/1',
  '',
].join('\n');

describe('Phishing email analysis', () => {
  it('flags the classic phishing tricks and decodes an Arabic subject', () => {
    const r = analyzeEmail(Buffer.from(PHISH));
    expect(r.subject).toBe('تنبيه: تم إيقاف حسابك');
    expect(r.from).toEqual({ name: 'service@paypal.com', address: 'alerts@paypa1-secure.example', domain: 'paypa1-secure.example' });
    expect(r.auth).toEqual([{ method: 'spf', result: 'softfail' }, { method: 'dkim', result: 'none' }, { method: 'dmarc', result: 'fail' }]);
    expect(r.level).toBe('risky');
    const keys = r.signals.map((x) => x.key);
    expect(keys).toEqual(expect.arrayContaining(['dmarcFail', 'spfFail', 'displayNameSpoof', 'replyToDiffers', 'deceptiveLinks', 'suspiciousLinks', 'dangerousAttachment']));
    const deceptive = r.links.find((l) => l.href === 'http://192.0.2.10/login')!;
    expect(deceptive.text).toBe('https://www.paypal.com/signin');
    expect(deceptive.flags).toEqual(expect.arrayContaining(['ip', 'http', 'mismatch']));
    expect(r.links.some((l) => l.href.startsWith('mailto:'))).toBe(false);
    expect(r.attachments[0]).toMatchObject({ name: 'invoice.pdf.exe', flags: expect.arrayContaining(['executable', 'double_extension']) });
    expect(r.attachments[0]!.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(attachmentBytes(Buffer.from(PHISH), 0)?.bytes.toString()).toBe('MZ fake program bytes');
    expect(r.received[0]).toMatchObject({ from: 'mail.paypa1-secure.example', by: 'mx.google.com', date: '2026-09-21T08:00:00.000Z' });
  });

  it('a properly authenticated newsletter has no warning signs', () => {
    const r = analyzeEmail(Buffer.from(LEGIT));
    expect(r.level).toBe('no_red_flags');
    expect(r.signals).toEqual([{ key: 'dmarcPass', tone: 'green' }]);
    expect(r.links[0]).toMatchObject({ host: 'www.example.com', flags: [] });
  });

  it('refuses non-email input and huge input', () => {
    expect(() => analyzeEmail(Buffer.from('just some text'))).toThrow('not_an_email');
    expect(() => analyzeEmail(Buffer.alloc(26 * 1024 * 1024))).toThrow('email_too_large');
  });

  it('decodes encodings found in real mail', () => {
    expect(decodeWords('=?ISO-8859-1?Q?Caf=E9_ouvert?=')).toBe('Café ouvert');
    const cp1256 = Buffer.from([0xe3, 0xd1, 0xcd, 0xc8, 0xc7]); // "مرحبا" in Windows-1256
    const msg = `From: a@example.com\nSubject: x\nContent-Type: text/plain; charset=windows-1256\nContent-Transfer-Encoding: base64\n\n${cp1256.toString('base64')}\n`;
    expect(analyzeEmail(Buffer.from(msg)).textPreview).toBe('مرحبا');
    const rfc2231 = `From: a@example.com\nContent-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: application/zip\nContent-Disposition: attachment; filename*=utf-8''%D9%81%D8%A7%D8%AA%D9%88%D8%B1%D8%A9.zip\n\nPK\n--X--\n`;
    expect(analyzeEmail(Buffer.from(rfc2231)).attachments[0]).toMatchObject({ name: 'فاتورة.zip', flags: ['container'] });
  });

  it('helpers', () => {
    expect(baseDomain('login.secure.paypal.com')).toBe('paypal.com');
    expect(baseDomain('www.bank.com.sa')).toBe('bank.com.sa');
    expect(linkFlags('javascript:alert(1)', null)).toEqual(['script']);
    expect(linkFlags('https://user@evil.example/x', null)).toContain('userinfo');
    expect(linkFlags('https://xn--pypal-4ve.com/', 'paypal.com')).toEqual(expect.arrayContaining(['punycode', 'mismatch']));
    expect(linkFlags('https://www.example.com/a', 'example.com/a')).toEqual([]);
    expect(attachmentFlags('report‮gpj.exe')).toEqual(expect.arrayContaining(['executable', 'rtlo']));
    expect(attachmentFlags('budget.xlsm')).toEqual(['macro']);
    expect(attachmentFlags('photo.jpg')).toEqual([]);
    expect(parseAddress('=?UTF-8?B?2KPYrdmF2K8=?= <ahmad@example.com>')).toEqual({ name: 'أحمد', address: 'ahmad@example.com', domain: 'example.com' });
  });
});
