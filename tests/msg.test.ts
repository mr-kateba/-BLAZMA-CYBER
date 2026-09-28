import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CfbError, isCfb, readCfb } from '../src/core/cfb';
import { analyzeEmail, attachmentBytes } from '../src/core/email';
import { decodeCodepage, msgToMime } from '../src/core/msg';
import { filetime, long, prop, propsStream, u16, writeCfb, type CfbNode } from './helpers/cfb-writer';

const PT_LONG = 0x0003;
const PT_SYSTIME = 0x0040;
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

const TRANSPORT = [
  'Received: from mail.paypa1-secure.example (mail.paypa1-secure.example [192.0.2.44]) by mx.outlook.com; Mon, 21 Sep 2026 08:00:00 +0000',
  'Authentication-Results: spf=softfail smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=fail header.from=paypa1-secure.example',
  'From: "service@paypal.com" <alerts@paypa1-secure.example>',
  'To: victim@example.com',
  'Subject: Account suspended',
  'MIME-Version: 1.0',
  'Content-Type: multipart/alternative;',
  '\tboundary="ORIGINAL"',
  '',
  '',
].join('\r\n');

const bigAttachment = Buffer.alloc(9000, 7); // ≥ 4096 bytes: stored in regular sectors
bigAttachment.write('MZ', 0);

function attachment(i: number, name: string, data: Buffer, mime?: string): CfbNode {
  return {
    name: `__attach_version1.0_#${i.toString(16).toUpperCase().padStart(8, '0')}`,
    children: [
      propsStream(8, [{ id: 0x3705, type: PT_LONG, value: long(1) }]),
      { name: prop(0x3707, '001F'), data: u16(name) },
      { name: prop(0x3701, '0102'), data },
      ...(mime ? [{ name: prop(0x370e, '001F'), data: u16(mime) }] : []),
    ],
  };
}

function receivedMsg(): Buffer {
  return writeCfb([
    propsStream(32, [{ id: 0x0e06, type: PT_SYSTIME, value: filetime(new Date('2026-09-21T08:00:00Z')) }]),
    { name: prop(0x001a, '001F'), data: u16('IPM.Note') },
    { name: prop(0x007d, '001F'), data: u16(TRANSPORT) },
    { name: prop(0x0037, '001F'), data: u16('Account suspended') },
    { name: prop(0x1000, '001F'), data: u16('Please verify at https://bit.ly/xyz now') },
    { name: prop(0x1013, '0102'), data: Buffer.from('<p><a href="http://192.0.2.10/login">https://www.paypal.com/signin</a></p>') },
    attachment(0, 'invoice.pdf.exe', bigAttachment, 'application/octet-stream'),
    attachment(1, 'تقرير.docm', Buffer.from('PK small macro doc')),
  ]);
}

describe('CFB reader', () => {
  it('reads streams from the mini stream and regular sectors', () => {
    const buf = writeCfb([
      { name: 'small', data: Buffer.from('hello') },
      { name: 'big', data: bigAttachment },
      { name: 'dir', children: [{ name: 'inner', data: Buffer.from('nested') }] },
    ]);
    expect(isCfb(buf)).toBe(true);
    const root = readCfb(buf);
    const by = new Map(root.children.map((c) => [c.name, c]));
    expect(by.get('small')!.data().toString()).toBe('hello');
    expect(sha(by.get('big')!.data())).toBe(sha(bigAttachment));
    expect(by.get('dir')!.kind).toBe('storage');
    expect(by.get('dir')!.children[0]!.data().toString()).toBe('nested');
  });

  it('rejects truncated or looping files instead of hanging', () => {
    expect(isCfb(Buffer.from('not a cfb'))).toBe(false);
    expect(() => readCfb(Buffer.alloc(1024))).toThrow(CfbError);
    const buf = writeCfb([{ name: 'big', data: bigAttachment }]);
    // Point a FAT entry of the big stream back to itself: a loop.
    const looped = Buffer.from(buf);
    const fatOff = 512;
    for (let i = 0; i < 128; i++) {
      if (looped.readUInt32LE(fatOff + i * 4) === i + 1) {
        looped.writeUInt32LE(i, fatOff + i * 4);
        break;
      }
    }
    expect(() => readCfb(looped).children.forEach((c) => c.data())).toThrow(CfbError);
    expect(() => readCfb(buf.subarray(0, 1500)).children.forEach((c) => c.data())).toThrow(CfbError);
  });
});

describe('.msg → MIME', () => {
  it('keeps the original internet headers and runs the full phishing analysis', () => {
    const mime = msgToMime(receivedMsg());
    const a = analyzeEmail(mime);
    expect(a.subject).toBe('Account suspended');
    expect(a.from?.address).toBe('alerts@paypa1-secure.example');
    expect(a.auth.find((x) => x.method === 'dmarc')?.result).toBe('fail');
    expect(a.received).toHaveLength(1);
    expect(a.signals.map((s) => s.key)).toEqual(expect.arrayContaining(['dmarcFail', 'displayNameSpoof', 'deceptiveLinks', 'suspiciousLinks', 'dangerousAttachment', 'riskyAttachment']));
    expect(a.level).toBe('risky');
    expect(a.links.map((l) => l.href)).toEqual(expect.arrayContaining(['http://192.0.2.10/login', 'https://bit.ly/xyz']));
    // The original multipart boundary is gone; ours replaces it.
    expect(mime.toString('latin1')).not.toContain('ORIGINAL');
  });

  it('extracts attachments byte-exact with Unicode names', () => {
    const mime = msgToMime(receivedMsg());
    const a = analyzeEmail(mime);
    expect(a.attachments.map((x) => x.name)).toEqual(['invoice.pdf.exe', 'تقرير.docm']);
    expect(a.attachments[0]!.sha256).toBe(sha(bigAttachment));
    expect(a.attachments[0]!.size).toBe(bigAttachment.length);
    expect(attachmentBytes(mime, 0)!.bytes.equals(bigAttachment)).toBe(true);
    expect(attachmentBytes(mime, 1)!.bytes.toString()).toBe('PK small macro doc');
  });

  it('rebuilds headers from properties when Outlook kept none (sent items / drafts)', () => {
    const buf = writeCfb([
      propsStream(32, [{ id: 0x0039, type: PT_SYSTIME, value: filetime(new Date('2026-09-20T10:30:00Z')) }]),
      { name: prop(0x001a, '001F'), data: u16('IPM.Note') },
      { name: prop(0x0037, '001F'), data: u16('فاتورة الشهر') },
      { name: prop(0x0c1a, '001F'), data: u16('Mona') },
      { name: prop(0x5d01, '001F'), data: u16('mona@example.com') },
      { name: prop(0x1000, '001F'), data: u16('Hello') },
      {
        name: '__recip_version1.0_#00000000',
        children: [
          propsStream(8, [{ id: 0x0c15, type: PT_LONG, value: long(1) }]),
          { name: prop(0x3001, '001F'), data: u16('Ali') },
          { name: prop(0x39fe, '001F'), data: u16('ali@example.org') },
        ],
      },
      {
        name: '__recip_version1.0_#00000001',
        children: [
          propsStream(8, [{ id: 0x0c15, type: PT_LONG, value: long(3) }]),
          { name: prop(0x39fe, '001F'), data: u16('hidden@example.org') },
        ],
      },
    ]);
    const mime = msgToMime(buf);
    const a = analyzeEmail(mime);
    expect(a.subject).toBe('فاتورة الشهر');
    expect(a.from).toEqual({ name: 'Mona', address: 'mona@example.com', domain: 'example.com' });
    expect(a.to).toContain('ali@example.org');
    expect(mime.toString('latin1')).not.toContain('hidden@example.org'); // Bcc stays out
    expect(a.date).toBe('2026-09-20T10:30:00.000Z');
    expect(a.auth).toEqual([]);
    expect(a.signals.map((s) => s.key)).toContain('noAuth');
  });

  it('neutralizes header injection through subjects, names and file names', () => {
    const buf = writeCfb([
      { name: prop(0x001a, '001F'), data: u16('IPM.Note') },
      { name: prop(0x0037, '001F'), data: u16('Hi\r\nAuthentication-Results: dmarc=pass') },
      { name: prop(0x0c1a, '001F'), data: u16('x\r\nReply-To: <a@b.c>') },
      { name: prop(0x5d01, '001F'), data: u16('evil@example.com>\r\nX: y') },
      attachment(0, 'a"\r\nContent-Type: text/html\r\n\r\n<x>.exe', Buffer.from('data')),
    ]);
    const a = analyzeEmail(msgToMime(buf));
    expect(a.auth).toEqual([]);
    expect(a.replyTo).toBeNull();
    expect(a.subject).toBe('Hi Authentication-Results: dmarc=pass');
    expect(a.attachments).toHaveLength(1);
    expect(a.attachments[0]!.flags).toContain('executable');
  });

  it('analyzes an attached (embedded) email', () => {
    const inner: CfbNode = {
      name: prop(0x3701, '000D'),
      children: [
        { name: prop(0x001a, '001F'), data: u16('IPM.Note') },
        { name: prop(0x0037, '001F'), data: u16('inner') },
        { name: prop(0x1000, '001F'), data: u16('click https://xn--pypal-4ve.com/login') },
        attachment(0, 'payload.js', Buffer.from('var x')),
      ],
    };
    const buf = writeCfb([
      { name: prop(0x001a, '001F'), data: u16('IPM.Note') },
      { name: prop(0x0037, '001F'), data: u16('Fwd') },
      { name: '__attach_version1.0_#00000000', children: [propsStream(8, [{ id: 0x3705, type: PT_LONG, value: long(5) }]), { name: prop(0x3001, '001F'), data: u16('inner') }, inner] },
    ]);
    const a = analyzeEmail(msgToMime(buf));
    expect(a.subject).toBe('Fwd');
    expect(a.links.some((l) => l.flags.includes('punycode'))).toBe(true);
    expect(a.attachments.map((x) => x.name)).toEqual(['payload.js']);
  });

  it('rejects compound files that are not emails (e.g. an old .doc)', () => {
    const doc = writeCfb([{ name: 'WordDocument', data: Buffer.alloc(100) }]);
    expect(() => msgToMime(doc)).toThrow('not_an_email');
    expect(() => msgToMime(Buffer.alloc(600))).toThrow(CfbError);
  });

  it('decodes ANSI strings with the message code page', () => {
    expect(decodeCodepage(Buffer.from([0xe3, 0xd1, 0xcd, 0xc8, 0xc7]), 1256)).toBe('مرحبا');
    expect(decodeCodepage(Buffer.from('café', 'latin1'), null)).toBe('café');
  });
});
