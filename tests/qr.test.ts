import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { imageSize } from '../src/core/image-size';
import { classifyQrContent, parseFieldList } from '../src/core/qr-content';
import { checkQrImage, isSupportedImage, readQrImage } from '../src/main/services/qr';

/** A literal backslash (escape character in WIFI:/MECARD: payloads). */
const BS = String.fromCharCode(92);
const keys = (x: { signals: { key: string }[] }) => x.signals.map((s) => s.key);

describe('QR content', () => {
  it('flags deceptive links and offers the link check', () => {
    const r = classifyQrContent('http://192.0.2.9/pay');
    expect(r.kind).toBe('url');
    expect(keys(r)).toEqual(['link.ip', 'link.http']);
    expect(r.level).toBe('risky');
    expect(r.actions.map((a) => a.page)).toEqual(['ip-intel', 'reputation']);
    expect(classifyQrContent('https://shop.example/x').actions.map((a) => a.page)).toContain('domain-intel');

    expect(classifyQrContent('https://bit.ly/abc').level).toBe('caution');
    expect(keys(classifyQrContent('https://paypal.com@evil.example/login'))).toContain('link.userinfo');
    expect(keys(classifyQrContent('https://xn--pypal-4ve.com/'))).toContain('link.punycode');
    const ok = classifyQrContent('https://www.example.com/menu');
    expect(ok.level).toBe('no_red_flags');
    expect(ok.signals[0]).toEqual({ key: 'link.checkFirst', tone: 'green', vars: { host: 'www.example.com' } });
    expect(classifyQrContent('javascript:alert(1)').level).toBe('risky');
  });

  it('never returns Wi-Fi passwords or 2FA secrets', () => {
    const w = classifyQrContent(`WIFI:T:WPA;S:Cafe${BS};Guest;P:sup3r-secret;H:true;;`);
    expect(w.kind).toBe('wifi');
    expect(w.display).toBeNull();
    expect(JSON.stringify(w)).not.toContain('sup3r-secret');
    expect(w.fields).toEqual([
      { key: 'ssid', value: 'Cafe;Guest' },
      { key: 'security', value: 'WPA' },
      { key: 'hidden', value: 'yes' },
      { key: 'password', value: 'present' },
    ]);
    expect(keys(classifyQrContent('WIFI:T:nopass;S:Free;;'))).toContain('wifi.open');

    const o = classifyQrContent('otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example');
    expect(o.kind).toBe('otp');
    expect(o.level).toBe('risky');
    expect(JSON.stringify(o)).not.toContain('JBSWY3DPEHPK3PXP');
    expect(o.fields).toEqual([{ key: 'issuer', value: 'Example' }, { key: 'account', value: 'alice@example.com' }]);
  });

  it('recognizes payments, messages, calls, contacts and plain text', () => {
    const p = classifyQrContent('bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.5&label=Fine');
    expect(p.kind).toBe('payment');
    expect(p.fields.find((f) => f.key === 'amount')?.value).toBe('0.5');
    expect(keys(p)).toEqual(['payment.irreversible']);

    const s = classifyQrContent('SMSTO:4545:WIN');
    expect(s.kind).toBe('sms');
    expect(keys(s)).toEqual(['sms.sends', 'sms.shortCode']);
    expect(classifyQrContent('sms:+966500000000?body=hi').fields).toEqual([{ key: 'number', value: '+966500000000' }, { key: 'message', value: 'hi' }]);

    const m = classifyQrContent('mailto:help@example.com?subject=Refund');
    expect(m.kind).toBe('email');
    expect(m.fields).toEqual([{ key: 'to', value: 'help@example.com' }, { key: 'subject', value: 'Refund' }]);
    expect(classifyQrContent('MATMSG:TO:a@b.example;SUB:Hi;BODY:x;;').fields[0]).toEqual({ key: 'to', value: 'a@b.example' });

    expect(classifyQrContent('tel:+15551234567').kind).toBe('phone');
    expect(classifyQrContent('geo:24.7136,46.6753').fields).toEqual([{ key: 'coordinates', value: '24.7136,46.6753' }]);
    const v = classifyQrContent('BEGIN:VCARD\nVERSION:3.0\nFN:Sara Ali\nURL:https://example.com\nEND:VCARD');
    expect(v.kind).toBe('contact');
    expect(v.fields).toEqual([{ key: 'name', value: 'Sara Ali' }]);
    expect(keys(v)).toContain('contact.hasLink');
    expect(classifyQrContent('MECARD:N:Omar;TEL:123;;').fields).toEqual([{ key: 'name', value: 'Omar' }]);

    const d = classifyQrContent('example.com');
    expect(d.kind).toBe('text');
    expect(keys(d)).toEqual(['text.looksLikeLink']);
    expect(classifyQrContent('Table 12 — enjoy your meal').level).toBe('no_red_flags');
    expect(keys(classifyQrContent('menu at https://x.example/m'))).toEqual(['text.containsLink']);
  });

  it('parses escaped field lists', () => {
    expect([...parseFieldList('S:a\\:b;P:x\\\\y;;')]).toEqual([['S', 'a:b'], ['P', 'x\\y']]);
  });
});

// ---- images

function png(width: number, height: number): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    return Buffer.concat([len, Buffer.from(type, 'latin1'), data, Buffer.alloc(4)]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.alloc(10))), chunk('IEND', Buffer.alloc(0))]);
}

describe('image checks', () => {
  it('reads dimensions from headers', () => {
    expect(imageSize(png(640, 480))).toEqual({ width: 640, height: 480 });
    const gif = Buffer.from('GIF89a\x20\x00\x10\x00\x00\x00\x00', 'latin1');
    expect(imageSize(gif)).toEqual({ width: 32, height: 16 });
    const bmp = Buffer.alloc(30);
    bmp.write('BM', 0, 'latin1');
    bmp.writeInt32LE(100, 18);
    bmp.writeInt32LE(-50, 22);
    expect(imageSize(bmp)).toEqual({ width: 100, height: 50 });
    // JPEG: SOI, APP0 (skipped), SOF0 with height 300, width 400.
    const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0, 0, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x01, 0x2c, 0x01, 0x90, 0x03, 0, 0, 0, 0]);
    expect(imageSize(jpg)).toEqual({ width: 400, height: 300 });
    const webp = Buffer.alloc(30);
    webp.write('RIFF', 0, 'latin1');
    webp.write('WEBPVP8X', 8, 'latin1');
    webp.writeUIntLE(1919, 24, 3);
    webp.writeUIntLE(1079, 27, 3);
    expect(imageSize(webp)).toEqual({ width: 1920, height: 1080 });
    expect(imageSize(Buffer.from('hello'))).toBeNull();
  });

  it('refuses non-images and decompression bombs', async () => {
    expect(isSupportedImage(png(1, 1))).toBe(true);
    expect(() => checkQrImage(Buffer.from('MZ not an image at all'))).toThrow('qr_not_image');
    expect(() => checkQrImage(png(20000, 20000))).toThrow('qr_image_too_large');
    expect(() => checkQrImage(png(1000, 1000))).not.toThrow();

    const dir = mkdtempSync(join(tmpdir(), 'blazma-qr-'));
    const good = join(dir, 'code.png');
    writeFileSync(good, png(200, 200));
    expect((await readQrImage(good)).length).toBeGreaterThan(20);
    const fake = join(dir, 'fake.png');
    writeFileSync(fake, 'not a png');
    await expect(readQrImage(fake)).rejects.toThrow('qr_not_image');
    await expect(readQrImage('relative/path.png')).rejects.toThrow();
    await expect(readQrImage(join(dir, 'missing.png'))).rejects.toThrow('file_not_found');
  });
});
