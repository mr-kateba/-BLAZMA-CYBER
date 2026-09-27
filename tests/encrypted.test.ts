import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectEncryption, isRecoverableFormat } from '../src/core/encrypted';

// zipcrypto.zip: a real archive made with `zip -e` (one 12-byte text file). The PDFs are minimal
// hand-written files exercising each /Encrypt scheme.
const FIX = join(__dirname, 'fixtures', 'encrypted');
const head = (b: Buffer | Uint8Array) => detectEncryption(b.subarray(0, 64), b);

// Local ZIP header builder: PK\x03\x04, version, flags, method...
function zipHeader(flags: number, method: number): Uint8Array {
  const b = new Uint8Array(32);
  b.set([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
  b[6] = flags & 0xff; b[7] = (flags >> 8) & 0xff;
  b[8] = method & 0xff; b[9] = (method >> 8) & 0xff;
  return b;
}

describe('encrypted-file detection', () => {
  it('detects ZipCrypto vs AES vs unencrypted zip', () => {
    expect(detectEncryption(zipHeader(0x0000, 0))).toMatchObject({ encrypted: false, format: 'zip' });
    expect(detectEncryption(zipHeader(0x0001, 0))).toMatchObject({ encrypted: true, format: 'zip', scheme: 'zip-zipcrypto', strength: 'weak' });
    expect(detectEncryption(zipHeader(0x0001, 99))).toMatchObject({ encrypted: true, scheme: 'zip-aes', strength: 'strong' });
    expect(detectEncryption(zipHeader(0x0041, 8))).toMatchObject({ encrypted: true, scheme: 'zip-aes' });
  });

  it('matches a REAL ZipCrypto archive produced by the zip tool', () => {
    expect(head(readFileSync(join(FIX, 'zipcrypto.zip')))).toMatchObject({ encrypted: true, format: 'zip', scheme: 'zip-zipcrypto', strength: 'weak' });
  });

  it('detects 7z, RAR4 and RAR5 containers', () => {
    expect(detectEncryption(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]))).toMatchObject({ format: '7z', scheme: '7z-aes', strength: 'strong' });
    expect(detectEncryption(new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]))).toMatchObject({ format: 'rar', scheme: 'rar5-aes' });
    expect(detectEncryption(new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]))).toMatchObject({ format: 'rar', scheme: 'rar4', strength: 'weak' });
  });

  it('detects PDF encryption strength from crafted and real fixtures', () => {
    const enc = Buffer.from('%PDF-1.6\ntrailer<</Encrypt 5 0 R>>\n5 0 obj<</Filter/Standard/V 5/R 6>>');
    expect(head(enc)).toMatchObject({ encrypted: true, format: 'pdf', scheme: 'pdf-aes-256', strength: 'strong' });
    const rc4 = Buffer.from('%PDF-1.4\ntrailer<</Encrypt 3 0 R>>\n3 0 obj<</Filter/Standard/V 2/R 3>>');
    expect(head(rc4)).toMatchObject({ scheme: 'pdf-rc4', strength: 'weak' });
    expect(head(Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog>>'))).toMatchObject({ encrypted: false, format: 'pdf' });
    for (const [file, scheme] of [['enc.pdf', 'pdf-aes-256'], ['rc4.pdf', 'pdf-rc4'], ['plain.pdf', null]] as const) {
      expect(head(readFileSync(join(FIX, file))), file).toMatchObject({ format: 'pdf', scheme });
    }
  });

  it('reports unknown for non-container data', () => {
    expect(detectEncryption(Buffer.from('just some text here'))).toEqual({ encrypted: false, format: 'unknown', scheme: null, strength: 'unknown', notes: [] });
  });

  it('knows which formats an external engine can target', () => {
    expect(isRecoverableFormat('zip')).toBe(true);
    expect(isRecoverableFormat('pdf')).toBe(true);
    expect(isRecoverableFormat('unknown')).toBe(false);
  });
});
