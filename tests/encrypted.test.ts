import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectEncryption, isRecoverableFormat } from '../src/core/encrypted';
import { detectFileEncryption } from '../src/main/services/recovery';
import { writeCfb } from './helpers/cfb-writer';

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

  it('recognizes 7z and RAR containers without claiming encryption from the signature alone', () => {
    // A bare signature has no entries to read: undetermined, never "encrypted" or "not encrypted".
    expect(detectEncryption(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]))).toMatchObject({ format: '7z', encrypted: false, undetermined: true });
    expect(detectEncryption(new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]))).toMatchObject({ format: 'rar', encrypted: false, undetermined: true });
    expect(detectEncryption(new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]))).toMatchObject({ format: 'rar', encrypted: false, undetermined: true });
  });

  it('reads real RAR5 and RAR3 archives: content-only encryption, encrypted names, and none', () => {
    const rar = (f: string) => head(readFileSync(join(FIX, f)));
    expect(rar('rar5-psw.rar')).toMatchObject({ encrypted: true, format: 'rar', scheme: 'rar5-aes', strength: 'strong', notes: ['recovery.note.rar5'] });
    expect(rar('rar5-hpsw.rar')).toMatchObject({ encrypted: true, scheme: 'rar5-aes', notes: ['recovery.note.rar5', 'recovery.note.namesEncrypted'] });
    expect(rar('rar5-solid.rar')).toEqual({ encrypted: false, format: 'rar', scheme: null, strength: 'unknown', notes: [] });
    expect(rar('rar3-comment-psw.rar')).toMatchObject({ encrypted: true, scheme: 'rar4', strength: 'weak', notes: ['recovery.note.rar4'] });
    expect(rar('rar3-comment-hpsw.rar')).toMatchObject({ encrypted: true, notes: ['recovery.note.rar4', 'recovery.note.namesEncrypted'] });
    expect(rar('rar3-comment-plain.rar')).toMatchObject({ encrypted: false, notes: [] });
  });

  it('reads the index of real 7z archives', async () => {
    const seven = async (f: string) => (await detectFileEncryption(join(FIX, f))).encryption;
    expect(await seven('7z-hpsw.7z')).toMatchObject({ encrypted: true, format: '7z', scheme: '7z-aes', notes: ['recovery.note.sevenZip', 'recovery.note.namesEncrypted'] });
    // Content-only encryption behind a compressed index: honest "couldn't confirm", and recovery stays possible.
    expect(await seven('7z-psw.7z')).toMatchObject({ encrypted: false, undetermined: true, notes: ['recovery.note.sevenZipCompressedIndex'] });
    expect(await seven('7z-plain.7z')).toMatchObject({ encrypted: false, format: '7z' });
    expect((await seven('7z-plain.7z')).encrypted).toBe(false);
  });

  it('reads Office protection from the document itself instead of assuming it', () => {
    expect(head(readFileSync(join(FIX, 'agile.docx')))).toMatchObject({ encrypted: true, format: 'office-ooxml', scheme: 'office-agile', strength: 'strong' });
    const fib = (flags: number) => {
      const w = Buffer.alloc(64);
      w.writeUInt16LE(0xa5ec, 0);
      w.writeUInt16LE(flags, 0x0a);
      return w;
    };
    const doc = (flags: number) => head(writeCfb([{ name: 'WordDocument', data: fib(flags) }, { name: '1Table', data: Buffer.alloc(16) }]));
    expect(doc(0x0000)).toEqual({ encrypted: false, format: 'office-legacy', scheme: null, strength: 'unknown', notes: [] });
    expect(doc(0x0100)).toMatchObject({ encrypted: true, format: 'office-legacy', scheme: 'office-rc4', strength: 'weak' });
    expect(doc(0x8100)).toMatchObject({ encrypted: true, scheme: 'office-xor' });
    // Excel: BOF, then FILEPASS (0x002F) when protected.
    const rec = (type: number, len: number) => Buffer.concat([Buffer.from([type & 0xff, type >> 8, len & 0xff, len >> 8]), Buffer.alloc(len)]);
    const xls = (protectedBook: boolean) => head(writeCfb([{ name: 'Workbook', data: Buffer.concat([rec(0x0809, 16), ...(protectedBook ? [rec(0x002f, 54)] : []), rec(0x0042, 2), rec(0x000a, 0)]) }]));
    expect(xls(true)).toMatchObject({ encrypted: true, format: 'office-legacy' });
    expect(xls(false)).toMatchObject({ encrypted: false, format: 'office-legacy' });
    // Other OLE files (e.g. an Outlook .msg) are not protected documents.
    expect(head(writeCfb([{ name: '__substg1.0_0037001F', data: Buffer.from('s', 'utf16le') }]))).toMatchObject({ encrypted: false, format: 'unknown' });
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
