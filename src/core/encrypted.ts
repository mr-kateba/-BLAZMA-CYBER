// Encrypted-file detection (pure, no I/O). Given the first bytes and the size of a file, report
// whether it is encrypted, the container format, and the encryption scheme/strength.
//
// This is defensive triage: an analyst or the owner of a file can see "this archive is AES-256"
// vs "this is legacy ZipCrypto", or that a PDF/Office document is password-protected. It does NOT
// attempt recovery; the Password Recovery workspace hands protected files the owner is authorized
// to recover to a separately installed external engine.

import { readCfb, type CfbEntry } from './cfb';

export type EncryptedFormat = 'zip' | '7z' | 'rar' | 'pdf' | 'office-ooxml' | 'office-legacy' | 'unknown';

export interface EncryptionInfo {
  encrypted: boolean;
  format: EncryptedFormat;
  /** Human/i18n scheme id, e.g. 'zip-aes', 'zip-zipcrypto', 'pdf-aes-256', 'office-agile'. */
  scheme: string | null;
  /** Rough strength for the UI: 'strong' (modern AES), 'weak' (legacy), or 'unknown'. */
  strength: 'strong' | 'weak' | 'unknown';
  /** Notes for the UI (i18n keys). */
  notes: string[];
  /** The file's own structure couldn't confirm either way (encrypted is then false). */
  undetermined?: boolean;
}

const u16le = (b: Uint8Array, o: number) => (b.length >= o + 2 ? b[o]! | (b[o + 1]! << 8) : -1);
const starts = (b: Uint8Array, sig: number[], off = 0) => sig.every((v, i) => b[off + i] === v);

function detectZip(head: Uint8Array): EncryptionInfo | null {
  // Local file header: PK\x03\x04
  if (!starts(head, [0x50, 0x4b, 0x03, 0x04])) return null;
  const flags = u16le(head, 6);
  const method = u16le(head, 8);
  const encrypted = (flags & 0x0001) !== 0;
  if (!encrypted) return { encrypted: false, format: 'zip', scheme: null, strength: 'unknown', notes: [] };
  // method 99 = WinZip AES; the "strong encryption" flag (bit 6) also indicates AES/other.
  if (method === 99 || (flags & 0x0040) !== 0) {
    return { encrypted: true, format: 'zip', scheme: 'zip-aes', strength: 'strong', notes: ['recovery.note.zipAes'] };
  }
  return { encrypted: true, format: 'zip', scheme: 'zip-zipcrypto', strength: 'weak', notes: ['recovery.note.zipCrypto'] };
}

function detect7z(head: Uint8Array, nextHeader?: Uint8Array): EncryptionInfo | null {
  // 7z signature: 37 7A BC AF 27 1C. Encryption is recorded in the archive's index ("next header")
  // at the end of the file: an AES-256 coder (id 06 F1 07 01) either on the packed index itself
  // (file names encrypted too) or on the file data.
  if (!starts(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return null;
  if (!nextHeader || nextHeader.length === 0) {
    return { encrypted: false, format: '7z', scheme: null, strength: 'unknown', notes: ['recovery.note.notChecked'], undetermined: true };
  }
  const hasAes = indexOfBytes(nextHeader, [0x24, 0x06, 0xf1, 0x07, 0x01]) >= 0;
  if (!hasAes) {
    // 0x17 without AES = the index is only compressed (7-Zip's default). The per-file coders are
    // inside the compressed part, so the file itself can't tell whether the contents are protected.
    if (nextHeader[0] === 0x17) return { encrypted: false, format: '7z', scheme: null, strength: 'unknown', notes: ['recovery.note.sevenZipCompressedIndex'], undetermined: true };
    return { encrypted: false, format: '7z', scheme: null, strength: 'unknown', notes: [] };
  }
  const notes = ['recovery.note.sevenZip'];
  // 0x17 = the index itself is packed; with an AES coder there, file names are hidden.
  if (nextHeader[0] === 0x17) notes.push('recovery.note.namesEncrypted');
  return { encrypted: true, format: '7z', scheme: '7z-aes', strength: 'strong', notes };
}

function indexOfBytes(b: Uint8Array, sig: number[]): number {
  outer: for (let i = 0; i + sig.length <= b.length; i++) {
    for (let j = 0; j < sig.length; j++) if (b[i + j] !== sig[j]) continue outer;
    return i;
  }
  return -1;
}

/** Where a 7z archive's index lives (from the start header), so the caller can read it. */
export function sevenZipNextHeaderRange(head: Uint8Array): { offset: number; size: number } | null {
  if (!starts(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) || head.length < 32) return null;
  const off = u32le(head, 12) + u32le(head, 16) * 2 ** 32;
  const size = u32le(head, 20) + u32le(head, 24) * 2 ** 32;
  if (off < 0 || size <= 0 || size > 16 * 1024 * 1024 || !Number.isSafeInteger(32 + off)) return null;
  return { offset: 32 + off, size };
}

/** RAR variable-length integer (7 bits per byte, low bits first). */
function vint(b: Uint8Array, o: number): { value: number; next: number } | null {
  let value = 0;
  for (let i = 0; i < 10 && o + i < b.length; i++) {
    const byte = b[o + i]!;
    value += (byte & 0x7f) * 2 ** (7 * i);
    if ((byte & 0x80) === 0) return { value, next: o + i + 1 };
  }
  return null;
}
const u32le = (b: Uint8Array, o: number) => (b.length >= o + 4 ? (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16)) + b[o + 3]! * 0x1000000 : -1);

/** What the archive's own headers say: files encrypted, names encrypted too, or nothing reachable. */
interface RarScan {
  files: number;
  encryptedFiles: number;
  namesEncrypted: boolean;
}

function scanRar5(b: Uint8Array): RarScan {
  const scan: RarScan = { files: 0, encryptedFiles: 0, namesEncrypted: false };
  let p = 8;
  for (let n = 0; n < 256 && p + 6 <= b.length; n++) {
    const size = vint(b, p + 4); // after the header CRC32
    if (!size || size.value === 0) break;
    const end = size.next + size.value;
    const type = vint(b, size.next);
    const flags = type && vint(b, type.next);
    if (!type || !flags) break;
    let q = flags.next;
    let extraSize = 0;
    let dataSize = 0;
    if (flags.value & 0x01) {
      const x = vint(b, q);
      if (!x) break;
      extraSize = x.value;
      q = x.next;
    }
    if (flags.value & 0x02) {
      const x = vint(b, q);
      if (!x) break;
      dataSize = x.value;
    }
    if (type.value === 4) {
      // Archive encryption header: everything after it, file names included, is encrypted.
      scan.namesEncrypted = true;
      break;
    }
    if (type.value === 2 && end <= b.length) {
      scan.files++;
      // Extra area records: size, type, data. Type 0x01 = file encryption record.
      for (let r = end - extraSize; extraSize > 0 && r < end; ) {
        const rs = vint(b, r);
        const rt = rs && vint(b, rs.next);
        if (!rs || !rt || rs.value === 0) break;
        if (rt.value === 0x01) {
          scan.encryptedFiles++;
          break;
        }
        r = rs.next + rs.value;
      }
    }
    if (type.value === 5) break; // end of archive
    p = end + dataSize;
  }
  return scan;
}

function scanRar4(b: Uint8Array): RarScan {
  const scan: RarScan = { files: 0, encryptedFiles: 0, namesEncrypted: false };
  let p = 7;
  for (let n = 0; n < 256 && p + 7 <= b.length; n++) {
    const type = b[p + 2]!;
    const flags = u16le(b, p + 3);
    const size = u16le(b, p + 5);
    if (size < 7) break;
    let add = 0;
    if (type === 0x73 && flags & 0x0080) {
      // Main header "password" flag: the following headers (file names) are encrypted.
      scan.namesEncrypted = true;
      break;
    }
    if (type === 0x74) {
      scan.files++;
      if (flags & 0x0004) scan.encryptedFiles++;
      add = u32le(b, p + 7) + (flags & 0x0100 ? u32le(b, p + 32) * 2 ** 32 : 0);
    } else if (flags & 0x8000) add = u32le(b, p + 7);
    if (type === 0x7b || add < 0) break; // end of archive
    p += size + add;
  }
  return scan;
}

function detectRar(head: Uint8Array, full?: Uint8Array): EncryptionInfo | null {
  const v5 = starts(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]);
  const v4 = starts(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]);
  if (!v5 && !v4) return null;
  const scan = (v5 ? scanRar5 : scanRar4)(full ?? head);
  const scheme = v5 ? 'rar5-aes' : 'rar4';
  const strength = v5 ? 'strong' : 'weak';
  if (scan.namesEncrypted || scan.encryptedFiles > 0) {
    const notes = [v5 ? 'recovery.note.rar5' : 'recovery.note.rar4'];
    if (scan.namesEncrypted) notes.push('recovery.note.namesEncrypted');
    return { encrypted: true, format: 'rar', scheme, strength, notes };
  }
  // No file entry could be read (e.g. a truncated file): say so instead of claiming "not encrypted".
  return { encrypted: false, format: 'rar', scheme: null, strength: 'unknown', ...(scan.files === 0 ? { notes: ['recovery.note.notChecked'], undetermined: true } : { notes: [] }) };
}

function detectPdf(head: Uint8Array, full?: Uint8Array): EncryptionInfo | null {
  if (!starts(head, [0x25, 0x50, 0x44, 0x46, 0x2d])) return null;
  const text = new TextDecoder('latin1').decode((full ?? head).subarray(0, Math.min((full ?? head).length, 2 * 1024 * 1024)));
  const enc = /\/Encrypt\b/.test(text);
  if (!enc) return { encrypted: false, format: 'pdf', scheme: null, strength: 'unknown', notes: [] };
  // Read /V (algorithm) and /R (revision) from the encryption dictionary when present.
  const v = Number(/\/V\s+(\d+)/.exec(text)?.[1] ?? 0);
  const r = Number(/\/R\s+(\d+)/.exec(text)?.[1] ?? 0);
  if (v >= 5 || r >= 6) return { encrypted: true, format: 'pdf', scheme: 'pdf-aes-256', strength: 'strong', notes: ['recovery.note.pdfAes'] };
  if (v === 4) return { encrypted: true, format: 'pdf', scheme: 'pdf-aes-128', strength: 'strong', notes: ['recovery.note.pdfAes'] };
  return { encrypted: true, format: 'pdf', scheme: 'pdf-rc4', strength: 'weak', notes: ['recovery.note.pdfRc4'] };
}

function detectOffice(head: Uint8Array, full?: Uint8Array): EncryptionInfo | null {
  if (!starts(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return null;
  let root: CfbEntry;
  try {
    root = readCfb(Buffer.from((full ?? head).buffer, (full ?? head).byteOffset, (full ?? head).byteLength));
  } catch {
    return { encrypted: false, format: 'unknown', scheme: null, strength: 'unknown', notes: ['recovery.note.notChecked'], undetermined: true };
  }
  const streams = new Map(root.children.map((c) => [c.name, c]));
  const read = (name: string): Buffer | null => {
    try {
      return streams.get(name)?.data() ?? null;
    } catch {
      return null;
    }
  };
  // Encrypted docx/xlsx/pptx: the OOXML package is wrapped in an OLE file (MS-OFFCRYPTO).
  if (streams.has('EncryptionInfo') && streams.has('EncryptedPackage')) {
    const info = read('EncryptionInfo');
    const agile = !!info && info.length >= 4 && u16le(info, 0) === 4 && u16le(info, 2) === 4;
    return { encrypted: true, format: 'office-ooxml', scheme: agile ? 'office-agile' : 'office-standard', strength: 'strong', notes: [agile ? 'recovery.note.officeAgile' : 'recovery.note.officeStandard'] };
  }
  // Word 97-2003: FIB flags fEncrypted (0x0100) / fObfuscated (0x8000).
  const word = read('WordDocument');
  if (word && word.length >= 12) {
    const flags = u16le(word, 0x0a);
    if (flags & 0x0100) return { encrypted: true, format: 'office-legacy', scheme: flags & 0x8000 ? 'office-xor' : 'office-rc4', strength: 'weak', notes: ['recovery.note.officeLegacy'] };
    return { encrypted: false, format: 'office-legacy', scheme: null, strength: 'unknown', notes: [] };
  }
  // Excel 97-2003: a FILEPASS record (0x002F) right after the workbook's BOF.
  const book = read('Workbook') ?? read('Book');
  if (book) {
    for (let p = 0, n = 0; p + 4 <= book.length && n < 64; n++) {
      const type = u16le(book, p);
      if (type === 0x002f) return { encrypted: true, format: 'office-legacy', scheme: 'office-rc4', strength: 'weak', notes: ['recovery.note.officeLegacy'] };
      if (type === 0x000a && n > 0) break; // EOF of the globals substream
      p += 4 + u16le(book, p + 2);
    }
    return { encrypted: false, format: 'office-legacy', scheme: null, strength: 'unknown', notes: [] };
  }
  // PowerPoint 97-2003: an encrypted presentation carries an EncryptedSummary stream.
  if (streams.has('PowerPoint Document')) {
    if (streams.has('EncryptedSummary')) return { encrypted: true, format: 'office-legacy', scheme: 'office-rc4', strength: 'weak', notes: ['recovery.note.officeLegacy'] };
    return { encrypted: false, format: 'office-legacy', scheme: null, strength: 'unknown', notes: [] };
  }
  // Another kind of OLE file (e.g. an Outlook .msg or an installer): not a protected document.
  return { encrypted: false, format: 'unknown', scheme: null, strength: 'unknown', notes: [] };
}

/**
 * Detects encryption from a file's header (pass >= 32 bytes). Pass the start of the file as `full`
 * (the whole file for OLE documents) so archive entries, PDF dictionaries and OLE streams can be
 * read, and a 7z archive's index (see sevenZipNextHeaderRange) as `sevenZipIndex`.
 */
export function detectEncryption(head: Uint8Array, full?: Uint8Array, sevenZipIndex?: Uint8Array): EncryptionInfo {
  return (
    detectZip(head) ??
    detect7z(head, sevenZipIndex) ??
    detectRar(head, full) ??
    detectPdf(head, full) ??
    detectOffice(head, full) ?? { encrypted: false, format: 'unknown', scheme: null, strength: 'unknown', notes: [] }
  );
}

/** Formats a supported external engine could work with (informational; engine must be user-installed). */
export function isRecoverableFormat(f: EncryptedFormat): boolean {
  return f === 'zip' || f === '7z' || f === 'rar' || f === 'pdf' || f === 'office-ooxml' || f === 'office-legacy';
}
