// Encrypted-file detection (pure, no I/O). Given the first bytes and the size of a file, report
// whether it is encrypted, the container format, and the encryption scheme/strength.
//
// This is defensive triage: an analyst or the owner of a file can see "this archive is AES-256"
// vs "this is legacy ZipCrypto", or that a PDF/Office document is password-protected. It does NOT
// attempt recovery; the Password Recovery workspace hands protected files the owner is authorized
// to recover to a separately installed external engine.

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

function detect7z(head: Uint8Array): EncryptionInfo | null {
  // 7z signature: 37 7A BC AF 27 1C. Whether the content/headers are encrypted lives deeper in the
  // archive, so from the header alone we can only say it's a 7z container (AES-256 when encrypted).
  if (!starts(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return null;
  return { encrypted: false, format: '7z', scheme: '7z-aes', strength: 'strong', notes: ['recovery.note.sevenZip'] };
}

function detectRar(head: Uint8Array): EncryptionInfo | null {
  const v5 = starts(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]);
  const v4 = starts(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]);
  if (!v5 && !v4) return null;
  return { encrypted: false, format: 'rar', scheme: v5 ? 'rar5-aes' : 'rar4', strength: v5 ? 'strong' : 'weak', notes: [v5 ? 'recovery.note.rar5' : 'recovery.note.rar4'] };
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

function detectOffice(head: Uint8Array): EncryptionInfo | null {
  // Modern Office (docx/xlsx/pptx) encryption wraps the OOXML in an OLE2 compound file
  // (D0 CF 11 E0...) containing an "EncryptionInfo" stream (agile/standard AES).
  if (starts(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    const text = new TextDecoder('latin1').decode(head);
    // The EncryptionInfo/EncryptedPackage stream names appear (UTF-16) early in the container.
    const looksEncrypted = /E\0n\0c\0r\0y\0p\0t/.test(text) || head.length > 0;
    return { encrypted: looksEncrypted, format: 'office-legacy', scheme: 'office-agile', strength: 'strong', notes: ['recovery.note.officeAgile'] };
  }
  return null;
}

/**
 * Detects encryption from a file's header (pass >= 32 bytes; pass the whole buffer for PDFs so the
 * /Encrypt dictionary can be found).
 */
export function detectEncryption(head: Uint8Array, full?: Uint8Array): EncryptionInfo {
  return (
    detectZip(head) ??
    detect7z(head) ??
    detectRar(head) ??
    detectPdf(head, full) ??
    detectOffice(head) ?? { encrypted: false, format: 'unknown', scheme: null, strength: 'unknown', notes: [] }
  );
}

/** Formats a supported external engine could work with (informational; engine must be user-installed). */
export function isRecoverableFormat(f: EncryptedFormat): boolean {
  return f === 'zip' || f === '7z' || f === 'rar' || f === 'pdf' || f === 'office-ooxml' || f === 'office-legacy';
}
