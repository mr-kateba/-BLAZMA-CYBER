// Real file type detection from magic bytes (the extension is never trusted).

export interface FileTypeInfo {
  /** Stable id used for i18n and logic. */
  id: string;
  mime: string;
  description: string;
}

interface Magic {
  offset: number;
  bytes: number[];
  info: FileTypeInfo;
}

const t = (id: string, mime: string, description: string): FileTypeInfo => ({ id, mime, description });
const ascii = (s: string) => [...s].map((ch) => ch.charCodeAt(0));

const MAGICS: Magic[] = [
  { offset: 0, bytes: [0x4d, 0x5a], info: t('pe', 'application/vnd.microsoft.portable-executable', 'Windows PE (MZ)') },
  { offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46], info: t('elf', 'application/x-elf', 'ELF executable') },
  { offset: 0, bytes: [0x25, 0x50, 0x44, 0x46, 0x2d], info: t('pdf', 'application/pdf', 'PDF document') },
  { offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04], info: t('zip', 'application/zip', 'ZIP archive (or OOXML/JAR/APK)') },
  { offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06], info: t('zip', 'application/zip', 'ZIP archive (empty)') },
  { offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], info: t('rar', 'application/vnd.rar', 'RAR archive') },
  { offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], info: t('7z', 'application/x-7z-compressed', '7-Zip archive') },
  { offset: 0, bytes: [0x1f, 0x8b], info: t('gzip', 'application/gzip', 'GZIP compressed') },
  { offset: 0, bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], info: t('ole', 'application/x-ole-storage', 'OLE2 compound document (legacy Office/MSI)') },
  { offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47], info: t('png', 'image/png', 'PNG image') },
  { offset: 0, bytes: [0xff, 0xd8, 0xff], info: t('jpeg', 'image/jpeg', 'JPEG image') },
  { offset: 0, bytes: ascii('GIF8'), info: t('gif', 'image/gif', 'GIF image') },
  { offset: 0, bytes: ascii('MSCF'), info: t('cab', 'application/vnd.ms-cab-compressed', 'Microsoft Cabinet') },
  { offset: 0, bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], info: t('lnk', 'application/x-ms-shortcut', 'Windows shortcut (LNK)') },
  { offset: 0, bytes: ascii('{\\rtf'), info: t('rtf', 'application/rtf', 'Rich Text Format') },
  { offset: 257, bytes: ascii('ustar'), info: t('tar', 'application/x-tar', 'TAR archive') },
];

function matches(buf: Uint8Array, m: Magic): boolean {
  if (buf.length < m.offset + m.bytes.length) return false;
  return m.bytes.every((b, i) => buf[m.offset + i] === b);
}

/** Heuristic: mostly printable UTF-8 / ASCII => text. */
function looksLikeText(buf: Uint8Array): boolean {
  if (buf.length === 0) return false;
  let printable = 0;
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) {
    const b = buf[i]!;
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f) || b >= 0x80) printable++;
  }
  return printable / n > 0.95;
}

/** Detects type from the first bytes of a file (pass at least 512 bytes when available). */
export function detectFileType(head: Uint8Array): FileTypeInfo {
  for (const m of MAGICS) if (matches(head, m)) return m.info;
  if (head.length === 0) return t('empty', 'application/x-empty', 'Empty file');
  if (looksLikeText(head)) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(head.slice(0, 512)).trimStart().toLowerCase();
    if (text.startsWith('<!doctype html') || text.startsWith('<html')) return t('html', 'text/html', 'HTML document');
    if (text.startsWith('<?xml')) return t('xml', 'application/xml', 'XML document');
    if (text.startsWith('#!')) return t('script', 'text/x-script', 'Script with shebang');
    return t('text', 'text/plain', 'Text');
  }
  return t('unknown', 'application/octet-stream', 'Unknown binary data');
}
