// Read-only parser for Microsoft Compound File Binary (CFB / OLE2) containers — the format of Outlook
// .msg files (MS-CFB). Pure and platform-neutral.
//
// SECURITY: the file is untrusted. Every sector number is bounds-checked, every chain is walked with a
// length limit (a loop in the FAT can't hang the parser), the directory tree is visited at most once
// per entry and the number of entries is capped. Nothing is executed; bytes are only copied out.

export const CFB_SIGNATURE = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

const MAXREGSECT = 0xfffffffa;
const ENDOFCHAIN = 0xfffffffe;
const NOSTREAM = 0xffffffff;
const MAX_ENTRIES = 50_000;

export class CfbError extends Error {
  readonly code = 'email_msg_invalid';
  constructor(detail: string) {
    super(`cfb: ${detail}`);
  }
}

export interface CfbEntry {
  name: string;
  kind: 'root' | 'storage' | 'stream';
  size: number;
  children: CfbEntry[];
  /** Stream bytes (empty for storages). Read on demand. */
  data(): Buffer;
}

export function isCfb(buf: Buffer): boolean {
  return buf.length >= 512 && buf.subarray(0, 8).equals(CFB_SIGNATURE);
}

interface RawEntry {
  name: string;
  type: number;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

export function readCfb(buf: Buffer): CfbEntry {
  if (!isCfb(buf)) throw new CfbError('signature');
  const sectorShift = buf.readUInt16LE(0x1e);
  if (sectorShift !== 9 && sectorShift !== 12) throw new CfbError('sector size');
  if (buf.readUInt16LE(0x20) !== 6) throw new CfbError('mini sector size');
  const ss = 1 << sectorShift;
  const numFat = buf.readUInt32LE(0x2c);
  const dirStart = buf.readUInt32LE(0x30);
  const cutoff = buf.readUInt32LE(0x38);
  const miniFatStart = buf.readUInt32LE(0x3c);
  const numDifat = buf.readUInt32LE(0x48);
  let difat = buf.readUInt32LE(0x44);

  // Writers may leave the last sector short; it is still addressable (reads are bounds-checked).
  const sectorCount = Math.ceil((buf.length - ss) / ss);
  if (sectorCount <= 0 || numFat === 0 || numFat > sectorCount) throw new CfbError('fat count');
  const sectorAt = (n: number): Buffer => {
    if (n > MAXREGSECT || n >= sectorCount) throw new CfbError('sector out of range');
    const off = (n + 1) * ss;
    const s = buf.subarray(off, off + ss);
    return s.length === ss ? s : Buffer.concat([s, Buffer.alloc(ss - s.length)]);
  };

  // FAT sector list: 109 entries in the header, then the DIFAT chain.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109 && fatSectors.length < numFat; i++) fatSectors.push(buf.readUInt32LE(0x4c + i * 4));
  for (let hops = 0; fatSectors.length < numFat; hops++) {
    if (difat > MAXREGSECT || hops > numDifat || hops > sectorCount) throw new CfbError('difat');
    const sec = sectorAt(difat);
    for (let j = 0; j < ss / 4 - 1 && fatSectors.length < numFat; j++) fatSectors.push(sec.readUInt32LE(j * 4));
    difat = sec.readUInt32LE(ss - 4);
  }
  const fat = new Uint32Array(numFat * (ss / 4));
  fatSectors.forEach((s, i) => {
    const sec = sectorAt(s);
    for (let j = 0; j < ss / 4; j++) fat[i * (ss / 4) + j] = sec.readUInt32LE(j * 4);
  });

  const chain = (table: Uint32Array, start: number, limit: number): number[] => {
    const out: number[] = [];
    for (let s = start; s !== ENDOFCHAIN; s = table[s]!) {
      if (s > MAXREGSECT || s >= table.length || out.length >= limit) throw new CfbError('chain');
      out.push(s);
    }
    return out;
  };
  const readRegular = (start: number, size?: number): Buffer => {
    const data = Buffer.concat(chain(fat, start, sectorCount).map(sectorAt));
    if (size === undefined) return data;
    if (data.length < size) throw new CfbError('short stream');
    return data.subarray(0, size);
  };

  // Directory.
  const dir = readRegular(dirStart);
  const entries: RawEntry[] = [];
  for (let off = 0; off + 128 <= dir.length && entries.length < MAX_ENTRIES; off += 128) {
    const nameLen = Math.min(64, dir.readUInt16LE(off + 64));
    const sizeHigh = dir.readUInt32LE(off + 124);
    entries.push({
      name: dir.toString('utf16le', off, off + Math.max(0, nameLen - 2)),
      type: dir[off + 66]!,
      left: dir.readUInt32LE(off + 68),
      right: dir.readUInt32LE(off + 72),
      child: dir.readUInt32LE(off + 76),
      start: dir.readUInt32LE(off + 116),
      // Version-3 files may leave garbage in the high half; nothing we read is ≥ 4 GB.
      size: sectorShift === 9 ? dir.readUInt32LE(off + 120) : sizeHigh === 0 ? dir.readUInt32LE(off + 120) : Number.MAX_SAFE_INTEGER,
    });
  }
  const rootRaw = entries[0];
  if (!rootRaw || rootRaw.type !== 5) throw new CfbError('root');

  // Mini stream (small streams live here, in 64-byte mini sectors).
  let miniStream: Buffer | null = null;
  let miniFat: Uint32Array | null = null;
  const readMini = (start: number, size: number): Buffer => {
    if (!miniStream) miniStream = rootRaw.size > 0 ? readRegular(rootRaw.start, rootRaw.size) : Buffer.alloc(0);
    if (!miniFat) {
      const raw = miniFatStart === ENDOFCHAIN ? Buffer.alloc(0) : readRegular(miniFatStart);
      miniFat = new Uint32Array(raw.length / 4);
      for (let i = 0; i < miniFat.length; i++) miniFat[i] = raw.readUInt32LE(i * 4);
    }
    const ms = miniStream;
    const parts = chain(miniFat, start, Math.ceil(ms.length / 64) + 1).map((s) => {
      if ((s + 1) * 64 > ms.length) throw new CfbError('mini sector out of range');
      return ms.subarray(s * 64, (s + 1) * 64);
    });
    const data = Buffer.concat(parts);
    if (data.length < size) throw new CfbError('short mini stream');
    return data.subarray(0, size);
  };

  // Tree: each storage's children form a (red-black) binary tree via left/right siblings.
  const used = new Set<number>([0]);
  const build = (idx: number, depth: number): CfbEntry => {
    if (depth > 32) throw new CfbError('nesting');
    const e = entries[idx]!;
    const kind = e.type === 5 ? 'root' : e.type === 1 ? 'storage' : 'stream';
    const children: CfbEntry[] = [];
    if (kind !== 'stream') {
      const stack = [e.child];
      while (stack.length) {
        const c = stack.pop()!;
        if (c === NOSTREAM) continue;
        if (c >= entries.length || used.has(c)) throw new CfbError('directory tree');
        used.add(c);
        const ce = entries[c]!;
        stack.push(ce.right, ce.left);
        if (ce.type === 1 || ce.type === 2) children.push(build(c, depth + 1));
      }
      children.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    }
    return {
      name: e.name,
      kind,
      size: kind === 'stream' ? e.size : 0,
      children,
      data: () => {
        if (kind !== 'stream' || e.size === 0) return Buffer.alloc(0);
        if (e.size > buf.length) throw new CfbError('stream size');
        return e.size < cutoff ? readMini(e.start, e.size) : readRegular(e.start, e.size);
      },
    };
  };
  return build(0, 0);
}
