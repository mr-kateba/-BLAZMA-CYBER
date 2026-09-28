// Test-only writer for Compound File Binary (MS-CFB v3, 512-byte sectors) — builds real .msg-shaped
// containers for the parser tests. Small streams go to the mini stream exactly like Outlook writes them.

export interface CfbNode {
  name: string;
  data?: Buffer; // stream when set, storage otherwise
  children?: CfbNode[];
}

const SS = 512;
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const FATSECT = 0xfffffffd;
const NOSTREAM = 0xffffffff;

interface Flat {
  node: CfbNode;
  type: number;
  child: number;
  right: number;
  start: number;
  size: number;
}

export function writeCfb(children: CfbNode[]): Buffer {
  const flat: Flat[] = [];
  const add = (node: CfbNode, type: number): number => {
    const idx = flat.length;
    flat.push({ node, type, child: NOSTREAM, right: NOSTREAM, start: ENDOFCHAIN, size: node.data?.length ?? 0 });
    const kids = node.children ?? [];
    let prev = -1;
    for (const k of kids) {
      const ki = add(k, k.data ? 2 : 1);
      if (prev < 0) flat[idx]!.child = ki;
      else flat[prev]!.right = ki; // degenerate (right-leaning) sibling tree: valid for readers
      prev = ki;
    }
    return idx;
  };
  add({ name: 'Root Entry', children }, 5);

  // Mini stream for streams < 4096 bytes.
  const mini: Buffer[] = [];
  const miniFat: number[] = [];
  const big: Flat[] = [];
  for (const f of flat) {
    if (f.type !== 2 || f.size === 0) continue;
    if (f.size < 4096) {
      const first = miniFat.length;
      const n = Math.ceil(f.size / 64);
      for (let i = 0; i < n; i++) miniFat.push(i === n - 1 ? ENDOFCHAIN : first + i + 1);
      const padded = Buffer.alloc(n * 64);
      f.node.data!.copy(padded);
      mini.push(padded);
      f.start = first;
    } else big.push(f);
  }
  const miniStream = Buffer.concat(mini);

  const dirSectors = Math.ceil((flat.length * 128) / SS);
  const miniFatSectors = Math.ceil((miniFat.length * 4) / SS);
  const miniStreamSectors = Math.ceil(miniStream.length / SS);
  const bigSectors = big.map((f) => Math.ceil(f.size / SS));
  const dataSectors = dirSectors + miniFatSectors + miniStreamSectors + bigSectors.reduce((a, b) => a + b, 0);
  let fatSectors = 1;
  while (fatSectors * (SS / 4) < fatSectors + dataSectors) fatSectors++;
  if (fatSectors > 109) throw new Error('test writer: too large');

  const fat: number[] = [];
  for (let i = 0; i < fatSectors; i++) fat.push(FATSECT);
  const alloc = (count: number): number => {
    if (count === 0) return ENDOFCHAIN;
    const start = fat.length;
    for (let i = 0; i < count; i++) fat.push(i === count - 1 ? ENDOFCHAIN : start + i + 1);
    return start;
  };
  const dirStart = alloc(dirSectors);
  const miniFatStart = alloc(miniFatSectors);
  const miniStreamStart = alloc(miniStreamSectors);
  big.forEach((f, i) => (f.start = alloc(bigSectors[i]!)));
  flat[0]!.start = miniStreamStart;
  flat[0]!.size = miniStream.length;

  const total = fat.length;
  const out = Buffer.alloc(SS * (1 + total));
  // Header
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(out, 0);
  out.writeUInt16LE(0x3e, 0x18);
  out.writeUInt16LE(3, 0x1a);
  out.writeUInt16LE(0xfffe, 0x1c);
  out.writeUInt16LE(9, 0x1e);
  out.writeUInt16LE(6, 0x20);
  out.writeUInt32LE(fatSectors, 0x2c);
  out.writeUInt32LE(dirStart, 0x30);
  out.writeUInt32LE(4096, 0x38);
  out.writeUInt32LE(miniFatSectors ? miniFatStart : ENDOFCHAIN, 0x3c);
  out.writeUInt32LE(miniFatSectors, 0x40);
  out.writeUInt32LE(ENDOFCHAIN, 0x44);
  out.writeUInt32LE(0, 0x48);
  for (let i = 0; i < 109; i++) out.writeUInt32LE(i < fatSectors ? i : FREESECT, 0x4c + i * 4);

  const sectorOff = (n: number) => SS * (n + 1);
  // FAT
  for (let i = 0; i < fatSectors * (SS / 4); i++) out.writeUInt32LE(fat[i] ?? FREESECT, sectorOff(0) + i * 4);
  // Directory
  const dirBuf = Buffer.alloc(dirSectors * SS);
  flat.forEach((f, i) => {
    const o = i * 128;
    const name = Buffer.from(`${f.node.name}\0`, 'utf16le');
    name.copy(dirBuf, o, 0, Math.min(64, name.length));
    dirBuf.writeUInt16LE(Math.min(64, name.length), o + 64);
    dirBuf[o + 66] = f.type;
    dirBuf[o + 67] = 1;
    dirBuf.writeUInt32LE(NOSTREAM, o + 68);
    dirBuf.writeUInt32LE(f.right, o + 72);
    dirBuf.writeUInt32LE(f.child, o + 76);
    dirBuf.writeUInt32LE(f.start, o + 116);
    dirBuf.writeUInt32LE(f.size, o + 120);
  });
  for (let i = flat.length; i < dirSectors * 4; i++) {
    dirBuf.writeUInt32LE(NOSTREAM, i * 128 + 68);
    dirBuf.writeUInt32LE(NOSTREAM, i * 128 + 72);
    dirBuf.writeUInt32LE(NOSTREAM, i * 128 + 76);
  }
  dirBuf.copy(out, sectorOff(dirStart));
  // Mini FAT + mini stream
  if (miniFatSectors) {
    const mf = Buffer.alloc(miniFatSectors * SS, 0xff);
    miniFat.forEach((v, i) => mf.writeUInt32LE(v, i * 4));
    mf.copy(out, sectorOff(miniFatStart));
  }
  if (miniStreamSectors) miniStream.copy(out, sectorOff(miniStreamStart));
  for (const f of big) f.node.data!.copy(out, sectorOff(f.start));
  return out;
}

// ---- .msg helpers

export const prop = (id: number, type: string) => `__substg1.0_${id.toString(16).toUpperCase().padStart(4, '0')}${type}`;
export const u16 = (s: string) => Buffer.from(s, 'utf16le');

/** `__properties_version1.0` with fixed-size values (PT_LONG / PT_SYSTIME). */
export function propsStream(headerSize: number, values: { id: number; type: number; value: Buffer }[]): CfbNode {
  const b = Buffer.alloc(headerSize + values.length * 16);
  values.forEach((v, i) => {
    const o = headerSize + i * 16;
    b.writeUInt32LE(((v.id << 16) | v.type) >>> 0, o);
    b.writeUInt32LE(6, o + 4);
    v.value.copy(b, o + 8);
  });
  return { name: '__properties_version1.0', data: b };
}

export const long = (n: number) => {
  const b = Buffer.alloc(8);
  b.writeInt32LE(n, 0);
  return b;
};

export const filetime = (d: Date) => {
  const ticks = BigInt(d.getTime() + 11_644_473_600_000) * 10_000n;
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(ticks, 0);
  return b;
};
