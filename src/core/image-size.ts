// Image dimensions from the file header only (pure): PNG, GIF, BMP, WebP, JPEG. Used to refuse
// "decompression bombs" (a small file that expands to a gigantic bitmap) before anything decodes them.

export interface ImageSize {
  width: number;
  height: number;
}

export function imageSize(b: Uint8Array): ImageSize | null {
  const u16be = (i: number) => (b[i]! << 8) | b[i + 1]!;
  const u16le = (i: number) => b[i]! | (b[i + 1]! << 8);
  const u32be = (i: number) => ((b[i]! << 24) >>> 0) + (b[i + 1]! << 16) + (b[i + 2]! << 8) + b[i + 3]!;
  const i32le = (i: number) => b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16) | (b[i + 3]! << 24);
  const u24le = (i: number) => b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16);
  const has = (n: number) => b.length >= n;

  // PNG: IHDR is the first chunk.
  if (has(24) && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return { width: u32be(16), height: u32be(20) };
  // GIF: logical screen size.
  if (has(10) && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return { width: u16le(6), height: u16le(8) };
  // BMP: BITMAPINFOHEADER (height is negative for top-down bitmaps).
  if (has(26) && b[0] === 0x42 && b[1] === 0x4d) return { width: Math.abs(i32le(18)), height: Math.abs(i32le(22)) };
  // WebP: RIFF....WEBP + VP8 / VP8L / VP8X.
  if (has(30) && b[0] === 0x52 && b[1] === 0x49 && b[8] === 0x57 && b[9] === 0x45) {
    const chunk = String.fromCharCode(b[12]!, b[13]!, b[14]!, b[15]!);
    if (chunk === 'VP8X') return { width: u24le(24) + 1, height: u24le(27) + 1 };
    if (chunk === 'VP8L') {
      const bits = b[21]! | (b[22]! << 8) | (b[23]! << 16) | (b[24]! << 24);
      return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
    }
    if (chunk === 'VP8 ') return { width: u16le(26) & 0x3fff, height: u16le(28) & 0x3fff };
    return null;
  }
  // JPEG: walk the markers up to the first start-of-frame.
  if (has(4) && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) return null;
      const m = b[i + 1]!;
      if (m === 0xff) {
        i++;
        continue;
      }
      if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) {
        i += 2;
        continue;
      }
      if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { width: u16be(i + 7), height: u16be(i + 5) };
      i += 2 + u16be(i + 2);
    }
  }
  return null;
}
