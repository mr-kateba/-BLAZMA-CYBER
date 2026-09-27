// Byte helpers for the packet parsers (pure). Out-of-range reads return 0 so a truncated or hostile
// frame can never throw from arithmetic; parsers check lengths before trusting what they read.

export const u8 = (b: Uint8Array, i: number): number => b[i] ?? 0;
export const u16 = (b: Uint8Array, i: number): number => (u8(b, i) << 8) | u8(b, i + 1);
export const u32 = (b: Uint8Array, i: number): number => ((u8(b, i) << 24) | (u8(b, i + 1) << 16) | (u8(b, i + 2) << 8) | u8(b, i + 3)) >>> 0;
export const u16le = (b: Uint8Array, i: number): number => u8(b, i) | (u8(b, i + 1) << 8);
export const u32le = (b: Uint8Array, i: number): number => (u8(b, i) | (u8(b, i + 1) << 8) | (u8(b, i + 2) << 16) | (u8(b, i + 3) << 24)) >>> 0;

export function ipv4At(b: Uint8Array, i: number): string {
  return `${u8(b, i)}.${u8(b, i + 1)}.${u8(b, i + 2)}.${u8(b, i + 3)}`;
}

/** RFC 5952 text form (longest zero run collapsed to "::"). */
export function ipv6At(b: Uint8Array, i: number): string {
  const groups: string[] = [];
  for (let k = 0; k < 16; k += 2) groups.push(u16(b, i + k).toString(16));
  let bestStart = -1;
  let bestLen = 0;
  for (let k = 0; k < 8; ) {
    if (groups[k] !== '0') {
      k++;
      continue;
    }
    let j = k;
    while (j < 8 && groups[j] === '0') j++;
    if (j - k > bestLen) {
      bestStart = k;
      bestLen = j - k;
    }
    k = j;
  }
  if (bestLen < 2) return groups.join(':');
  return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLen).join(':')}`;
}

export function macAt(b: Uint8Array, i: number): string {
  const parts: string[] = [];
  for (let k = 0; k < 6; k++) parts.push(u8(b, i + k).toString(16).padStart(2, '0').toUpperCase());
  return parts.join(':');
}

const utf8 = new TextDecoder('utf-8', { fatal: false });
export function text(b: Uint8Array, start: number, end: number): string {
  return utf8.decode(b.subarray(start, Math.min(end, b.length)));
}

/** Printable ASCII only (for names shown in the UI), or null. */
export function printable(s: string, max = 253): string | null {
  return s.length > 0 && s.length <= max && /^[\x20-\x7e]+$/.test(s) ? s : null;
}
