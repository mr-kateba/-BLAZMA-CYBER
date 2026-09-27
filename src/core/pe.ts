// Defensive, bounds-checked PE (Portable Executable) header parser.
// It only READS bytes; nothing is ever loaded or executed. Malformed input yields
// { ok: false } with a reason instead of throwing.

import { shannonEntropy } from './entropy.js';

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  entropy: number;
  executable: boolean;
  writable: boolean;
}

export interface PeImport {
  dll: string;
  functions: string[];
}

export interface PeInfo {
  machine: string;
  is64: boolean;
  isDll: boolean;
  subsystem: string;
  timestamp: number;
  entryPoint: number;
  sections: PeSection[];
  imports: PeImport[];
  exports: string[];
  hasSignatureDirectory: boolean;
  /** Section names commonly produced by known packers (informational indicator only). */
  packerHints: string[];
}

export type PeResult = { ok: true; pe: PeInfo } | { ok: false; reason: string };

const MACHINES: Record<number, string> = {
  0x14c: 'x86',
  0x8664: 'x64',
  0xaa64: 'ARM64',
  0x1c4: 'ARMv7',
};

const SUBSYSTEMS: Record<number, string> = {
  1: 'native',
  2: 'windows_gui',
  3: 'windows_cui',
  9: 'windows_ce',
  10: 'efi_application',
  14: 'xbox',
  16: 'boot_application',
};

const PACKER_SECTIONS = ['upx0', 'upx1', 'upx2', '.aspack', '.adata', '.petite', '.mpress1', '.mpress2', '.themida', '.vmp0', '.vmp1', '.nsp0', '.nsp1'];

const MAX_IMPORT_DLLS = 256;
const MAX_FUNCS_PER_DLL = 512;
const MAX_EXPORTS = 2048;

export function parsePe(buf: Uint8Array): PeResult {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const inRange = (off: number, len: number) => off >= 0 && len >= 0 && off + len <= buf.length;
  const u16 = (o: number) => (inRange(o, 2) ? dv.getUint16(o, true) : NaN);
  const u32 = (o: number) => (inRange(o, 4) ? dv.getUint32(o, true) : NaN);

  if (!inRange(0, 64) || u16(0) !== 0x5a4d) return { ok: false, reason: 'not_mz' };
  const peOff = u32(0x3c);
  if (!Number.isFinite(peOff) || !inRange(peOff, 24) || u32(peOff) !== 0x00004550) return { ok: false, reason: 'no_pe_signature' };

  const coff = peOff + 4;
  const machineId = u16(coff);
  const numSections = u16(coff + 2);
  const timestamp = u32(coff + 4);
  const optSize = u16(coff + 16);
  const characteristics = u16(coff + 18);
  const opt = coff + 20;
  const magic = u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) return { ok: false, reason: 'bad_optional_header' };
  const is64 = magic === 0x20b;

  const entryPoint = u32(opt + 16);
  const subsystemId = u16(opt + 68);
  const dataDirOff = opt + (is64 ? 112 : 96);
  const numDirs = u32(dataDirOff - 4);
  const dir = (i: number) =>
    i < numDirs && inRange(dataDirOff + i * 8, 8) ? { rva: u32(dataDirOff + i * 8), size: u32(dataDirOff + i * 8 + 4) } : { rva: 0, size: 0 };

  const secTable = opt + optSize;
  if (numSections > 96 || !inRange(secTable, numSections * 40)) return { ok: false, reason: 'bad_section_table' };

  const sections: PeSection[] = [];
  for (let i = 0; i < numSections; i++) {
    const s = secTable + i * 40;
    const nameBytes = buf.slice(s, s + 8);
    const name = new TextDecoder('latin1').decode(nameBytes).replace(/\0+$/, '');
    const virtualSize = u32(s + 8);
    const virtualAddress = u32(s + 12);
    const rawSize = u32(s + 16);
    const rawOffset = u32(s + 20);
    const ch = u32(s + 36);
    const start = Math.min(rawOffset, buf.length);
    const end = Math.min(rawOffset + rawSize, buf.length);
    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawOffset,
      rawSize,
      entropy: end > start ? shannonEntropy(buf.subarray(start, end)) : 0,
      executable: (ch & 0x20000000) !== 0,
      writable: (ch & 0x80000000) !== 0,
    });
  }

  const rvaToOffset = (rva: number): number => {
    for (const s of sections) {
      const span = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + span) return rva - s.virtualAddress + s.rawOffset;
    }
    return -1;
  };

  const readCString = (off: number, max = 256): string | null => {
    if (off < 0 || off >= buf.length) return null;
    let end = off;
    while (end < buf.length && end - off < max && buf[end] !== 0) end++;
    return new TextDecoder('latin1').decode(buf.subarray(off, end));
  };

  // Imports
  const imports: PeImport[] = [];
  const impDir = dir(1);
  if (impDir.rva) {
    let desc = rvaToOffset(impDir.rva);
    while (desc >= 0 && inRange(desc, 20) && imports.length < MAX_IMPORT_DLLS) {
      const origThunk = u32(desc);
      const nameRva = u32(desc + 12);
      const firstThunk = u32(desc + 16);
      if (!nameRva && !firstThunk) break;
      const dll = readCString(rvaToOffset(nameRva));
      if (!dll) break;
      const functions: string[] = [];
      let thunk = rvaToOffset(origThunk || firstThunk);
      const step = is64 ? 8 : 4;
      while (thunk >= 0 && inRange(thunk, step) && functions.length < MAX_FUNCS_PER_DLL) {
        const lo = u32(thunk);
        const hi = is64 ? u32(thunk + 4) : 0;
        if (lo === 0 && hi === 0) break;
        const byOrdinal = is64 ? (hi & 0x80000000) !== 0 : (lo & 0x80000000) !== 0;
        if (byOrdinal) functions.push(`#${lo & 0xffff}`);
        else {
          const fn = readCString(rvaToOffset(lo) + 2);
          if (fn) functions.push(fn);
        }
        thunk += step;
      }
      imports.push({ dll, functions });
      desc += 20;
    }
  }

  // Exports
  const exports: string[] = [];
  const expDir = dir(0);
  if (expDir.rva) {
    const e = rvaToOffset(expDir.rva);
    if (e >= 0 && inRange(e, 40)) {
      const numNames = Math.min(u32(e + 24), MAX_EXPORTS);
      const namesOff = rvaToOffset(u32(e + 32));
      for (let i = 0; i < numNames && namesOff >= 0 && inRange(namesOff + i * 4, 4); i++) {
        const n = readCString(rvaToOffset(u32(namesOff + i * 4)));
        if (n) exports.push(n);
      }
    }
  }

  const lowerNames = sections.map((s) => s.name.toLowerCase());
  return {
    ok: true,
    pe: {
      machine: MACHINES[machineId] ?? `0x${machineId.toString(16)}`,
      is64,
      isDll: (characteristics & 0x2000) !== 0,
      subsystem: SUBSYSTEMS[subsystemId] ?? `unknown_${subsystemId}`,
      timestamp,
      entryPoint,
      sections,
      imports,
      exports,
      hasSignatureDirectory: dir(4).size > 0,
      packerHints: PACKER_SECTIONS.filter((p) => lowerNames.includes(p)),
    },
  };
}
