import { describe, expect, it } from 'vitest';
import { shannonEntropy, entropyLabel } from '../src/core/entropy';
import { extractAsciiStrings, extractIocs } from '../src/core/ioc';
import { detectFileType } from '../src/core/filetype';
import { parsePe } from '../src/core/pe';
import { assess } from '../src/core/detection';

describe('entropy', () => {
  it('is 0 for uniform data and 8 for all byte values', () => {
    expect(shannonEntropy(new Uint8Array(1000))).toBe(0);
    const all = new Uint8Array(256 * 4).map((_, i) => i % 256);
    expect(shannonEntropy(all)).toBeCloseTo(8, 6);
    expect(entropyLabel(7.9)).toBe('high');
    expect(entropyLabel(3)).toBe('low');
  });
});

describe('IOC extraction', () => {
  it('extracts urls, ips, domains, emails', () => {
    const text = 'connect http://evil.example.com/a?b=1 then 10.0.0.5 and 8.8.8.8; mail ops@corp.example.org; see update.contoso.net';
    const r = extractIocs(text);
    expect(r.urls).toEqual(['http://evil.example.com/a?b=1']);
    expect(r.ipv4).toEqual(['10.0.0.5', '8.8.8.8']);
    expect(r.emails).toEqual(['ops@corp.example.org']);
    expect(r.domains).toContain('evil.example.com');
    expect(r.domains).toContain('update.contoso.net');
    expect(r.domains).not.toContain('corp.example.org');
  });
  it('extracts ascii strings', () => {
    const bytes = new Uint8Array([0, 0, ...Buffer.from('hello world'), 0, 1, ...Buffer.from('abc'), 0]);
    expect(extractAsciiStrings(bytes)).toEqual(['hello world']);
  });
});

describe('file type detection', () => {
  it('uses magic bytes, not extensions', () => {
    expect(detectFileType(Buffer.from('%PDF-1.7\n')).id).toBe('pdf');
    expect(detectFileType(Buffer.from([0x50, 0x4b, 3, 4, 0])).id).toBe('zip');
    expect(detectFileType(Buffer.from('MZ\x90\x00')).id).toBe('pe');
    expect(detectFileType(Buffer.from('<!DOCTYPE html><html>')).id).toBe('html');
    expect(detectFileType(Buffer.from('plain text here')).id).toBe('text');
    expect(detectFileType(new Uint8Array(0)).id).toBe('empty');
    expect(detectFileType(new Uint8Array([0, 1, 2, 0xff, 0])).id).toBe('unknown');
  });
});

/** Builds a minimal but structurally valid PE32+ image with one section and one import. */
function buildTestPe(): Uint8Array {
  const buf = new Uint8Array(0x600);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x00004550, true);
  const coff = 0x84;
  dv.setUint16(coff, 0x8664, true); // x64
  dv.setUint16(coff + 2, 1, true); // 1 section
  dv.setUint32(coff + 4, 1700000000, true);
  dv.setUint16(coff + 16, 240, true); // optional header size
  dv.setUint16(coff + 18, 0x0022, true); // EXE
  const opt = coff + 20;
  dv.setUint16(opt, 0x20b, true);
  dv.setUint32(opt + 16, 0x1000, true);
  dv.setUint16(opt + 68, 3, true); // console
  dv.setUint32(opt + 108, 16, true); // number of data dirs
  const dd = opt + 112;
  dv.setUint32(dd + 8, 0x1100, true); // import dir RVA
  dv.setUint32(dd + 12, 40, true);
  const sec = opt + 240;
  buf.set(Buffer.from('.text'), sec);
  dv.setUint32(sec + 8, 0x400, true); // vsize
  dv.setUint32(sec + 12, 0x1000, true); // VA
  dv.setUint32(sec + 16, 0x400, true); // raw size
  dv.setUint32(sec + 20, 0x200, true); // raw offset
  dv.setUint32(sec + 36, 0x60000020, true); // code|exec|read
  // Import descriptor at RVA 0x1100 -> file 0x300
  const desc = 0x300;
  dv.setUint32(desc, 0x1180, true); // OriginalFirstThunk
  dv.setUint32(desc + 12, 0x11c0, true); // Name RVA
  dv.setUint32(desc + 16, 0x1180, true);
  // Thunk array at 0x1180 -> 0x380: one entry pointing to hint/name at 0x11d0
  dv.setUint32(0x380, 0x11d0, true);
  buf.set(Buffer.from('KERNEL32.dll\0'), 0x3c0);
  buf.set(Buffer.from('\0\0GetTickCount\0'), 0x3d0);
  return buf;
}

describe('PE parser', () => {
  it('parses a synthetic PE32+', () => {
    const r = parsePe(buildTestPe());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.pe.machine).toBe('x64');
    expect(r.pe.is64).toBe(true);
    expect(r.pe.isDll).toBe(false);
    expect(r.pe.subsystem).toBe('windows_cui');
    expect(r.pe.sections).toHaveLength(1);
    expect(r.pe.sections[0]!.name).toBe('.text');
    expect(r.pe.sections[0]!.executable).toBe(true);
    expect(r.pe.imports).toEqual([{ dll: 'KERNEL32.dll', functions: ['GetTickCount'] }]);
    expect(r.pe.hasSignatureDirectory).toBe(false);
  });
  it('rejects non-PE and truncated input without throwing', () => {
    expect(parsePe(Buffer.from('hello'))).toEqual({ ok: false, reason: 'not_mz' });
    const pe = buildTestPe();
    expect(parsePe(pe.slice(0, 0x90)).ok).toBe(false);
    // Corrupt pointer to PE header far outside the file
    const bad = buildTestPe();
    new DataView(bad.buffer).setUint32(0x3c, 0xfffffff0, true);
    expect(parsePe(bad)).toEqual({ ok: false, reason: 'no_pe_signature' });
  });
  it('survives random garbage after MZ', () => {
    for (let i = 0; i < 200; i++) {
      const g = new Uint8Array(1024).map(() => Math.floor(Math.random() * 256));
      g[0] = 0x4d; g[1] = 0x5a;
      expect(() => parsePe(g)).not.toThrow();
    }
  });
});

describe('detection model', () => {
  const all = new Set(['defender', 'yara', 'signature'] as const);
  it('never claims clean when engines are missing', () => {
    const r = assess([{ source: 'entropy', weight: 'neutral', reasonKey: 'x' }], { availableSources: new Set() });
    expect(r.verdict).toBe('unknown');
    expect(r.incomplete).toBe(true);
  });
  it('one weak signal alone is not suspicious', () => {
    const r = assess(
      [
        { source: 'defender', weight: 'clean', reasonKey: 'a' },
        { source: 'signature', weight: 'neutral', reasonKey: 'b' },
        { source: 'entropy', weight: 'weak', reasonKey: 'c' },
      ],
      { availableSources: new Set(all) },
    );
    expect(r.verdict).toBe('no_detections');
  });
  it('combined weak + strong signals become suspicious with reasons', () => {
    const r = assess(
      [
        { source: 'yara', weight: 'strong', reasonKey: 'yara_match' },
        { source: 'entropy', weight: 'weak', reasonKey: 'high_entropy' },
      ],
      { availableSources: new Set(all) },
    );
    expect(r.verdict).toBe('suspicious');
    expect(r.reasons.map((x) => x.key)).toEqual(['yara_match', 'high_entropy']);
  });
  it('Defender detection is malicious', () => {
    const r = assess([{ source: 'defender', weight: 'malicious', reasonKey: 'def' }], { availableSources: new Set(all) });
    expect(r.verdict).toBe('malicious');
  });
});
