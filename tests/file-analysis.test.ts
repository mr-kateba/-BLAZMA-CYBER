import { describe, expect, it, vi, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));

import { analyzeFile, hashFile, hashText, buildSignals, pickInterestingStrings, yaraWeight } from '../src/main/services/file-analysis';

let dir: string;
beforeAll(() => { dir = mkdtempSync(join(tmpdir(), 'blazma-test-')); });
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const noSig = { verifySignature: async () => ({ checked: false as const, reason: 'unsupported_platform' }) };

describe('file hashing', () => {
  it('matches Node crypto for all algorithms', async () => {
    const data = Buffer.alloc(3 * 1024 * 1024 + 17, 7);
    const f = join(dir, 'a.bin');
    writeFileSync(f, data);
    const r = await hashFile(f, new AbortController().signal, () => {});
    for (const algo of ['md5', 'sha1', 'sha256', 'sha512'] as const) {
      expect(r[algo]).toBe(createHash(algo).update(data).digest('hex'));
    }
    expect(r.sizeBytes).toBe(data.length);
  });
  it('known vectors for text', () => {
    expect(hashText('abc').md5).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(hashText('abc').sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hashText('').sha1).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  });
  it('supports cancellation', async () => {
    const f = join(dir, 'big.bin');
    writeFileSync(f, Buffer.alloc(8 * 1024 * 1024));
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(hashFile(f, ctrl.signal, () => {})).rejects.toMatchObject({ code: 'cancelled' });
  });
  it('reports clean errors for bad paths', async () => {
    const s = new AbortController().signal;
    await expect(hashFile('relative.txt', s, () => {})).rejects.toMatchObject({ code: 'path_not_absolute' });
    await expect(hashFile(join(dir, 'nope'), s, () => {})).rejects.toMatchObject({ code: 'file_not_found' });
    await expect(hashFile(dir, s, () => {})).rejects.toMatchObject({ code: 'not_a_file' });
  });
});

describe('file analysis', () => {
  it('analyzes a text file with indicators and never claims it is clean without engines', async () => {
    const f = join(dir, 'note.txt');
    writeFileSync(f, 'visit https://update.example.net/x and 203.0.113.9\npowershell -nop\n');
    const r = await analyzeFile(f, new AbortController().signal, () => {}, noSig);
    expect(r.type.id).toBe('text');
    expect(r.iocs.urls).toContain('https://update.example.net/x');
    expect(r.iocs.ipv4).toContain('203.0.113.9');
    expect(r.interestingStrings.length).toBe(1);
    expect(r.assessment.verdict).toBe('unknown');
    expect(r.assessment.incomplete).toBe(true);
    expect(r.unavailableEngines.map((e) => e.engine)).toContain('defender');
  });
  it('includes engine results and explains unavailable engines', async () => {
    const f = join(dir, 'eng.txt');
    writeFileSync(f, 'plain');
    const r = await analyzeFile(f, new AbortController().signal, () => {}, {
      ...noSig,
      defender: async () => ({ ran: true, threats: ['Virus:DOS/EICAR_Test_File'] }),
      yara: async () => { throw Object.assign(new Error('x'), { code: 'yara_not_installed' }); },
    });
    expect(r.defender).toEqual({ ran: true, threats: ['Virus:DOS/EICAR_Test_File'] });
    expect(r.yara).toEqual({ ran: false, reason: 'yara_not_installed' });
    expect(r.assessment.verdict).toBe('malicious');
    expect(r.unavailableEngines.map((e) => e.engine)).toEqual(['yara', 'signature', 'hash_reputation']);
  });
  it('maps YARA severity meta to evidence weight', () => {
    expect(yaraWeight({ severity: 'malicious' })).toBe('malicious');
    expect(yaraWeight({ severity: 'info' })).toBe('weak');
    expect(yaraWeight({})).toBe('strong');
    const r = buildSignals({ typeId: 'text', entropy: 1, packerHints: [], signature: { checked: false }, interestingCount: 0,
      yara: { ran: true, rulesUsed: 3, matches: [{ rule: 'R', namespace: 'n', tags: [], meta: { severity: 'suspicious' } }] } });
    expect(r.signals).toEqual([{ source: 'yara', weight: 'strong', reasonKey: 'assessment.reason.yara_match', reasonArgs: { rule: 'R' } }]);
    expect(r.available.has('yara')).toBe(true);
  });
  it('builds signals conservatively', () => {
    const base = { typeId: 'pe', entropy: 7.9, packerHints: ['upx0'], interestingCount: 0 };
    const unsigned = buildSignals({ ...base, signature: { checked: true, status: 'not_signed' } });
    expect(unsigned.signals.map((s) => s.weight)).toEqual(['weak', 'weak', 'weak']);
    const signed = buildSignals({ ...base, signature: { checked: true, status: 'valid', publisher: 'Contoso' } });
    expect(signed.signals[0]!.weight).toBe('clean');
  });
  it('picks interesting strings case-insensitively', () => {
    expect(pickInterestingStrings(['hello', 'C:\\Windows\\System32\\CMD.EXE /c', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'])).toHaveLength(2);
  });
});
