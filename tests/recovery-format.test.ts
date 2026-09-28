import { describe, expect, it } from 'vitest';
import { bareHash, extractorFor, firstHashLine, hashcatHash, hashcatMode, johnHashLine } from '../src/core/recovery-format';

describe('recovery hash format', () => {
  it('maps each supported format to John’s extractor', () => {
    expect(extractorFor('rar')).toMatchObject({ files: ['rar2john.exe', 'rar2john'], compiled: true });
    expect(extractorFor('zip')?.compiled).toBe(true);
    expect(extractorFor('7z')?.compiled).toBe(false);
    expect(extractorFor('pdf')?.compiled).toBe(false);
    expect(extractorFor('office-ooxml')?.files).toEqual(['office2john.py']);
    expect(extractorFor('unknown')).toBeNull();
  });

  it('finds the hash line and strips the file-name prefix (even with a Windows C: path)', () => {
    const out = 'rar2john: making hashes\nC:\\Users\\me\\ملف.rar:$rar5$16$abc$8$def$ghi\n';
    const line = firstHashLine(out)!;
    expect(bareHash(line)).toBe('$rar5$16$abc$8$def$ghi');
    expect(johnHashLine(line)).toBe('target:$rar5$16$abc$8$def$ghi');
    expect(firstHashLine('no hashes here')).toBeNull();
  });

  it('gives hashcat the bare hash without trailing *2john metadata', () => {
    expect(hashcatHash('f.zip:$zip2$*0*3*abc*def*$/zip2$::f.zip')).toBe('$zip2$*0*3*abc*def*$/zip2$');
    expect(hashcatHash('x:$rar5$16$abc$8$def$ghi')).toBe('$rar5$16$abc$8$def$ghi');
  });

  it('maps hash prefixes to hashcat modes, or null when it should defer to John', () => {
    expect(hashcatMode('$rar5$16$abc')).toBe(13000);
    expect(hashcatMode('$RAR3$*0*abc')).toBe(12500);
    expect(hashcatMode('$zip2$*0*')).toBe(13600);
    expect(hashcatMode('$7z$0$abc')).toBe(11600);
    expect(hashcatMode('$office$*2007*x')).toBe(9400);
    expect(hashcatMode('$office$*2010*x')).toBe(9500);
    expect(hashcatMode('$office$*2013*x')).toBe(9600);
    expect(hashcatMode('$pdf$1*abc')).toBeNull();
    expect(hashcatMode('$RAR3$*1*abc')).toBeNull();
  });
});
