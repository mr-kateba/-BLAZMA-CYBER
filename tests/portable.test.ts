import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PORTABLE_MARKER, portableDirFor } from '../src/main/services/paths';

describe('Portable mode', () => {
  it('is on only for a packaged copy with portable.txt next to the executable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'blazma-portable-'));
    const exe = join(dir, 'Blazma Cyber.exe');
    expect(portableDirFor(exe, true)).toBeNull();
    writeFileSync(join(dir, PORTABLE_MARKER), 'x');
    expect(portableDirFor(exe, true)).toBe(join(dir, 'Blazma-data'));
    expect(portableDirFor(exe, false)).toBeNull(); // development runs never switch
  });
});
