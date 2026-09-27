import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let dataDir: string;
vi.mock('electron', () => ({ app: { getPath: () => dataDir }, safeStorage: {} }));

import { QuarantineService } from '../src/main/services/quarantine';

let workDir: string;
beforeAll(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'blazma-q-data-'));
  workDir = mkdtempSync(join(tmpdir(), 'blazma-q-work-'));
});
afterAll(() => {
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(workDir, { recursive: true, force: true });
});

function makeFile(name: string, content: Buffer | string): string {
  const p = join(workDir, name);
  writeFileSync(p, content);
  return p;
}

describe('quarantine', () => {
  let q: QuarantineService;
  beforeEach(() => {
    // Fresh index per test by clearing the quarantine dir
    rmSync(join(dataDir, 'quarantine'), { recursive: true, force: true });
    q = new QuarantineService();
  });

  it('quarantines a file: removes original, stores neutralized blob, records metadata', async () => {
    const content = Buffer.from('MZ\x90\x00 this looks like a PE header ' + 'A'.repeat(5000));
    const sha = createHash('sha256').update(content).digest('hex');
    const p = makeFile('evil.exe', content);

    const entry = await q.quarantine(p, 'test');
    expect(existsSync(p)).toBe(false); // original removed
    expect(entry.originalName).toBe('evil.exe');
    expect(entry.sizeBytes).toBe(content.length);
    expect(entry.sha256).toBe(sha);
    expect(entry.typeId).toBe('pe');

    // Stored blob is neutralized: it must NOT start with the MZ magic
    const qdir = join(dataDir, 'quarantine');
    const blob = readdirSync(qdir).find((f) => f.endsWith('.blazmaq'))!;
    const stored = readFileSync(join(qdir, blob));
    expect(stored[0]).not.toBe(0x4d);
    expect(stored[0]).toBe(0x4d ^ 0xff);
    expect(q.list()).toHaveLength(1);
  });

  it('restores exact original bytes and verifies the hash', async () => {
    const content = Buffer.from(Buffer.alloc(3 * 1024 * 1024 + 123).map((_, i) => (i * 7) % 256));
    const p = makeFile('sample.bin', content);
    const sha = createHash('sha256').update(content).digest('hex');
    const entry = await q.quarantine(p, 'test');

    const target = join(workDir, 'restored.bin');
    const r = await q.restore(entry.id, target);
    expect(r.path).toBe(target);
    expect(createHash('sha256').update(readFileSync(target)).digest('hex')).toBe(sha);
    expect(q.list()).toHaveLength(0); // removed from quarantine after restore
    rmSync(target);
  });

  it('refuses to overwrite an existing file on restore', async () => {
    const p = makeFile('a.txt', 'hello');
    const entry = await q.quarantine(p, 'test');
    makeFile('a.txt', 'something else'); // recreate at original path
    await expect(q.restore(entry.id)).rejects.toMatchObject({ code: 'restore_target_exists' });
  });

  it('permanently deletes on remove', async () => {
    const p = makeFile('b.txt', 'data');
    const entry = await q.quarantine(p, 'test');
    const qdir = join(dataDir, 'quarantine');
    expect(readdirSync(qdir).some((f) => f.endsWith('.blazmaq'))).toBe(true);
    await q.remove(entry.id);
    expect(readdirSync(qdir).some((f) => f.endsWith('.blazmaq'))).toBe(false);
    expect(q.list()).toHaveLength(0);
  });

  it('decodes to a temp file for rescan then cleans up', async () => {
    const content = Buffer.from('the original content 123');
    const p = makeFile('c.txt', content);
    const entry = await q.quarantine(p, 'test');
    let seen = '';
    let tempPath = '';
    await q.withDecoded(entry.id, async (tmp) => {
      tempPath = tmp;
      seen = readFileSync(tmp, 'utf8');
    });
    expect(seen).toBe('the original content 123');
    expect(existsSync(tempPath)).toBe(false); // temp cleaned up
  });

  it('validates input and missing items', async () => {
    await expect(q.quarantine('relative/path', 'x')).rejects.toMatchObject({ code: 'path_not_absolute' });
    await expect(q.quarantine(join(workDir, 'nope'), 'x')).rejects.toMatchObject({ code: 'file_not_found' });
    await expect(q.restore('bad id!')).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(q.restore('q-missing-0000000000')).rejects.toMatchObject({ code: 'quarantine_not_found' });
    await expect(q.remove('q-missing-0000000000')).rejects.toMatchObject({ code: 'quarantine_not_found' });
  });
});
