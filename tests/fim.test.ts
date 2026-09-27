import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { diffFingerprints, isExecutableLike, type FimEntry } from '../src/core/fim';

const data = mkdtempSync(join(tmpdir(), 'blz-fim-data-'));
process.env.BLAZMA_DATA_DIR = data;
vi.mock('electron', () => ({ app: { getPath: () => tmpdir() }, safeStorage: {} }));
const { FimService, fingerprint, FimError } = await import('../src/main/services/fim');

const e = (path: string, sha256: string, mtimeMs = 1000, size = 1): FimEntry => ({ path, sha256, mtimeMs, size });
const signal = () => new AbortController().signal;

describe('fingerprint comparison', () => {
  it('reports added, removed and modified files; timestamps alone are not changes', () => {
    const before = { files: [e('a.txt', '1'), e('b.exe', '2'), e('c.txt', '3'), e('d.txt', '4')] };
    const after = { files: [e('a.txt', '1', 5000), e('b.exe', '9'), e('d.txt', '8', 7000), e('new.ps1', '5')] };
    const d = diffFingerprints(before, after);
    expect(d.changes.map((c) => `${c.change}:${c.path}`)).toEqual(['modified:b.exe', 'modified:d.txt', 'added:new.ps1', 'removed:c.txt']);
    expect(d.unchanged).toBe(1);
    expect(d.touched).toBe(1);
    // b.exe changed content but kept its timestamp.
    expect(d.hiddenEdits).toEqual(['b.exe']);
    expect(d.changes[0]).toMatchObject({ before: { sha256: '2' }, after: { sha256: '9' } });
  });

  it('knows which files can run code', () => {
    for (const f of ['x.exe', 'A.DLL', 'run.ps1', 'go.bat', 'link.lnk', 'm.hta']) expect(isExecutableLike(f)).toBe(true);
    for (const f of ['notes.txt', 'photo.jpg', 'hosts', 'exe.txt']) expect(isExecutableLike(f)).toBe(false);
  });
});

describe('watching a real folder', () => {
  const root = mkdtempSync(join(tmpdir(), 'blz-fim-root-'));
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(data, { recursive: true, force: true });
  });
  mkdirSync(join(root, 'sub', 'deep'), { recursive: true });
  writeFileSync(join(root, 'keep.txt'), 'same');
  writeFileSync(join(root, 'edit.txt'), 'v1');
  writeFileSync(join(root, 'sneaky.dll'), 'original');
  writeFileSync(join(root, 'sub', 'gone.txt'), 'bye');
  writeFileSync(join(root, 'sub', 'deep', 'touch.txt'), 'content');
  const outside = mkdtempSync(join(tmpdir(), 'blz-fim-outside-'));
  writeFileSync(join(outside, 'secret.txt'), 'not in the watch');
  let linked = true;
  try {
    symlinkSync(outside, join(root, 'link'), 'junction');
  } catch {
    linked = false;
  }

  it('fingerprints every regular file without following links', async () => {
    const fp = await fingerprint(root, signal());
    expect(fp.files.map((f) => f.path)).toEqual(['edit.txt', 'keep.txt', 'sneaky.dll', 'sub/deep/touch.txt', 'sub/gone.txt']);
    expect(fp.files.find((f) => f.path === 'keep.txt')).toMatchObject({ size: 4, sha256: createHash('sha256').update('same').digest('hex') });
    expect(fp.truncated).toBe(false);
    if (linked) expect(JSON.stringify(fp)).not.toContain('secret.txt');
  });

  it('detects every kind of change, including an edit with a restored timestamp', async () => {
    const fim = new FimService();
    const w = await fim.create(root, 'Test folder', signal());
    expect(w).toMatchObject({ name: 'Test folder', files: 5, lastCheck: null });
    expect(fim.list().map((x) => x.id)).toContain(w.id);

    const clean = await fim.check(w.id, signal());
    expect(clean.totalChanges).toBe(0);
    expect(clean.watch.lastCheck).toMatchObject({ added: 0, removed: 0, modified: 0 });

    writeFileSync(join(root, 'edit.txt'), 'v2 longer');
    const st = statSync(join(root, 'sneaky.dll'));
    writeFileSync(join(root, 'sneaky.dll'), 'patched!');
    utimesSync(join(root, 'sneaky.dll'), st.atime, st.mtime); // attacker restores the timestamp
    unlinkSync(join(root, 'sub', 'gone.txt'));
    writeFileSync(join(root, 'sub', 'dropper.exe'), 'MZ');
    const later = new Date(Date.now() + 60_000);
    utimesSync(join(root, 'sub', 'deep', 'touch.txt'), later, later);

    const r = await fim.check(w.id, signal());
    expect(r.diff.changes.map((c) => `${c.change}:${c.path}`)).toEqual(['modified:edit.txt', 'modified:sneaky.dll', 'added:sub/dropper.exe', 'removed:sub/gone.txt']);
    expect(r.diff.hiddenEdits).toEqual(['sneaky.dll']);
    expect(r.diff.touched).toBe(1);
    expect(r.watch.lastCheck).toMatchObject({ added: 1, removed: 1, modified: 2 });

    expect(fim.resolve(w.id, 'sub/dropper.exe')).toBe(join(root, 'sub', 'dropper.exe'));
    expect(() => fim.resolve(w.id, '../outside')).toThrow(FimError);

    await fim.accept(w.id, signal());
    expect((await fim.check(w.id, signal())).totalChanges).toBe(0);
    fim.remove(w.id);
    expect(fim.list().find((x) => x.id === w.id)).toBeUndefined();
  });

  it('refuses bad input and honours cancel', async () => {
    const fim = new FimService();
    await expect(fim.create('relative/path', '', signal())).rejects.toMatchObject({ code: 'invalid_path' });
    await expect(fim.create(join(root, 'keep.txt'), '', signal())).rejects.toMatchObject({ code: 'fim_not_folder' });
    await expect(fim.check('../../etc', signal())).rejects.toMatchObject({ code: 'invalid_input' });
    const ac = new AbortController();
    ac.abort();
    await expect(fingerprint(root, ac.signal)).rejects.toMatchObject({ code: 'cancelled' });
  });
});
