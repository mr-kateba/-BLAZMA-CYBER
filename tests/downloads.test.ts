import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isFinishedDownloadName, type DownloadsWatchState } from '../src/core/downloads';
import { DownloadsWatcher } from '../src/main/services/downloads-watch';
import { sanitizeSettings } from '../src/main/services/settings';
import { DEFAULT_SETTINGS, type FileAnalysis } from '../src/shared/api';

const until = async (cond: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timeout');
    await new Promise((r) => setTimeout(r, 25));
  }
};

describe('Downloads watcher', () => {
  const dirs: string[] = [];
  const watchers: DownloadsWatcher[] = [];
  afterEach(() => {
    watchers.forEach((w) => w.stop());
    dirs.forEach((d) => rmSync(d, { recursive: true, force: true }));
  });

  it('recognises finished downloads', () => {
    for (const ok of ['setup.exe', 'invoice.pdf', 'صورة.jpg', 'archive.tar.gz']) expect(isFinishedDownloadName(ok), ok).toBe(true);
    for (const no of ['setup.exe.crdownload', 'a.part', 'b.download', 'c.tmp', 'desktop.ini', '~$doc.docx', '.hidden', 'x.exe:Zone.Identifier', '']) expect(isFinishedDownloadName(no), no).toBe(false);
  });

  it('is opt-in (off by default) and validated', () => {
    expect(DEFAULT_SETTINGS.watchDownloads).toBe(false);
    expect(sanitizeSettings({ watchDownloads: 'yes' }, DEFAULT_SETTINGS).watchDownloads).toBe(false);
    expect(sanitizeSettings({ watchDownloads: true }, DEFAULT_SETTINGS).watchDownloads).toBe(true);
  });

  it('analyzes a download once it is complete (after the browser renames it) and flags suspicious ones', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'blazma-dl-'));
    dirs.push(dir);
    const analyze = vi.fn(async (p: string) => ({ assessment: { verdict: p.endsWith('.exe') ? 'suspicious' : 'no_detections', reasons: [{ key: 'x' }] } }) as unknown as FileAnalysis);
    const flagged = vi.fn();
    let state: DownloadsWatchState | null = null;
    const w = new DownloadsWatcher({ folder: () => dir, analyze, onChange: (s) => (state = s), onFlagged: flagged, settleMs: 60 });
    watchers.push(w);
    expect(w.setEnabled(true)).toMatchObject({ enabled: true, watching: true, folder: dir, error: null });

    writeFileSync(join(dir, 'setup.exe.crdownload'), 'MZ partial');
    await new Promise((r) => setTimeout(r, 200));
    expect(analyze).not.toHaveBeenCalled();
    renameSync(join(dir, 'setup.exe.crdownload'), join(dir, 'setup.exe'));
    writeFileSync(join(dir, 'notes.txt'), 'hello');
    await until(() => analyze.mock.calls.length === 2 && state!.recent.every((e) => e.status === 'done'));
    expect(analyze.mock.calls.map((c) => c[0]).sort()).toEqual([join(dir, 'notes.txt'), join(dir, 'setup.exe')]);
    expect(flagged).toHaveBeenCalledTimes(1);
    expect(flagged.mock.calls[0]![0]).toMatchObject({ name: 'setup.exe', verdict: 'suspicious', reasons: 1 });

    // The same file is not analyzed twice; turning it off stops watching.
    await new Promise((r) => setTimeout(r, 200));
    expect(analyze).toHaveBeenCalledTimes(2);
    expect(w.setEnabled(false)).toMatchObject({ enabled: false, watching: false });
    writeFileSync(join(dir, 'later.exe'), 'MZ');
    await new Promise((r) => setTimeout(r, 300));
    expect(analyze).toHaveBeenCalledTimes(2);
  });

  it('a missing folder is reported, never faked', () => {
    const w = new DownloadsWatcher({ folder: () => join(tmpdir(), 'blazma-no-such-dir-xyz'), analyze: vi.fn(), onChange: () => {}, onFlagged: () => {} });
    watchers.push(w);
    expect(w.setEnabled(true)).toMatchObject({ enabled: true, watching: false, error: 'file_not_found' });
  });
});
