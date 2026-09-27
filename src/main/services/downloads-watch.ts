// Downloads watcher (opt-in): while Blazma is open, every finished download in the user's Downloads
// folder is analyzed statically — exactly like File Analyzer (the file is only read, never opened
// or executed). Results appear on the dashboard; a notification is shown only for suspicious or
// malicious verdicts. One file at a time, a bounded queue, nothing is moved or deleted.

import { watch, type FSWatcher } from 'node:fs';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { FileAnalysis } from '../../shared/api';
import { isFinishedDownloadName, type DownloadEvent, type DownloadsWatchState } from '../../core/downloads';

export interface WatcherDeps {
  folder: () => string;
  analyze: (path: string, signal: AbortSignal) => Promise<FileAnalysis>;
  onChange: (state: DownloadsWatchState) => void;
  onFlagged: (ev: DownloadEvent) => void;
  /** How long a file's size must stay unchanged before it is considered complete. */
  settleMs?: number;
}

const MAX_RECENT = 25;
const MAX_QUEUE = 20;

export class DownloadsWatcher {
  private fsw: FSWatcher | null = null;
  private enabled = false;
  private error: string | null = null;
  private recent: DownloadEvent[] = [];
  private queue: DownloadEvent[] = [];
  private busy = false;
  private pending = new Map<string, NodeJS.Timeout>();
  private seen = new Set<string>();
  private ctrl: AbortController | null = null;

  constructor(private readonly deps: WatcherDeps) {}

  state(): DownloadsWatchState {
    return { enabled: this.enabled, watching: !!this.fsw, folder: this.enabled ? this.deps.folder() : null, error: this.error, recent: [...this.recent] };
  }

  setEnabled(on: boolean): DownloadsWatchState {
    if (on && !this.enabled) this.start();
    else if (!on && this.enabled) this.stop();
    return this.state();
  }

  private start() {
    this.enabled = true;
    this.error = null;
    try {
      this.fsw = watch(this.deps.folder(), { persistent: false }, (_ev, name) => {
        if (typeof name === 'string' && name && !name.includes('/') && !name.includes('\\')) this.schedule(name);
      });
      this.fsw.on('error', () => {
        this.error = 'watch_failed';
        this.fsw?.close();
        this.fsw = null;
        this.changed();
      });
    } catch (e) {
      this.error = (e as NodeJS.ErrnoException).code === 'ENOENT' ? 'file_not_found' : 'watch_failed';
      this.fsw = null;
    }
    this.changed();
  }

  stop() {
    this.enabled = false;
    this.fsw?.close();
    this.fsw = null;
    for (const t of this.pending.values()) clearTimeout(t);
    this.pending.clear();
    this.ctrl?.abort();
    for (const q of this.queue) Object.assign(q, { status: 'failed', error: 'cancelled' });
    this.queue = [];
    this.changed();
  }

  private schedule(name: string) {
    if (!isFinishedDownloadName(name)) return;
    clearTimeout(this.pending.get(name));
    this.pending.set(name, setTimeout(() => void this.check(name), this.deps.settleMs ?? 2000));
  }

  /** Waits until the size is stable, then queues the file once per (size, mtime). */
  private async check(name: string, lastSize = -1): Promise<void> {
    this.pending.delete(name);
    if (!this.enabled) return;
    const path = join(this.deps.folder(), name);
    const st = await stat(path).catch(() => null);
    if (!st || !st.isFile() || st.size === 0) return;
    if (st.size !== lastSize) {
      this.pending.set(name, setTimeout(() => void this.check(name, st.size), this.deps.settleMs ?? 2000));
      return;
    }
    const key = `${path}|${st.size}|${st.mtimeMs}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    if (this.seen.size > 500) this.seen.delete(this.seen.values().next().value!);
    if (this.queue.length >= MAX_QUEUE) return;
    const ev: DownloadEvent = { id: randomUUID(), path, name, at: new Date().toISOString(), status: 'queued' };
    this.recent = [ev, ...this.recent].slice(0, MAX_RECENT);
    this.queue.push(ev);
    this.changed();
    void this.drain();
  }

  private async drain() {
    if (this.busy) return;
    this.busy = true;
    try {
      while (this.enabled && this.queue.length) {
        const ev = this.queue.shift()!;
        ev.status = 'analyzing';
        this.changed();
        this.ctrl = new AbortController();
        try {
          const r = await this.deps.analyze(ev.path, this.ctrl.signal);
          Object.assign(ev, { status: 'done', verdict: r.assessment.verdict, reasons: r.assessment.reasons.length });
          if (ev.verdict === 'suspicious' || ev.verdict === 'malicious') this.deps.onFlagged({ ...ev });
        } catch (e) {
          Object.assign(ev, { status: 'failed', error: (e as { code?: string }).code ?? 'internal_error' });
        }
        this.changed();
      }
    } finally {
      this.busy = false;
      this.ctrl = null;
    }
  }

  private changed() {
    this.deps.onChange(this.state());
  }
}
