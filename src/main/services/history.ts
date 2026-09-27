import { join } from 'node:path';
import type { ActivityEntry } from '../../shared/api';
import type { NetworkActivityEntry } from '../../core/network-gate';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

/** Bounded, persisted, newest-first list. */
class BoundedLog<T> {
  private items: T[];
  constructor(private readonly file: string, private readonly cap: number) {
    const loaded = readJson<unknown>(file, []);
    this.items = Array.isArray(loaded) ? (loaded as T[]).slice(0, cap) : [];
  }
  add(item: T): void {
    this.items.unshift(item);
    if (this.items.length > this.cap) this.items.length = this.cap;
    writeJson(this.file, this.items);
  }
  list(limit = this.cap): T[] {
    return this.items.slice(0, limit);
  }
  clear(): void {
    this.items = [];
    writeJson(this.file, this.items);
  }
}

export class HistoryService {
  readonly activity = new BoundedLog<ActivityEntry>(join(subDir('state'), 'activity.json'), 200);
  /** The Network Activity log is always kept (it is a transparency feature), capped at 1000. */
  readonly network = new BoundedLog<NetworkActivityEntry>(join(subDir('state'), 'network-activity.json'), 1000);

  constructor(private readonly keepHistory: () => boolean) {}

  record(entry: Omit<ActivityEntry, 'id' | 'timestamp'>): void {
    if (!this.keepHistory()) return;
    this.activity.add({ ...entry, id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, timestamp: new Date().toISOString() });
  }
}
