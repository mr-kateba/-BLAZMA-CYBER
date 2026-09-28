// Remembers the devices seen on the user's own networks so a never-before-seen device can be
// flagged. Read-only with respect to the network (it only stores MAC addresses the discovery
// already found) and stored locally like the rest of Blazma's state.

import { join } from 'node:path';
import { classifyDevices, rememberDevices, type DeviceWatchResult, type KnownDevice, type SeenDevice } from '../../core/known-devices';
import { normalizeMac } from '../../core/oui';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

export class DeviceWatchService {
  private readonly file = join(subDir('state'), 'known-devices.json');

  private load(): Record<string, KnownDevice> {
    const v = readJson<Record<string, KnownDevice>>(this.file, {});
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  }

  list(): KnownDevice[] {
    return Object.values(this.load()).sort((a, b) => a.firstSeen.localeCompare(b.firstSeen));
  }

  /** Compares the freshly discovered devices with what was saved (does not change anything). */
  classify(seen: SeenDevice[]): DeviceWatchResult {
    return classifyDevices(seen, this.load());
  }

  /** Records the freshly seen devices as the new baseline; `trust` marks them all as expected. */
  remember(seen: SeenDevice[], trust = false): void {
    writeJson(this.file, rememberDevices(seen, this.load(), new Date().toISOString(), trust));
  }

  setTrusted(rawMac: unknown, trusted: unknown): void {
    const mac = normalizeMac(typeof rawMac === 'string' ? rawMac : null);
    if (!mac) return;
    const known = this.load();
    if (known[mac]) {
      known[mac] = { ...known[mac]!, trusted: trusted === true };
      writeJson(this.file, known);
    }
  }

  rename(rawMac: unknown, rawName: unknown): void {
    const mac = normalizeMac(typeof rawMac === 'string' ? rawMac : null);
    if (!mac) return;
    const known = this.load();
    if (known[mac]) {
      const name = typeof rawName === 'string' && rawName.trim() ? rawName.trim().slice(0, 60) : null;
      known[mac] = { ...known[mac]!, name };
      writeJson(this.file, known);
    }
  }

  forget(rawMac: unknown): void {
    const mac = normalizeMac(typeof rawMac === 'string' ? rawMac : null);
    if (!mac) return;
    const known = this.load();
    if (known[mac]) {
      delete known[mac];
      writeJson(this.file, known);
    }
  }

  clear(): void {
    writeJson(this.file, {});
  }
}
