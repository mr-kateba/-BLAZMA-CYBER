// Known-device tracking (pure): remembers the devices seen on the user's own network (by MAC
// address) so a device that was never seen before can be flagged. This is a memory aid, not a
// verdict — a new device is often just a guest's phone; the UI says so. Nothing here reaches the
// network: it only compares a freshly discovered list with what was saved earlier.

import { normalizeMac } from './oui';

/** One device the user has seen before, keyed by its (normalized) MAC address. */
export interface KnownDevice {
  mac: string;
  /** A name the user gave it, or null. */
  name: string | null;
  /** ISO timestamp it was first seen. */
  firstSeen: string;
  /** ISO timestamp it was last seen. */
  lastSeen: string;
  /** The user marked it as expected/theirs. */
  trusted: boolean;
}

export interface SeenDevice {
  address: string;
  mac: string | null;
}

export type DeviceStatus = 'new' | 'known' | 'trusted';

export interface WatchedDevice extends SeenDevice {
  status: DeviceStatus;
  name: string | null;
  firstSeen: string | null;
}

export interface DeviceWatchResult {
  devices: WatchedDevice[];
  /** MACs that are new this scan (never saved before). */
  newCount: number;
  /** Saved devices that did not answer this scan (may just be switched off). */
  offline: KnownDevice[];
}

/** Classifies a freshly discovered list against the saved known devices (does not mutate `known`). */
export function classifyDevices(seen: SeenDevice[], known: Record<string, KnownDevice>): DeviceWatchResult {
  const devices: WatchedDevice[] = [];
  const seenMacs = new Set<string>();
  for (const d of seen) {
    const mac = d.mac ? normalizeMac(d.mac) : null;
    const k = mac ? known[mac] : undefined;
    if (mac) seenMacs.add(mac);
    // Without a MAC (some hosts never answer ARP) we cannot track it, so it is neither new nor known.
    const status: DeviceStatus = !mac ? 'known' : k ? (k.trusted ? 'trusted' : 'known') : 'new';
    devices.push({ address: d.address, mac, status, name: k?.name ?? null, firstSeen: k?.firstSeen ?? null });
  }
  const order: Record<DeviceStatus, number> = { new: 0, known: 1, trusted: 2 };
  devices.sort((a, b) => order[a.status] - order[b.status] || ipKey(a.address) - ipKey(b.address));
  return {
    devices,
    newCount: devices.filter((d) => d.status === 'new').length,
    offline: Object.values(known).filter((k) => !seenMacs.has(k.mac)),
  };
}

/** Records the freshly seen devices into the saved map (new ones added, existing ones touched). */
export function rememberDevices(seen: SeenDevice[], known: Record<string, KnownDevice>, now: string, trust = false): Record<string, KnownDevice> {
  const next = { ...known };
  for (const d of seen) {
    const mac = normalizeMac(d.mac);
    if (!mac) continue;
    const existing = next[mac];
    next[mac] = existing
      ? { ...existing, lastSeen: now, trusted: existing.trusted || trust }
      : { mac, name: null, firstSeen: now, lastSeen: now, trusted: trust };
  }
  return next;
}

function ipKey(ip: string): number {
  const p = ip.split('.');
  return p.length === 4 ? p.reduce((n, o) => n * 256 + (Number(o) || 0), 0) : Number.MAX_SAFE_INTEGER;
}
