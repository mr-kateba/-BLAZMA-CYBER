import { describe, expect, it } from 'vitest';
import { classifyDevices, rememberDevices, type KnownDevice } from '../src/core/known-devices';

const dev = (mac: string, o: Partial<KnownDevice> = {}): KnownDevice => ({ mac, name: null, firstSeen: '2026-01-01T00:00:00.000Z', lastSeen: '2026-01-01T00:00:00.000Z', trusted: false, ...o });
const known: Record<string, KnownDevice> = {
  'AA:BB:CC:00:00:01': dev('AA:BB:CC:00:00:01', { name: 'Router', trusted: true }),
  'AA:BB:CC:00:00:02': dev('AA:BB:CC:00:00:02'),
};

describe('known-device tracking', () => {
  it('flags never-seen MACs as new, keeps trusted/known apart, ignores case and separators', () => {
    const r = classifyDevices([
      { address: '192.168.1.1', mac: 'aa-bb-cc-00-00-01' }, // trusted (different spelling)
      { address: '192.168.1.9', mac: 'DE:AD:00:00:00:09' }, // never seen → new
      { address: '192.168.1.20', mac: null },               // no MAC → cannot track
    ], known);
    expect(r.devices.map((d) => `${d.address}:${d.status}`)).toEqual([
      '192.168.1.9:new', '192.168.1.20:known', '192.168.1.1:trusted',
    ]);
    expect(r.devices[2]).toMatchObject({ name: 'Router', firstSeen: '2026-01-01T00:00:00.000Z' });
    expect(r.newCount).toBe(1);
    // Device ...02 was saved but did not answer this scan → offline.
    expect(r.offline.map((k) => k.mac)).toEqual(['AA:BB:CC:00:00:02']);
  });

  it('remembers new devices and can trust them, without losing earlier state', () => {
    const now = '2026-02-02T00:00:00.000Z';
    const next = rememberDevices([{ address: '192.168.1.9', mac: 'de:ad:00:00:00:09' }, { address: '1.2.3.4', mac: null }], known, now);
    expect(Object.keys(next).sort()).toEqual(['AA:BB:CC:00:00:01', 'AA:BB:CC:00:00:02', 'DE:AD:00:00:00:09']);
    expect(next['DE:AD:00:00:00:09']).toMatchObject({ firstSeen: now, lastSeen: now, trusted: false });
    // A second pass with trust=true keeps the router's original firstSeen and its trust.
    const trusted = rememberDevices([{ address: '192.168.1.1', mac: 'AA:BB:CC:00:00:01' }, { address: '192.168.1.9', mac: 'DE:AD:00:00:00:09' }], next, now, true);
    expect(trusted['AA:BB:CC:00:00:01']).toMatchObject({ firstSeen: '2026-01-01T00:00:00.000Z', trusted: true, lastSeen: now });
    expect(trusted['DE:AD:00:00:00:09']!.trusted).toBe(true);
    // rememberDevices does not mutate its input.
    expect(known['DE:AD:00:00:00:09']).toBeUndefined();
  });
});
