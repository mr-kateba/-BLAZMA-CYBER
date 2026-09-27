import { describe, expect, it } from 'vitest';
import { macInfo, normalizeMac, OUI_SOURCE } from '../src/core/oui';

describe('offline MAC manufacturer lookup', () => {
  it('normalizes any common MAC notation', () => {
    expect(normalizeMac('b8-27-eb-12-34-56')).toBe('B8:27:EB:12:34:56');
    expect(normalizeMac('b827.eb12.3456')).toBe('B8:27:EB:12:34:56');
    expect(normalizeMac('not a mac')).toBeNull();
    expect(normalizeMac(null)).toBeNull();
  });

  it('names registered manufacturers from the IEEE registry', () => {
    expect(macInfo('B8:27:EB:00:00:01')).toEqual({ mac: 'B8:27:EB:00:00:01', kind: 'vendor', vendor: 'Raspberry Pi Foundation' });
    expect(macInfo('00:15:5d:01:02:03')?.vendor).toBe('Microsoft');
    expect(macInfo('3c:5a:b4:00:00:00')?.vendor).toBe('Google');
    expect(OUI_SOURCE).toMatch(/IEEE/);
  });

  it('never guesses a maker for random, group or broadcast addresses', () => {
    // Second hex digit 2/6/A/E = locally administered (randomized Wi-Fi MAC).
    expect(macInfo('DA:A1:19:00:00:01')).toEqual({ mac: 'DA:A1:19:00:00:01', kind: 'random', vendor: null });
    expect(macInfo('01:00:5E:00:00:FB')?.kind).toBe('multicast');
    expect(macInfo('ff:ff:ff:ff:ff:ff')?.kind).toBe('broadcast');
    // A globally unique prefix that nobody registered.
    expect(macInfo('00:00:00:00:00:00')?.kind).toBe('vendor');
    expect(macInfo('FC:FF:FF:00:00:00')).toMatchObject({ vendor: null });
  });
});
