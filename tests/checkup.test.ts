import { describe, expect, it } from 'vitest';
import { deviceArea, extensionsArea, foldersArea, overall, tamperArea, wifiArea } from '../src/core/checkup';
import type { DeviceSecurityReport } from '../src/core/device-security';
import type { TamperReport } from '../src/core/tamper';

const dev = (statuses: Array<'pass' | 'warn' | 'fail' | 'unknown'>, score: number | null = 80): DeviceSecurityReport => ({
  score, grade: null, elevated: false, collectedAt: '', unknown: statuses.filter((s) => s === 'unknown').length,
  evaluated: statuses.filter((s) => s !== 'unknown').length,
  checks: statuses.map((status, i) => ({ id: `c${i}`, status, weight: 1, detail: null, link: null })),
});
const tamper = (statuses: Array<'pass' | 'warn' | 'fail' | 'unknown'>): TamperReport => ({ collectedAt: '', findings: statuses.map((status, i) => ({ id: (['hosts', 'proxy', 'dns', 'root_certs'] as const)[i]!, status, detail: null, items: [] })) });
const diff = (changes: number, hidden: string[] = []) => ({ totalChanges: changes, diff: { changes: [], unchanged: 0, touched: 0, hiddenEdits: hidden } });

describe('full checkup', () => {
  it('device security: fails beat warnings; nothing evaluated is not "ok"', () => {
    expect(deviceArea({ data: dev(['pass', 'warn', 'fail', 'unknown'], 61) })).toMatchObject({ state: 'problem', count: 2, vars: { score: 61 } });
    expect(deviceArea({ data: dev(['pass', 'warn']) }).state).toBe('attention');
    expect(deviceArea({ data: dev(['pass', 'unknown']) })).toMatchObject({ state: 'ok', count: 0 });
    expect(deviceArea({ data: dev(['unknown'], null) })).toMatchObject({ state: 'unavailable', reason: 'unsupported_platform' });
    expect(deviceArea({ error: 'unsupported_platform' })).toMatchObject({ state: 'unavailable', reason: 'unsupported_platform' });
    expect(deviceArea(null).state).toBe('unavailable');
  });

  it('tampering, extensions and Wi-Fi', () => {
    expect(tamperArea({ data: tamper(['pass', 'warn', 'unknown', 'unknown']) })).toMatchObject({ state: 'attention', count: 1 });
    expect(tamperArea({ data: tamper(['fail', 'pass']) }).state).toBe('problem');
    expect(tamperArea({ data: tamper(['unknown', 'unknown']) }).state).toBe('unavailable');
    const ext = (risks: Array<'high' | 'medium' | 'low'>, browsers = 1) => ({ data: { collectedAt: '', browsers: Array.from({ length: browsers }, () => ({ browser: 'chrome' as const, profiles: 1 })), extensions: risks.map((risk) => ({ risk })) as never } });
    // Broad access alone ("medium") is not a finding; unusual installation ("high") is worth a look — never "problem".
    expect(extensionsArea(ext(['medium', 'low']))).toMatchObject({ state: 'ok', vars: { total: 2 } });
    expect(extensionsArea(ext(['high', 'medium']))).toMatchObject({ state: 'attention', count: 1 });
    expect(extensionsArea(ext([], 0))).toMatchObject({ state: 'unavailable', reason: 'no_browsers' });
    const wifi = (sev: Array<'high' | 'medium' | 'low' | 'info'>, available = true) => ({ data: { available, reason: available ? null : 'no_wifi_adapter', findings: sev.map((severity) => ({ id: 'x' as never, severity, vars: {} })) } });
    expect(wifiArea(wifi(['low', 'info'])).state).toBe('ok');
    expect(wifiArea(wifi(['medium'])).state).toBe('attention');
    expect(wifiArea(wifi(['high', 'medium']))).toMatchObject({ state: 'problem', count: 2 });
    expect(wifiArea(wifi([], false))).toMatchObject({ state: 'unavailable', reason: 'no_wifi_adapter' });
  });

  it('watched folders: hidden edits are a problem', () => {
    expect(foldersArea({ data: [] })).toMatchObject({ state: 'unavailable', reason: 'no_watches' });
    expect(foldersArea({ data: [diff(0), diff(0)] })).toMatchObject({ state: 'ok', vars: { folders: 2 } });
    expect(foldersArea({ data: [diff(3), diff(0)] })).toMatchObject({ state: 'attention', count: 3 });
    expect(foldersArea({ data: [diff(1, ['a.dll'])] }).state).toBe('problem');
  });

  it('overall = worst checked area; unavailable areas never hide a problem or fake an ok', () => {
    const u = deviceArea(null);
    expect(overall([u, u])).toBe('unavailable');
    expect(overall([u, foldersArea({ data: [diff(0)] })])).toBe('ok');
    expect(overall([foldersArea({ data: [diff(2)] }), tamperArea({ data: tamper(['fail']) }), u])).toBe('problem');
  });
});

describe('remembered checkup summary (from the untrusted renderer)', () => {
  it('keeps only valid areas, recomputes the verdict and uses its own time', async () => {
    const { sanitizeCheckupSummary } = await import('../src/core/checkup');
    const now = new Date('2026-09-28T00:00:00Z');
    const s = sanitizeCheckupSummary({ at: '1999-01-01', verdict: 'ok', areas: [{ area: 'tamper', state: 'problem', count: 1 }, { area: 'wifi', state: 'unavailable', count: 0 }] }, now);
    expect(s).toEqual({ at: now.toISOString(), verdict: 'problem', areas: [{ area: 'tamper', state: 'problem', count: 1 }, { area: 'wifi', state: 'unavailable', count: 0 }] });
    for (const bad of [null, 'x', { areas: 'x' }, { areas: [{ area: 'evil', state: 'ok', count: 0 }] }, { areas: [{ area: 'wifi', state: 'great', count: 0 }] }, { areas: [{ area: 'wifi', state: 'ok', count: -1 }] }, { areas: [{ area: 'wifi', state: 'ok', count: 0 }, { area: 'wifi', state: 'ok', count: 0 }] }]) {
      expect(sanitizeCheckupSummary(bad)).toBeNull();
    }
  });
});
