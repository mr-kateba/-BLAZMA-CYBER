import { describe, expect, it } from 'vitest';
import { buildCheckupHtmlReport, sanitizeCheckupReport } from '../src/core/checkup-report';
import { createTranslator, type Dict } from '../src/core/i18n';
import en from '../locales/en.json';
import ar from '../locales/ar.json';

const tEn = createTranslator(en as Dict, en as Dict);
const tAr = createTranslator(ar as Dict, en as Dict);
const NOW = '2026-09-28T12:00:00.000Z';

describe('full-checkup report', () => {
  const input = sanitizeCheckupReport({ areas: [
    { area: 'ports', state: 'attention', count: 2, vars: { network: 5 } },
    { area: 'device', state: 'problem', count: 3, vars: { score: 58 } },
    { area: 'wifi', state: 'unavailable', count: 0, reason: 'no_wifi_adapter' },
  ] })!;

  it('validates the renderer input and keeps the checkup order', () => {
    expect(input.areas.map((a) => a.area)).toEqual(['device', 'wifi', 'ports']);
    for (const bad of [
      null, { areas: [] }, { areas: 'x' },
      { areas: [{ area: 'evil', state: 'ok', count: 0 }] },
      { areas: [{ area: 'wifi', state: 'ok', count: -1 }] },
      { areas: [{ area: 'wifi', state: 'unavailable', count: 0, reason: '<script>' }] },
      { areas: [{ area: 'device', state: 'ok', count: 0, vars: { score: '<b>' } }] },
      { areas: [{ area: 'device', state: 'ok', count: 0, vars: { path: 1 } }] },
      { areas: [{ area: 'wifi', state: 'ok', count: 0 }, { area: 'wifi', state: 'ok', count: 0 }] },
    ]) expect(sanitizeCheckupReport(bad)).toBeNull();
  });

  it('builds a script-free report with a strict CSP and the worst verdict', () => {
    const html = buildCheckupHtmlReport(input, tEn, 'en', NOW, '1.1.2');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain(tEn('checkup.verdict.problem'));
    expect(html).toContain('Score 58/100');
    expect(html).toContain(tEn('errors.no_wifi_adapter'));
    expect(html).toContain('dir="ltr"');
  });

  it('is right-to-left in Arabic', () => {
    const html = buildCheckupHtmlReport(input, tAr, 'ar', NOW, '1.1.2');
    expect(html).toContain('dir="rtl"');
    expect(html).toContain(tAr('checkup.reportTitle'));
  });
});
