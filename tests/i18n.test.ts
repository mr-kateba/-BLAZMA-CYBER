import { describe, expect, it } from 'vitest';
import en from '../locales/en.json';
import ar from '../locales/ar.json';
import { createTranslator, directionOf, flattenKeys, interpolate, placeholders, type Dict } from '../src/core/i18n';

describe('localization', () => {
  it('Arabic and English have exactly the same keys', () => {
    const e = flattenKeys(en as Dict).sort();
    const a = flattenKeys(ar as Dict).sort();
    expect(a).toEqual(e);
  });
  it('placeholders match between languages', () => {
    const tEn = en as Dict;
    const tAr = ar as Dict;
    for (const key of flattenKeys(tEn)) {
      const get = (d: Dict) => key.split('.').reduce<any>((n, p) => n[p], d) as string;
      expect(placeholders(get(tAr)), key).toEqual(placeholders(get(tEn)));
    }
  });
  it('no Arabic string is left untranslated (identical to English) unless it is a technical term', () => {
    const allowed = /^(BLAZMA CYBER|العربية|YARA-X|RDAP|RDAP \/ WHOIS|Ping|DNS|ASN|CIDR|Tor|SPF|DMARC|DNSSEC|IPv\{\{v\}\}|MIME|Microsoft Defender|YARA|Electron|English|Left-to-right interface|VirusTotal|AbuseIPDB|Shodan|Censys|(MalwareBazaar|URLhaus|ThreatFox) \(abuse\.ch\)|abuse\.ch \(MalwareBazaar · URLhaus · ThreatFox\)|\{\{.*)$/;
    const get = (d: Dict, key: string) => key.split('.').reduce<any>((n, p) => n[p], d) as string;
    const same = flattenKeys(en as Dict).filter((k) => get(en as Dict, k) === get(ar as Dict, k) && !allowed.test(get(en as Dict, k)));
    expect(same).toEqual([]);
  });
  it('direction follows language', () => {
    expect(directionOf('ar')).toBe('rtl');
    expect(directionOf('en')).toBe('ltr');
  });
  it('translates with interpolation and falls back to English, then to the key', () => {
    const t = createTranslator({ a: { b: 'مرحبا {{name}}' } }, { a: { b: 'Hi {{name}}', c: 'Only EN' } });
    expect(t('a.b', { name: 'X' })).toBe('مرحبا X');
    expect(t('a.c')).toBe('Only EN');
    expect(t('missing.key')).toBe('missing.key');
    expect(interpolate('{{a}}-{{b}}', { a: 1 })).toBe('1-{{b}}');
  });
});
