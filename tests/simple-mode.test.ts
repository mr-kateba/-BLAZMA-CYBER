import { describe, expect, it } from 'vitest';
import { summarizeDomain } from '../src/core/link-summary';
import { visibleNav, labelKeyFor, NAV } from '../src/renderer/nav';
import { sanitizeSettings } from '../src/main/services/settings';
import { DEFAULT_SETTINGS, type DomainLookupResult } from '../src/shared/api';

const NOW = new Date('2026-09-27T00:00:00Z');
const base: DomainLookupResult = { input: 'example.com', domain: 'example.com', dns: null, rdap: null, tls: null, infrastructure: [], reputation: [], sources: [] };
const tls = (authorized: boolean, daysRemaining: number | null) => ({
  host: 'example.com', port: 443, protocol: 'TLSv1.3', authorized, authorizationError: null, subject: null, issuer: null,
  validFrom: null, validTo: null, daysRemaining, sans: [], fingerprint256: null, serialNumber: null,
});

describe('Simple mode', () => {
  it('keeps only the essentials, with friendlier labels', () => {
    const ids = visibleNav('simple').flatMap((s) => s.items.map((i) => i.id));
    expect(ids).toEqual(['dashboard', 'device-security', 'domain-intel', 'email-check', 'password-check', 'security-center', 'file-analyzer', 'browser-extensions', 'privacy', 'settings-appearance', 'settings-language']);
    expect(visibleNav('expert')).toBe(NAV);
    const fa = NAV.flatMap((s) => s.items).find((i) => i.id === 'file-analyzer')!;
    expect(labelKeyFor(fa, 'simple')).toBe('nav.simple.scanFile');
    expect(labelKeyFor(fa, 'expert')).toBe('nav.fileAnalyzer');
  });

  it('uiMode is validated and defaults to simple', () => {
    expect(DEFAULT_SETTINGS.uiMode).toBe('simple');
    expect(sanitizeSettings({ uiMode: 'expert' }, DEFAULT_SETTINGS).uiMode).toBe('expert');
    expect(sanitizeSettings({ uiMode: 'god-mode' }, DEFAULT_SETTINGS).uiMode).toBe('simple');
  });
});

describe('Link summary ("Is this site trustworthy?")', () => {
  it('nothing checked (e.g. Offline Mode) → unknown, no invented signals', () => {
    expect(summarizeDomain(base, NOW)).toEqual({ level: 'unknown', signals: [] });
  });

  it('a days-old domain is a warning sign even with a valid padlock', () => {
    const r = summarizeDomain({ ...base, rdap: { created: '2026-09-20T00:00:00Z' } as never, tls: tls(true, 80) }, NOW);
    expect(r.level).toBe('risky');
    expect(r.signals[0]).toEqual({ key: 'veryYoung', tone: 'red', vars: { days: 7 } });
    expect(r.signals.map((s) => s.key)).toContain('tlsOk');
  });

  it('vendor detections dominate; an established site with a valid cert has no red flags (not "safe")', () => {
    const vt = (malicious: number, suspicious = 0) => ({ service: 'virustotal' as const, found: true, malicious, suspicious });
    expect(summarizeDomain({ ...base, reputation: [vt(3)] }, NOW).level).toBe('risky');
    expect(summarizeDomain({ ...base, reputation: [vt(0, 2)] }, NOW).level).toBe('caution');
    const ok = summarizeDomain({ ...base, rdap: { created: '2010-01-01T00:00:00Z' } as never, tls: tls(true, 60), reputation: [vt(0)] }, NOW);
    expect(ok.level).toBe('no_red_flags');
    expect(ok.signals.map((s) => s.key).sort()).toEqual(['old', 'reputationClean', 'tlsOk']);
  });

  it('expired/untrusted certificates and dead names are cautions; not-found reputation is ignored', () => {
    expect(summarizeDomain({ ...base, tls: tls(true, -3) }, NOW).signals).toEqual([{ key: 'tlsExpired', tone: 'amber' }]);
    expect(summarizeDomain({ ...base, tls: tls(false, 10) }, NOW).level).toBe('caution');
    const dns = { a: [], aaaa: [], mx: [], txt: [], ns: [], cname: [], soa: null, caa: [], spf: null, dmarc: null };
    expect(summarizeDomain({ ...base, dns }, NOW).signals).toEqual([{ key: 'noAddress', tone: 'amber' }]);
    expect(summarizeDomain({ ...base, reputation: [{ service: 'virustotal', found: false }] }, NOW).level).toBe('unknown');
  });
});
