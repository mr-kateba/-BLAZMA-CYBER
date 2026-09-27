import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let dataDir: string;
vi.mock('electron', () => ({
  app: { getPath: () => dataDir, getVersion: () => '0.1.0' },
  safeStorage: {},
  shell: { openPath: async () => '', showItemInFolder: () => {} },
  BrowserWindow: class {},
}));

import en from '../locales/en.json';
import ar from '../locales/ar.json';
import { createTranslator, type Dict } from '../src/core/i18n';
import { buildHtmlReport, buildJsonReport, collectIndicators, escapeHtml } from '../src/core/report';
import { indicatorType, matches, persistenceFlags } from '../src/core/hunt';
import { CaseService } from '../src/main/services/cases';
import { ReportService } from '../src/main/services/reports';
import type { InvestigationCase, ReportOptions } from '../src/shared/api';

beforeAll(() => { dataDir = mkdtempSync(join(tmpdir(), 'blazma-inv-')); });
afterAll(() => rmSync(dataDir, { recursive: true, force: true }));

const opts = (o: Partial<ReportOptions> = {}): ReportOptions => ({ format: 'html', language: 'en', includeMachineInfo: false, includeNotes: true, includeTimeline: true, ...o });

describe('case store', () => {
  it('creates sequential CASE-YYYY-NNN ids and keeps evidence separate from notes', () => {
    const svc = new CaseService();
    const a = svc.create('Phishing wave', 'desc', ['phishing', 'phishing', ' email ']);
    const b = svc.create('Second', '', []);
    const y = new Date().getFullYear();
    expect(a.id).toBe(`CASE-${y}-001`);
    expect(b.id).toBe(`CASE-${y}-002`);
    expect(a.tags).toEqual(['phishing', 'email']);
    const withEv = svc.addEvidence(a.id, { kind: 'ip', value: '203.0.113.7', source: 'ipIntel', details: { asn: 64500, nested: { no: 1 } } });
    const withNote = svc.addNote(a.id, 'Analyst note: sender spoofed');
    expect(withEv.evidence).toHaveLength(1);
    expect(withEv.evidence[0]!.details).toEqual({ asn: 64500 }); // nested objects dropped
    expect(withNote.notes).toHaveLength(1);
    expect(withNote.evidence).toHaveLength(1);
    expect(withNote.timeline.map((t) => t.kind)).toEqual(['status', 'evidence', 'note']);
    expect(svc.list().map((c) => c.id)).toContain(a.id);
  });
  it('validates input and ids', () => {
    const svc = new CaseService();
    expect(() => svc.create('   ', '', [])).toThrow('invalid_input');
    expect(() => svc.get('../../etc/passwd')).toThrow('invalid_input');
    expect(() => svc.get('CASE-1999-999')).toThrow('case_not_found');
    const c = svc.create('X', '', []);
    expect(() => svc.addEvidence(c.id, { kind: 'bogus', value: 'x' })).toThrow('invalid_input');
  });
  it('status changes are recorded on the timeline', () => {
    const svc = new CaseService();
    const c = svc.create('Status', '', []);
    const closed = svc.update(c.id, { status: 'closed' });
    expect(closed.status).toBe('closed');
    expect(closed.timeline.at(-1)!.title).toBe('case.closed');
  });
});

const sampleCase = (): InvestigationCase => ({
  id: 'CASE-2026-042',
  name: 'Test <script>alert(1)</script>',
  description: 'desc & "quotes"',
  tags: ['t1'],
  status: 'open',
  createdAt: '2026-09-01T10:00:00.000Z',
  updatedAt: '2026-09-02T10:00:00.000Z',
  evidence: [
    { id: 'e1', kind: 'file', value: 'C:\\x\\<img src=x onerror=alert(1)>.exe', label: null, source: 'fileAnalyzer', addedAt: '2026-09-01T11:00:00.000Z', details: { verdict: 'suspicious', sha256: 'a'.repeat(64) } },
    { id: 'e2', kind: 'domain', value: 'evil.example', label: null, source: 'domainIntel', addedAt: '2026-09-01T12:00:00.000Z', details: null },
    { id: 'e3', kind: 'ip', value: '203.0.113.7', label: null, source: 'ipIntel', addedAt: '2026-09-01T13:00:00.000Z', details: null },
  ],
  notes: [{ id: 'n1', text: 'note <b>bold</b>', createdAt: '2026-09-01T14:00:00.000Z', updatedAt: '2026-09-01T14:00:00.000Z' }],
  timeline: [{ id: 't1', time: '2026-09-01T10:00:00.000Z', title: 'Created', detail: null, kind: 'status' }],
});

describe('reports', () => {
  const tEn = createTranslator(en as Dict);
  const tAr = createTranslator(ar as Dict, en as Dict);

  it('escapes every untrusted value (no HTML/script injection)', () => {
    expect(escapeHtml('<a href="x">\'&')).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;');
    const html = buildHtmlReport(sampleCase(), opts(), tEn, '2026-09-27T00:00:00.000Z', null);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<b>bold</b>');
    expect(html).toContain('&lt;script&gt;');
    // A strict CSP forbids scripts even if a viewer is permissive
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script/i);
  });
  it('Arabic reports are RTL with technical values kept LTR', () => {
    const html = buildHtmlReport(sampleCase(), opts({ language: 'ar' }), tAr, '2026-09-27T00:00:00.000Z', null);
    expect(html).toMatch(/<html lang="ar" dir="rtl">/);
    expect(html).toContain('<bdi dir="ltr" class="ltr">203.0.113.7</bdi>');
    expect(html).toContain(ar.report.title as string);
  });
  it('omits machine info unless explicitly requested', () => {
    const m = { os: 'Windows 11', arch: 'x64', hostname: 'ANALYST-PC', appVersion: '0.1.0' };
    expect(buildHtmlReport(sampleCase(), opts(), tEn, 'x', m)).not.toContain('ANALYST-PC');
    expect(buildHtmlReport(sampleCase(), opts({ includeMachineInfo: true }), tEn, 'x', m)).toContain('ANALYST-PC');
    expect(buildJsonReport(sampleCase(), opts(), 'x', m)).not.toContain('ANALYST-PC');
  });
  it('JSON export collects indicators (file SHA-256 included) and honors options', () => {
    const j = JSON.parse(buildJsonReport(sampleCase(), opts({ includeNotes: false }), 'now', null));
    expect(j.format).toBe('blazma-cyber-report');
    expect(j.indicators.domain).toEqual(['evil.example']);
    expect(j.indicators.hash).toEqual(['a'.repeat(64)]);
    expect(j.notes).toBeUndefined();
    expect(j.timeline).toHaveLength(1);
    expect(collectIndicators(sampleCase()).ip).toEqual(['203.0.113.7']);
  });
  it('generates, lists and deletes HTML/JSON report files', async () => {
    const svc = new ReportService();
    const cs = new CaseService();
    const c = cs.create('Report me', '', []);
    const r1 = await svc.generate(cs.get(c.id), { format: 'html', language: 'ar' });
    const r2 = await svc.generate(cs.get(c.id), { format: 'json', language: 'en' });
    expect(r1.path.endsWith('.html')).toBe(true);
    expect(r2.sizeBytes).toBeGreaterThan(10);
    expect(svc.list().map((r) => r.id)).toEqual([r2.id, r1.id].sort((a, b) => (svc.list().findIndex((x) => x.id === a) - svc.list().findIndex((x) => x.id === b))));
    await svc.remove(r1.id);
    expect(svc.list().some((r) => r.id === r1.id)).toBe(false);
  });
});

describe('threat hunting helpers', () => {
  it('types indicators', () => {
    expect(indicatorType('203.0.113.7')).toBe('ip');
    expect(indicatorType('a'.repeat(64))).toBe('hash');
    expect(indicatorType('Example.COM')).toBe('domain');
    expect(indicatorType('powershell')).toBe('text');
  });
  it('matches IPs and hashes as whole tokens only', () => {
    expect(matches('conn to 10.0.0.1:443', '10.0.0.1', 'ip')).toBe(true);
    expect(matches('conn to 10.0.0.12', '10.0.0.1', 'ip')).toBe(false);
    expect(matches('file=' + 'a'.repeat(64), 'a'.repeat(64), 'hash')).toBe(true);
    expect(matches('Updater.EXE', 'updater', 'text')).toBe(true);
    expect(matches(null, 'x', 'text')).toBe(false);
  });
  it('flags autostart locations for review', () => {
    expect(persistenceFlags('C:\\Users\\bob\\AppData\\Roaming\\x\\run.exe')).toEqual(['hunt.flag.userFolder', 'hunt.flag.outsideSystem']);
    expect(persistenceFlags('"C:\\Program Files\\Vendor\\app.exe" --tray')).toEqual([]);
    expect(persistenceFlags('D:\\tools\\agent.exe')).toEqual(['hunt.flag.outsideSystem']);
  });
});
