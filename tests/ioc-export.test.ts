import { describe, expect, it } from 'vitest';
import { caseIocs, iocsToCsv, iocsToStix, stixPattern, stixString } from '../src/core/ioc-export';
import type { InvestigationCase } from '../src/shared/api';

const ev = (kind: InvestigationCase['evidence'][number]['kind'], value: string, extra: Partial<InvestigationCase['evidence'][number]> = {}) => ({
  id: `e-${kind}-${value.length}`, kind, value, label: null, source: 'manual', addedAt: '2026-09-27T10:00:00.000Z', details: null, ...extra,
});
const CASE: InvestigationCase = {
  id: 'CASE-2026-001', name: 'Phishing "invoice" wave', description: 'Reported by finance', status: 'open', tags: [], createdAt: '2026-09-27T09:00:00.000Z', updatedAt: '2026-09-27T10:00:00.000Z',
  notes: [], timeline: [],
  evidence: [
    ev('file', 'C:\\Users\\a\\Downloads\\invoice.pdf.exe', { label: 'attachment', details: { sha256: 'A'.repeat(64), md5: 'b'.repeat(32), verdict: 'malicious' } }),
    ev('hash', 'a'.repeat(64)), // same as the file's SHA-256 (different case) → one row
    ev('ip', '203.0.113.7'),
    ev('ip', '2001:db8::7'),
    ev('domain', 'PayPa1-Secure.example'),
    ev('url', "http://203.0.113.7/log'in?a=1"),
    ev('email', 'alerts@paypa1-secure.example'),
    ev('process', 'evil.exe'),
    ev('hash', 'not-a-hash'),
  ],
};

describe('IOC export', () => {
  const rows = caseIocs(CASE);

  it('collects exportable indicators only, normalized and de-duplicated', () => {
    expect(rows.map((r) => `${r.type}:${r.value}`)).toEqual([
      `sha256:${'a'.repeat(64)}`, `md5:${'b'.repeat(32)}`, 'file_name:invoice.pdf.exe', 'ipv4:203.0.113.7', 'ipv6:2001:db8::7',
      'domain:paypa1-secure.example', "url:http://203.0.113.7/log'in?a=1", 'email:alerts@paypa1-secure.example',
    ]);
    expect(rows[0]!.label).toBe('attachment');
  });

  it('CSV quotes properly and neutralizes spreadsheet formulas', () => {
    const csv = iocsToCsv([{ type: 'url', value: '=HYPERLINK("http://x")', label: 'a,b', source: '@evil', addedAt: '2026-01-01T00:00:00.000Z' }], 'CASE-1', 'n"ame');
    const [header, line] = csv.trimEnd().split('\r\n');
    expect(header).toBe('type,value,label,source,added_at,case_id,case_name');
    expect(line).toBe(`url,"'=HYPERLINK(""http://x"")","a,b",'@evil,2026-01-01T00:00:00.000Z,CASE-1,"n""ame"`);
    expect(iocsToCsv(rows, CASE.id, CASE.name).trimEnd().split('\r\n')).toHaveLength(rows.length + 1);
  });

  it('STIX patterns escape quotes and backslashes', () => {
    expect(stixString("a'b\\c")).toBe("'a\\'b\\\\c'");
    expect(stixPattern(rows[0]!)).toBe(`[file:hashes.'SHA-256' = '${'a'.repeat(64)}']`);
    expect(stixPattern(rows.find((r) => r.type === 'url')!)).toBe("[url:value = 'http://203.0.113.7/log\\'in?a=1']");
    expect(stixPattern(rows.find((r) => r.type === 'ipv6')!)).toBe("[ipv6-addr:value = '2001:db8::7']");
    expect(stixPattern(rows.find((r) => r.type === 'file_name')!)).toBe("[file:name = 'invoice.pdf.exe']");
  });

  it('STIX 2.1 bundle: identity, one indicator per IOC, a grouping for the case', () => {
    let n = 0;
    const uuid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
    const b = JSON.parse(iocsToStix(CASE, rows, '2026-09-27T12:00:00.000Z', uuid));
    expect(b.type).toBe('bundle');
    expect(b.id).toMatch(/^bundle--/);
    const types = b.objects.map((o: { type: string }) => o.type);
    expect(types[0]).toBe('identity');
    expect(types.filter((t: string) => t === 'indicator')).toHaveLength(rows.length);
    expect(types.at(-1)).toBe('grouping');
    const ids = b.objects.map((o: { id: string }) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const o of b.objects) expect(o.spec_version).toBe('2.1');
    const ind = b.objects.find((o: { type: string }) => o.type === 'indicator');
    expect(ind).toMatchObject({ pattern_type: 'stix', valid_from: '2026-09-27T10:00:00.000Z', created_by_ref: b.objects[0].id });
    const grp = b.objects.at(-1);
    expect(grp).toMatchObject({ name: CASE.name, context: 'suspicious-activity', description: 'Reported by finance' });
    expect(grp.object_refs).toEqual(b.objects.filter((o: { type: string }) => o.type === 'indicator').map((o: { id: string }) => o.id));
  });
});
