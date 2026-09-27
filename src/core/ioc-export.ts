// IOC export for a case (pure): CSV for spreadsheets / SIEM imports and a STIX 2.1 bundle for threat-
// intelligence platforms (MISP, OpenCTI…). Only indicators the case actually holds are exported.

import type { InvestigationCase } from '../shared/api';
import { isIPv4, isIPv6 } from './validation';

export type IocType = 'sha256' | 'sha1' | 'md5' | 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'file_name';

export interface IocRow {
  type: IocType;
  value: string;
  label: string | null;
  source: string;
  addedAt: string;
}

function hashType(v: string): IocType | null {
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  return null;
}

/** Every exportable indicator of a case, de-duplicated by (type, value). File evidence contributes its hashes. */
export function caseIocs(c: InvestigationCase): IocRow[] {
  const out = new Map<string, IocRow>();
  const put = (type: IocType, raw: string, e: InvestigationCase['evidence'][number]) => {
    const value = type === 'sha256' || type === 'sha1' || type === 'md5' || type === 'domain' || type === 'email' ? raw.trim().toLowerCase() : raw.trim();
    if (!value) return;
    const key = `${type}|${value}`;
    if (!out.has(key)) out.set(key, { type, value, label: e.label, source: e.source, addedAt: e.addedAt });
  };
  for (const e of c.evidence) {
    const v = e.value.trim();
    if (e.kind === 'hash') {
      const t = hashType(v);
      if (t) put(t, v, e);
    } else if (e.kind === 'ip') {
      if (isIPv4(v)) put('ipv4', v, e);
      else if (isIPv6(v)) put('ipv6', v, e);
    } else if (e.kind === 'domain') put('domain', v, e);
    else if (e.kind === 'url') put('url', v, e);
    else if (e.kind === 'email') put('email', v, e);
    else if (e.kind === 'file') {
      for (const k of ['sha256', 'sha1', 'md5'] as const) {
        const h = e.details?.[k];
        if (typeof h === 'string' && hashType(h) === k) put(k, h, e);
      }
      const name = v.split(/[\\/]/).pop();
      if (name) put('file_name', name, e);
    }
  }
  return [...out.values()];
}

/** RFC 4180 CSV. Cells that a spreadsheet would treat as a formula are prefixed with ' (CSV injection). */
export function iocsToCsv(rows: IocRow[], caseId: string, caseName: string): string {
  const cell = (v: string | null) => {
    let s = v ?? '';
    if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [['type', 'value', 'label', 'source', 'added_at', 'case_id', 'case_name'].join(',')];
  for (const r of rows) lines.push([r.type, r.value, r.label, r.source, r.addedAt, caseId, caseName].map(cell).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

const STIX_HASH: Partial<Record<IocType, string>> = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };

/** STIX patterning string literal: backslash and single quote are escaped. */
export function stixString(v: string): string {
  return `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

export function stixPattern(r: IocRow): string {
  const v = stixString(r.value);
  if (STIX_HASH[r.type]) return `[file:hashes.'${STIX_HASH[r.type]}' = ${v}]`;
  switch (r.type) {
    case 'ipv4': return `[ipv4-addr:value = ${v}]`;
    case 'ipv6': return `[ipv6-addr:value = ${v}]`;
    case 'domain': return `[domain-name:value = ${v}]`;
    case 'url': return `[url:value = ${v}]`;
    case 'email': return `[email-addr:value = ${v}]`;
    default: return `[file:name = ${v}]`;
  }
}

/** A STIX 2.1 bundle: the BLAZMA identity, one indicator per IOC and a grouping for the case. */
export function iocsToStix(c: InvestigationCase, rows: IocRow[], now: string, uuid: () => string): string {
  const ts = (s: string) => new Date(s).toISOString();
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${uuid()}`, created: now, modified: now, name: 'BLAZMA CYBER', identity_class: 'system' };
  const indicators = rows.map((r) => ({
    type: 'indicator',
    spec_version: '2.1',
    id: `indicator--${uuid()}`,
    created: now,
    modified: now,
    created_by_ref: identity.id,
    name: r.label ? `${r.label} (${r.type})` : `${r.type}: ${r.value}`.slice(0, 250),
    description: `Case ${c.id} — source: ${r.source}`,
    indicator_types: ['unknown'],
    pattern: stixPattern(r),
    pattern_type: 'stix',
    valid_from: ts(r.addedAt),
  }));
  const grouping = {
    type: 'grouping',
    spec_version: '2.1',
    id: `grouping--${uuid()}`,
    created: now,
    modified: now,
    created_by_ref: identity.id,
    name: c.name,
    ...(c.description ? { description: c.description } : {}),
    context: 'suspicious-activity',
    object_refs: indicators.length ? indicators.map((i) => i.id) : [identity.id],
  };
  return JSON.stringify({ type: 'bundle', id: `bundle--${uuid()}`, objects: [identity, ...indicators, grouping] }, null, 2);
}
