// Report generation (pure): builds a self-contained, print-friendly HTML report and a JSON export
// from a case. Bilingual: Arabic reports are RTL, English LTR; technical values stay LTR.
//
// SECURITY: evidence values come from untrusted sources (file names, domains, strings extracted from
// malware). Every dynamic value is HTML-escaped, the document has no scripts, and a strict CSP meta
// tag forbids any script or remote resource even if a viewer is permissive.

import type { InvestigationCase, ReportOptions } from '../shared/api';
import { directionOf, type Lang, type Vars } from './i18n';

type T = (key: string, vars?: Vars) => string;

export interface MachineInfo {
  os: string;
  arch: string;
  hostname: string;
  appVersion: string;
}

export function escapeHtml(v: unknown): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const ltr = (v: unknown) => `<bdi dir="ltr" class="ltr">${escapeHtml(v)}</bdi>`;

export function fmt(lang: Lang, iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return new Intl.DateTimeFormat(lang === 'ar' ? 'ar-u-nu-latn' : 'en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(d);
}

/** Groups evidence values by kind for the "Indicators" section. */
export function collectIndicators(c: InvestigationCase): Record<string, string[]> {
  const out: Record<string, Set<string>> = {};
  for (const e of c.evidence) {
    const k = e.kind;
    if (!['hash', 'ip', 'domain', 'url', 'email'].includes(k)) continue;
    (out[k] ??= new Set()).add(e.value);
    // File evidence contributes its SHA-256 to the hash indicators.
  }
  for (const e of c.evidence) {
    if (e.kind === 'file' && e.details && typeof e.details.sha256 === 'string') (out.hash ??= new Set()).add(e.details.sha256);
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v].sort()]));
}

/** Modules that contributed evidence (for the "Modules used" section). */
export function modulesUsed(c: InvestigationCase): string[] {
  return [...new Set(c.evidence.map((e) => e.source))].sort();
}

export function buildJsonReport(c: InvestigationCase, opts: ReportOptions, generatedAt: string, machine: MachineInfo | null): string {
  const payload = {
    format: 'blazma-cyber-report',
    version: 1,
    generatedAt,
    language: opts.language,
    case: {
      id: c.id,
      name: c.name,
      description: c.description,
      status: c.status,
      tags: c.tags,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
    },
    modulesUsed: modulesUsed(c),
    indicators: collectIndicators(c),
    evidence: c.evidence,
    ...(opts.includeNotes ? { notes: c.notes } : {}),
    ...(opts.includeTimeline ? { timeline: [...c.timeline].sort((a, b) => a.time.localeCompare(b.time)) } : {}),
    ...(opts.includeMachineInfo && machine ? { machine } : {}),
  };
  return JSON.stringify(payload, null, 2);
}

/** Shared print-friendly stylesheet for every Blazma HTML report (no remote resources). */
export const REPORT_STYLE = `<style>
  :root { color-scheme: light; }
  body { font-family: 'Segoe UI', 'IBM Plex Sans Arabic', Tahoma, Arial, sans-serif; color: #0f172a; margin: 0; background: #fff; line-height: 1.55; }
  .page { max-width: 960px; margin: 0 auto; padding: 32px 28px 48px; }
  header { border-bottom: 3px solid #1d4ed8; padding-bottom: 14px; margin-bottom: 18px; }
  .brand { font-weight: 800; letter-spacing: .06em; color: #1d4ed8; direction: ltr; unicode-bidi: isolate; }
  h1 { margin: 6px 0 2px; font-size: 24px; }
  h2 { font-size: 17px; margin: 26px 0 10px; color: #1e3a8a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 14px 0 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.kv th { width: 30%; text-align: start; color: #475569; font-weight: 600; padding: 5px 8px; vertical-align: top; }
  table.kv td { padding: 5px 8px; }
  table.grid th { text-align: start; background: #f1f5f9; padding: 7px 8px; font-size: 12px; color: #334155; }
  table.grid td { padding: 7px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  .ltr { direction: ltr; unicode-bidi: isolate; }
  .mono, .mono .ltr { font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12px; word-break: break-all; }
  .muted { color: #64748b; font-size: 12px; }
  .tag { display: inline-block; background: #e0e7ff; color: #3730a3; border-radius: 999px; padding: 1px 9px; font-size: 12px; }
  .desc { background: #f8fafc; border-inline-start: 3px solid #1d4ed8; padding: 10px 12px; }
  .note { border: 1px solid #e2e8f0; border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; white-space: pre-wrap; }
  .details { color: #475569; font-size: 11px; margin-top: 3px; }
  ul.mono { margin: 0; padding-inline-start: 20px; }
  ol.timeline { padding-inline-start: 20px; }
  ol.timeline li { margin-bottom: 6px; }
  footer { margin-top: 34px; color: #64748b; font-size: 11px; border-top: 1px solid #e2e8f0; padding-top: 10px; }
  @media print { .page { padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style>`;

export function buildHtmlReport(c: InvestigationCase, opts: ReportOptions, t: T, generatedAt: string, machine: MachineInfo | null): string {
  const lang = opts.language;
  const dir = directionOf(lang);
  const ind = collectIndicators(c);
  const findings = c.evidence.filter((e) => e.kind === 'file' || e.kind === 'finding');

  const row = (k: string, v: string) => `<tr><th>${escapeHtml(k)}</th><td>${v}</td></tr>`;
  const section = (title: string, body: string) => `<section><h2>${escapeHtml(title)}</h2>${body}</section>`;
  const empty = `<p class="muted">${escapeHtml(t('report.none'))}</p>`;

  const caseInfo = `<table class="kv">
    ${row(t('report.caseId'), ltr(c.id))}
    ${row(t('report.caseName'), escapeHtml(c.name))}
    ${row(t('report.status'), escapeHtml(t(`cases.status.${c.status}`)))}
    ${row(t('report.created'), escapeHtml(fmt(lang, c.createdAt)))}
    ${row(t('report.updated'), escapeHtml(fmt(lang, c.updatedAt)))}
    ${c.tags.length ? row(t('report.tags'), c.tags.map((x) => `<span class="tag">${escapeHtml(x)}</span>`).join(' ')) : ''}
  </table>
  ${c.description ? `<p class="desc">${escapeHtml(c.description)}</p>` : ''}`;

  const findingsHtml = findings.length
    ? `<table class="grid"><thead><tr><th>${escapeHtml(t('report.item'))}</th><th>${escapeHtml(t('report.verdict'))}</th><th>SHA-256</th><th>${escapeHtml(t('report.source'))}</th></tr></thead><tbody>
      ${findings
        .map((e) => {
          const verdict = e.details && typeof e.details.verdict === 'string' ? t(`verdict.${e.details.verdict}`) : '—';
          const sha = e.details && typeof e.details.sha256 === 'string' ? ltr(e.details.sha256) : '—';
          return `<tr><td>${e.label ? escapeHtml(e.label) : ltr(e.value)}</td><td>${escapeHtml(verdict)}</td><td class="mono">${sha}</td><td>${escapeHtml(t(`report.module.${e.source}`))}</td></tr>`;
        })
        .join('')}
      </tbody></table>`
    : empty;

  const indHtml = Object.keys(ind).length
    ? Object.entries(ind)
        .map(([k, list]) => `<h3>${escapeHtml(t(`cases.kind.${k}`))} (${list.length})</h3><ul class="mono">${list.map((v) => `<li>${ltr(v)}</li>`).join('')}</ul>`)
        .join('')
    : empty;

  const evidenceHtml = c.evidence.length
    ? `<table class="grid"><thead><tr><th>${escapeHtml(t('report.kind'))}</th><th>${escapeHtml(t('report.value'))}</th><th>${escapeHtml(t('report.source'))}</th><th>${escapeHtml(t('report.added'))}</th></tr></thead><tbody>
      ${c.evidence
        .map((e) => `<tr><td>${escapeHtml(t(`cases.kind.${e.kind}`))}</td><td class="mono">${ltr(e.value)}${e.label ? `<div class="muted">${escapeHtml(e.label)}</div>` : ''}${e.details ? `<div class="details">${Object.entries(e.details).filter(([, v]) => v !== null && v !== '').map(([k, v]) => `<span>${escapeHtml(k)}: ${ltr(v)}</span>`).join(' · ')}</div>` : ''}</td><td>${escapeHtml(t(`report.module.${e.source}`))}</td><td>${escapeHtml(fmt(lang, e.addedAt))}</td></tr>`)
        .join('')}
      </tbody></table>`
    : empty;

  const notesHtml = c.notes.length ? c.notes.map((n) => `<div class="note"><div class="muted">${escapeHtml(fmt(lang, n.createdAt))}</div><p>${escapeHtml(n.text)}</p></div>`).join('') : empty;

  const timeline = [...c.timeline].sort((a, b) => a.time.localeCompare(b.time));
  const timelineHtml = timeline.length
    ? `<ol class="timeline">${timeline.map((ev) => `<li><span class="muted">${escapeHtml(fmt(lang, ev.time))}</span> — <strong>${escapeHtml(ev.title)}</strong>${ev.detail ? `<div>${ltr(ev.detail)}</div>` : ''}</li>`).join('')}</ol>`
    : empty;

  const machineHtml = opts.includeMachineInfo && machine
    ? `<table class="kv">${row(t('report.os'), ltr(machine.os))}${row(t('report.arch'), ltr(machine.arch))}${row(t('report.hostname'), ltr(machine.hostname))}${row(t('report.appVersion'), ltr(machine.appVersion))}</table>`
    : '';

  return `<!doctype html>
<html lang="${lang}" dir="${dir}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(`${c.id} — ${c.name}`)}</title>
${REPORT_STYLE}
</head>
<body><div class="page">
<header>
  <div class="brand">Blazma Cyber</div>
  <h1>${escapeHtml(t('report.title'))}</h1>
  <div class="muted">${escapeHtml(t('report.generated', { time: fmt(lang, generatedAt) }))}</div>
</header>
${section(t('report.caseInfo'), caseInfo)}
${section(t('report.modules'), modulesUsed(c).length ? `<p>${modulesUsed(c).map((m) => `<span class="tag">${escapeHtml(t(`report.module.${m}`))}</span>`).join(' ')}</p>` : empty)}
${section(t('report.findings'), findingsHtml)}
${section(t('report.indicators'), indHtml)}
${section(t('report.evidence'), evidenceHtml)}
${opts.includeNotes ? section(t('report.notes'), notesHtml) : ''}
${opts.includeTimeline ? section(t('report.timeline'), timelineHtml) : ''}
${machineHtml ? section(t('report.machine'), machineHtml) : ''}
<footer>${escapeHtml(t('report.footer'))}</footer>
</div></body></html>`;
}
