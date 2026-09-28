// Full-checkup report (pure): turns the checkup's per-area results into a self-contained, printable
// HTML page (saved as HTML or PDF by the main process). Same rules as case reports: every dynamic
// value is escaped, no scripts, a strict CSP, and only states/counts/reason codes are included — no
// evidence (file paths, addresses) ever leaves the checkup page through this report.

import { overall, type AreaState, type CheckupArea } from './checkup';
import { directionOf, type Lang, type Vars } from './i18n';
import { escapeHtml, fmt, REPORT_STYLE } from './report';

type T = (key: string, vars?: Vars) => string;

export interface CheckupReportArea {
  area: CheckupArea;
  state: AreaState;
  count: number;
  /** i18n error code (only for unavailable areas). */
  reason?: string;
  /** Numbers shown in the summary line (score, totals). */
  vars?: Record<string, number | string>;
}

export interface CheckupReportInput {
  areas: CheckupReportArea[];
}

const AREAS: CheckupArea[] = ['device', 'tamper', 'startup', 'extensions', 'wifi', 'ports', 'folders'];
const STATES: AreaState[] = ['ok', 'attention', 'problem', 'unavailable'];
const REASON_RE = /^[a-z][a-z0-9_]{0,47}$/;
const VAR_KEYS = new Set(['score', 'total', 'network', 'folders']);

/** Validates the (untrusted) renderer input; returns null when anything is malformed. */
export function sanitizeCheckupReport(x: unknown): CheckupReportInput | null {
  if (!x || typeof x !== 'object') return null;
  const raw = (x as Record<string, unknown>).areas;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > AREAS.length) return null;
  const areas: CheckupReportArea[] = [];
  for (const item of raw) {
    const r = (item ?? {}) as Record<string, unknown>;
    if (!AREAS.includes(r.area as CheckupArea) || !STATES.includes(r.state as AreaState)) return null;
    if (areas.some((a) => a.area === r.area)) return null;
    if (typeof r.count !== 'number' || !Number.isInteger(r.count) || r.count < 0 || r.count > 1_000_000) return null;
    const out: CheckupReportArea = { area: r.area as CheckupArea, state: r.state as AreaState, count: r.count };
    if (r.reason !== undefined) {
      if (typeof r.reason !== 'string' || !REASON_RE.test(r.reason)) return null;
      out.reason = r.reason;
    }
    if (r.vars !== undefined) {
      if (!r.vars || typeof r.vars !== 'object') return null;
      const vars: Record<string, number | string> = {};
      for (const [k, v] of Object.entries(r.vars as Record<string, unknown>)) {
        if (!VAR_KEYS.has(k)) return null;
        if (typeof v === 'number' && Number.isFinite(v) && Math.abs(v) <= 1_000_000) vars[k] = v;
        else if (v === '—') vars[k] = v;
        else return null;
      }
      out.vars = vars;
    }
    areas.push(out);
  }
  // Report the areas in the checkup's own order.
  areas.sort((a, b) => AREAS.indexOf(a.area) - AREAS.indexOf(b.area));
  return { areas };
}

const STATE_COLOR: Record<AreaState, string> = { ok: '#15803d', attention: '#b45309', problem: '#b91c1c', unavailable: '#64748b' };

export function buildCheckupHtmlReport(input: CheckupReportInput, t: T, lang: Lang, generatedAt: string, appVersion: string): string {
  const verdict = overall(input.areas.map((a) => ({ area: a.area, state: a.state, count: a.count })));
  const rows = input.areas
    .map((a) => {
      const detail = a.state === 'unavailable'
        ? t(`errors.${a.reason ?? 'not_checked'}`)
        : t(`checkup.area.${a.area}.${a.state}`, { n: a.count, ...(a.vars ?? {}) });
      return `<tr>
        <td><strong>${escapeHtml(t(`checkup.area.${a.area}.title`))}</strong><div class="muted">${escapeHtml(t(`checkup.area.${a.area}.what`))}</div></td>
        <td><span class="state" style="color:${STATE_COLOR[a.state]};border-color:${STATE_COLOR[a.state]}">${escapeHtml(t(`checkup.state.${a.state}`))}</span></td>
        <td>${escapeHtml(detail)}</td>
      </tr>`;
    })
    .join('');

  return `<!doctype html>
<html lang="${lang}" dir="${directionOf(lang)}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(t('checkup.reportTitle'))}</title>
${REPORT_STYLE}
<style>
  .verdict { border: 2px solid ${STATE_COLOR[verdict]}; border-radius: 10px; padding: 12px 16px; margin: 8px 0 18px; }
  .verdict strong { color: ${STATE_COLOR[verdict]}; font-size: 18px; }
  .state { display: inline-block; border: 1px solid; border-radius: 999px; padding: 1px 10px; font-size: 12px; font-weight: 600; white-space: nowrap; }
</style>
</head>
<body><div class="page">
<header>
  <div class="brand">Blazma Cyber</div>
  <h1>${escapeHtml(t('checkup.reportTitle'))}</h1>
  <div class="muted">${escapeHtml(t('report.generated', { time: fmt(lang, generatedAt) }))} · <bdi dir="ltr" class="ltr">v${escapeHtml(appVersion)}</bdi></div>
</header>
<div class="verdict"><strong>${escapeHtml(t(`checkup.verdict.${verdict}`))}</strong></div>
<table class="grid">
  <thead><tr><th>${escapeHtml(t('checkup.reportArea'))}</th><th>${escapeHtml(t('checkup.reportState'))}</th><th>${escapeHtml(t('checkup.reportDetail'))}</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
<p class="desc">${escapeHtml(t('checkup.readOnly'))}</p>
<footer>${escapeHtml(t('checkup.reportFooter'))}</footer>
</div></body></html>`;
}
