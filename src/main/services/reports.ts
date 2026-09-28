// Report generation and local storage. Reports are written to <data>/reports/ and can be opened
// or revealed in the OS file manager. PDF is produced by printing the HTML report via an offscreen
// BrowserWindow (Electron printToPDF) — no extra dependency.

import { BrowserWindow, shell } from 'electron';
import os from 'node:os';
import { app } from 'electron';
import { writeFile, readFile, rm, stat } from 'node:fs/promises';
import { dirname, extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { InvestigationCase, ReportFormat, ReportOptions, ReportRecord } from '../../shared/api';
import type { Lang } from '../../core/i18n';
import { buildHtmlReport, buildJsonReport, type MachineInfo } from '../../core/report';
import { createTranslator, type Dict } from '../../core/i18n';
import en from '../../../locales/en.json';
import ar from '../../../locales/ar.json';
import { readJson, writeJson } from './json-store';
import { randomUUID } from 'node:crypto';
import { caseIocs, iocsToCsv, iocsToStix } from '../../core/ioc-export';
import { buildCheckupHtmlReport, sanitizeCheckupReport } from '../../core/checkup-report';
import { subDir } from './paths';

export class ReportError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const DICTS: Record<Lang, Dict> = { en: en as Dict, ar: ar as Dict };
const ID_RE = /^rep-[a-z0-9-]+$/;

function machineInfo(): MachineInfo {
  return { os: `${os.type()} ${os.release()}`, arch: os.arch(), hostname: os.hostname(), appVersion: app.getVersion() };
}

export class ReportService {
  private readonly dir = subDir('reports');
  private readonly indexFile = join(this.dir, 'index.json');

  private index(): ReportRecord[] {
    const raw = readJson<unknown>(this.indexFile, []);
    return Array.isArray(raw) ? (raw as ReportRecord[]) : [];
  }
  private saveIndex(list: ReportRecord[]): void {
    writeJson(this.indexFile, list);
  }

  list(): ReportRecord[] {
    return this.index().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async generate(c: InvestigationCase, rawOpts: unknown): Promise<ReportRecord> {
    const o = (rawOpts ?? {}) as Record<string, unknown>;
    const format: ReportFormat = (['json', 'pdf', 'csv', 'stix'] as const).find((f) => f === o.format) ?? 'html';
    const language: Lang = o.language === 'ar' ? 'ar' : 'en';
    const opts: ReportOptions = {
      format,
      language,
      includeMachineInfo: o.includeMachineInfo === true,
      includeNotes: o.includeNotes !== false,
      includeTimeline: o.includeTimeline !== false,
    };
    const t = createTranslator(DICTS[language], DICTS.en);
    const now = new Date().toISOString();
    const machine = opts.includeMachineInfo ? machineInfo() : null;
    const id = `rep-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const ext = format === 'stix' ? 'stix.json' : format;
    const path = join(this.dir, `${c.id}-${language}-${id}.${ext}`);

    if (format === 'csv' || format === 'stix') {
      const rows = caseIocs(c);
      const body = format === 'csv' ? iocsToCsv(rows, c.id, c.name) : iocsToStix(c, rows, now, randomUUID);
      await writeFile(path, body, { encoding: 'utf8', mode: 0o600 });
    } else if (format === 'json') {
      await writeFile(path, buildJsonReport(c, opts, now, machine), { encoding: 'utf8', mode: 0o600 });
    } else {
      const html = buildHtmlReport(c, opts, t, now, machine);
      if (format === 'html') {
        await writeFile(path, html, { encoding: 'utf8', mode: 0o600 });
      } else {
        await this.htmlToPdf(html, path);
      }
    }
    const st = await stat(path);
    const rec: ReportRecord = { id, caseId: c.id, caseName: c.name, format, language, path, createdAt: now, sizeBytes: st.size };
    this.saveIndex([rec, ...this.index()]);
    return rec;
  }

  /** Saves the full-checkup summary (states and counts only) as an HTML or PDF report. */
  async generateCheckup(rawInput: unknown, rawLang: unknown, rawFormat: unknown): Promise<ReportRecord> {
    const input = sanitizeCheckupReport(rawInput);
    if (!input) throw new ReportError('invalid_input');
    const language: Lang = rawLang === 'ar' ? 'ar' : 'en';
    const format: ReportFormat = rawFormat === 'pdf' ? 'pdf' : 'html';
    const t = createTranslator(DICTS[language], DICTS.en);
    const now = new Date().toISOString();
    const id = `rep-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const path = join(this.dir, `checkup-${language}-${id}.${format}`);
    const html = buildCheckupHtmlReport(input, t, language, now, app.getVersion());
    if (format === 'html') await writeFile(path, html, { encoding: 'utf8', mode: 0o600 });
    else await this.htmlToPdf(html, path);
    const st = await stat(path);
    const rec: ReportRecord = { id, caseId: 'checkup', caseName: t('checkup.reportTitle'), format, language, path, createdAt: now, sizeBytes: st.size };
    this.saveIndex([rec, ...this.index()]);
    return rec;
  }

  /** Renders HTML to PDF in a hidden, sandboxed, offline window (no network, no scripts). */
  private async htmlToPdf(html: string, outPath: string): Promise<void> {
    const tmp = join(subDir('temp'), `report-${process.pid}-${Date.now()}.html`);
    await writeFile(tmp, html, 'utf8');
    const win = new BrowserWindow({
      show: false,
      webPreferences: { javascript: false, sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, images: true },
    });
    try {
      await win.loadURL(pathToFileURL(tmp).href);
      const pdf = await win.webContents.printToPDF({ printBackground: true });
      await writeFile(outPath, pdf, { mode: 0o600 });
    } finally {
      win.destroy();
      await rm(tmp, { force: true });
    }
  }

  private rec(id: unknown): ReportRecord {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new ReportError('invalid_input');
    const r = this.index().find((x) => x.id === id);
    if (!r) throw new ReportError('report_not_found');
    // Defence in depth: the index is local state, but we only ever open/delete our own report files.
    if (typeof r.path !== 'string' || dirname(resolve(r.path)) !== resolve(this.dir) || !['.html', '.pdf', '.json'].includes(extname(r.path))) {
      throw new ReportError('report_not_found');
    }
    return r;
  }

  async open(id: unknown): Promise<void> {
    const r = this.rec(id);
    const err = await shell.openPath(r.path);
    if (err) throw new ReportError('open_failed');
  }
  reveal(id: unknown): void {
    shell.showItemInFolder(this.rec(id).path);
  }
  async remove(id: unknown): Promise<void> {
    const r = this.rec(id);
    await rm(r.path, { force: true });
    this.saveIndex(this.index().filter((x) => x.id !== id));
  }
  async clearAll(): Promise<void> {
    for (const r of this.index()) await rm(r.path, { force: true });
    this.saveIndex([]);
  }

  /** For tests/preview: return the report content without persisting a PDF. */
  async render(c: InvestigationCase, opts: ReportOptions): Promise<string> {
    const t = createTranslator(DICTS[opts.language], DICTS.en);
    const now = new Date().toISOString();
    const machine = opts.includeMachineInfo ? machineInfo() : null;
    return opts.format === 'json' ? buildJsonReport(c, opts, now, machine) : buildHtmlReport(c, opts, t, now, machine);
  }
}
