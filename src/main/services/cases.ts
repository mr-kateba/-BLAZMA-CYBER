// Local investigation case store. Cases are plain JSON under <data>/state/cases/, one file per case.
// Evidence is kept strictly separate from analyst notes (different arrays), as required.

import { readdirSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { CaseNote, CaseSummary, Evidence, EvidenceKind, InvestigationCase, TimelineEvent } from '../../shared/api';
import { readJson, writeJson } from './json-store';
import { subDir } from './paths';

export class CaseError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

const ID_RE = /^CASE-\d{4}-\d{3,}$/;
const EVIDENCE_KINDS: EvidenceKind[] = ['file', 'hash', 'ip', 'domain', 'url', 'email', 'process', 'connection', 'finding', 'other'];
const rid = (p: string) => `${p}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

export class CaseService {
  private readonly dir = subDir('cases');

  private file(id: string): string {
    return join(this.dir, `${id}.json`);
  }
  private load(id: unknown): InvestigationCase {
    if (typeof id !== 'string' || !ID_RE.test(id)) throw new CaseError('invalid_input');
    const c = readJson<InvestigationCase | null>(this.file(id), null);
    if (!c || c.id !== id) throw new CaseError('case_not_found');
    c.evidence ??= [];
    c.notes ??= [];
    c.timeline ??= [];
    return c;
  }
  private save(c: InvestigationCase): InvestigationCase {
    c.updatedAt = new Date().toISOString();
    writeJson(this.file(c.id), c);
    return c;
  }
  private ids(): string[] {
    try {
      return readdirSync(this.dir).filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, '')).filter((id) => ID_RE.test(id));
    } catch {
      return [];
    }
  }

  private nextId(): string {
    const year = new Date().getFullYear();
    const prefix = `CASE-${year}-`;
    const n = this.ids().filter((id) => id.startsWith(prefix)).map((id) => Number(id.slice(prefix.length))).reduce((m, x) => Math.max(m, x), 0);
    return `${prefix}${String(n + 1).padStart(3, '0')}`;
  }

  list(): CaseSummary[] {
    return this.ids()
      .map((id) => {
        try {
          const c = this.load(id);
          return { id: c.id, name: c.name, status: c.status, tags: c.tags, createdAt: c.createdAt, updatedAt: c.updatedAt, evidenceCount: c.evidence.length, noteCount: c.notes.length };
        } catch {
          return null;
        }
      })
      .filter((x): x is CaseSummary => !!x)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  get(id: unknown): InvestigationCase {
    return this.load(id);
  }

  private static text(v: unknown, max: number): string {
    return typeof v === 'string' ? v.slice(0, max) : '';
  }
  private static tags(v: unknown): string[] {
    return Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === 'string').map((x) => x.trim().slice(0, 40)).filter(Boolean))].slice(0, 20) : [];
  }

  create(name: unknown, description: unknown, tags: unknown): InvestigationCase {
    const cleanName = CaseService.text(name, 120).trim();
    if (!cleanName) throw new CaseError('invalid_input');
    const now = new Date().toISOString();
    const c: InvestigationCase = {
      id: this.nextId(),
      name: cleanName,
      description: CaseService.text(description, 4000),
      tags: CaseService.tags(tags),
      status: 'open',
      createdAt: now,
      updatedAt: now,
      evidence: [],
      notes: [],
      timeline: [{ id: rid('t'), time: now, title: 'case.created', detail: null, kind: 'status' }],
    };
    return this.save(c);
  }

  update(id: unknown, patch: unknown): InvestigationCase {
    const c = this.load(id);
    const p = (patch ?? {}) as Record<string, unknown>;
    if (typeof p.name === 'string' && p.name.trim()) c.name = p.name.trim().slice(0, 120);
    if (typeof p.description === 'string') c.description = p.description.slice(0, 4000);
    if (Array.isArray(p.tags)) c.tags = CaseService.tags(p.tags);
    if (p.status === 'open' || p.status === 'closed') {
      if (p.status !== c.status) c.timeline.push({ id: rid('t'), time: new Date().toISOString(), title: p.status === 'closed' ? 'case.closed' : 'case.reopened', detail: null, kind: 'status' });
      c.status = p.status;
    }
    return this.save(c);
  }

  remove(id: unknown): void {
    const c = this.load(id);
    void rm(this.file(c.id), { force: true });
  }

  addEvidence(id: unknown, ev: unknown): InvestigationCase {
    const c = this.load(id);
    const e = (ev ?? {}) as Record<string, unknown>;
    if (!EVIDENCE_KINDS.includes(e.kind as EvidenceKind)) throw new CaseError('invalid_input');
    const value = CaseService.text(e.value, 4096).trim();
    if (!value) throw new CaseError('invalid_input');
    let details: Evidence['details'] = null;
    if (e.details && typeof e.details === 'object' && !Array.isArray(e.details)) {
      details = {};
      for (const [k, v] of Object.entries(e.details as Record<string, unknown>).slice(0, 30)) {
        if (v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') details[k.slice(0, 40)] = typeof v === 'string' ? v.slice(0, 1000) : v;
      }
    }
    const entry: Evidence = {
      id: rid('e'),
      kind: e.kind as EvidenceKind,
      value,
      label: typeof e.label === 'string' ? e.label.slice(0, 200) : null,
      source: CaseService.text(e.source, 40) || 'manual',
      addedAt: new Date().toISOString(),
      details,
    };
    c.evidence.push(entry);
    c.timeline.push({ id: rid('t'), time: entry.addedAt, title: 'case.evidenceAdded', detail: `${entry.kind}:${value}`, kind: 'evidence' });
    return this.save(c);
  }

  removeEvidence(id: unknown, evidenceId: unknown): InvestigationCase {
    const c = this.load(id);
    c.evidence = c.evidence.filter((e) => e.id !== evidenceId);
    return this.save(c);
  }

  addNote(id: unknown, text: unknown): InvestigationCase {
    const c = this.load(id);
    const body = CaseService.text(text, 20000).trim();
    if (!body) throw new CaseError('invalid_input');
    const now = new Date().toISOString();
    const note: CaseNote = { id: rid('n'), text: body, createdAt: now, updatedAt: now };
    c.notes.push(note);
    c.timeline.push({ id: rid('t'), time: now, title: 'case.noteAdded', detail: null, kind: 'note' });
    return this.save(c);
  }

  updateNote(id: unknown, noteId: unknown, text: unknown): InvestigationCase {
    const c = this.load(id);
    const note = c.notes.find((n) => n.id === noteId);
    if (!note) throw new CaseError('note_not_found');
    const body = CaseService.text(text, 20000).trim();
    if (!body) throw new CaseError('invalid_input');
    note.text = body;
    note.updatedAt = new Date().toISOString();
    return this.save(c);
  }

  removeNote(id: unknown, noteId: unknown): InvestigationCase {
    const c = this.load(id);
    c.notes = c.notes.filter((n) => n.id !== noteId);
    return this.save(c);
  }

  addEvent(id: unknown, title: unknown, detail: unknown, time: unknown): InvestigationCase {
    const c = this.load(id);
    const t = CaseService.text(title, 200).trim();
    if (!t) throw new CaseError('invalid_input');
    const when = typeof time === 'string' && !Number.isNaN(Date.parse(time)) ? new Date(time).toISOString() : new Date().toISOString();
    const ev: TimelineEvent = { id: rid('t'), time: when, title: t, detail: typeof detail === 'string' ? detail.slice(0, 1000) : null, kind: 'event' };
    c.timeline.push(ev);
    return this.save(c);
  }

  clearAll(): void {
    for (const id of this.ids()) void rm(this.file(id), { force: true });
  }
}
