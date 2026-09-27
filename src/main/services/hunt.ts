// Threat hunting: correlate an indicator across BLAZMA's own local data — cases, quarantine,
// activity, network-activity log, and (on demand) live processes/connections/services/startup/tasks.
// Read-only. Everything is local; nothing is sent anywhere.

import type { CaseService } from './cases';
import type { HistoryService } from './history';
import type { QuarantineService } from './quarantine';
import * as forensics from './forensics';
import type { HuntHit, HuntResult, HuntSource, PersistenceItem, YaraRuleFile } from '../../shared/api';
import type { YaraService } from './yara';
import { indicatorType, matches, persistenceFlags } from '../../core/hunt';

export class HuntService {
  constructor(
    private readonly cases: CaseService,
    private readonly history: HistoryService,
    private readonly quarantine: QuarantineService,
    private readonly yara: YaraService,
  ) {}

  async search(rawQuery: unknown): Promise<HuntResult> {
    if (typeof rawQuery !== 'string' || !rawQuery.trim()) throw new Error('invalid_input');
    const query = rawQuery.trim();
    const type = indicatorType(query);
    const m = (s: string | null | undefined) => matches(s, query, type);
    const started = Date.now();
    const hits: HuntHit[] = [];
    const searched: HuntResult['searched'] = [];
    const run = async (source: HuntSource, fn: () => void | Promise<void>) => {
      try {
        await fn();
        searched.push({ source, ok: true });
      } catch (e) {
        searched.push({ source, ok: false, error: (e as { code?: string }).code ?? 'error' });
      }
    };

    await run('case', () => {
      for (const summary of this.cases.list()) {
        const c = this.cases.get(summary.id);
        for (const ev of c.evidence) {
          if (m(ev.value) || m(ev.label) || (ev.details && Object.values(ev.details).some((v) => m(String(v))))) {
            hits.push({ source: 'case', title: `${c.id} — ${c.name}`, detail: `${ev.kind}: ${ev.value}`, time: ev.addedAt, ref: c.id });
          }
        }
        if (m(c.name) || m(c.description) || c.tags.some(m)) hits.push({ source: 'case', title: `${c.id} — ${c.name}`, detail: null, time: c.updatedAt, ref: c.id });
      }
    });

    await run('quarantine', () => {
      for (const q of this.quarantine.list()) {
        if (m(q.originalName) || m(q.originalPath) || m(q.sha256) || m(q.reason)) {
          hits.push({ source: 'quarantine', title: q.originalName, detail: q.sha256, time: q.quarantinedAt, ref: q.id });
        }
      }
    });

    await run('activity', () => {
      for (const a of this.history.activity.list()) if (m(a.subject)) hits.push({ source: 'activity', title: a.subject, detail: a.kind, time: a.timestamp, ref: null });
    });

    await run('network_log', () => {
      for (const n of this.history.network.list()) if (m(n.host) || m(n.service)) hits.push({ source: 'network_log', title: n.host, detail: `${n.module} · ${n.outcome}`, time: n.timestamp, ref: null });
    });

    // Live system correlation (best-effort; unavailable off Windows for some sources).
    await run('process', async () => {
      const r = await forensics.processes();
      for (const p of r.rows) if (m(p.name) || m(p.path) || m(p.commandLine)) hits.push({ source: 'process', title: `${p.name} (${p.pid})`, detail: p.path, time: p.started, ref: null });
    });
    await run('connection', async () => {
      const r = await forensics.connections();
      for (const c of r.rows) if (m(c.remoteAddress) || m(c.process)) hits.push({ source: 'connection', title: `${c.remoteAddress ?? '—'}:${c.remotePort ?? ''}`, detail: c.process, time: null, ref: null });
    });
    if (process.platform === 'win32') {
      await run('service', async () => {
        const r = await forensics.services();
        for (const s of r.rows) if (m(s.name) || m(s.displayName) || m(s.binaryPath)) hits.push({ source: 'service', title: s.displayName ?? s.name, detail: s.binaryPath, time: null, ref: null });
      });
      await run('startup', async () => {
        const r = await forensics.startup();
        for (const s of r.rows) if (m(s.name) || m(s.command)) hits.push({ source: 'startup', title: s.name, detail: s.command, time: null, ref: null });
      });
    }

    await run('yara_rule', async () => {
      const rules: YaraRuleFile[] = await this.yara.listRules();
      for (const rule of rules) {
        if (m(rule.name) || m(rule.id)) hits.push({ source: 'yara_rule', title: rule.name, detail: rule.id, time: null, ref: null });
      }
    });

    return { query, indicatorType: type, hits, searched, durationMs: Date.now() - started };
  }

  /** Reviews autostart persistence (startup entries, non-Microsoft scheduled tasks) with location flags. */
  async persistence(): Promise<PersistenceItem[]> {
    if (process.platform !== 'win32') throw new forensics.ForensicsError('unsupported_platform');
    const [start, task] = await Promise.all([forensics.startup(), forensics.tasks()]);
    const items: PersistenceItem[] = [];
    for (const s of start.rows) items.push({ kind: 'startup', name: s.name, command: s.command, location: s.location, flags: persistenceFlags(s.command) });
    for (const tk of task.rows) {
      if (tk.microsoft) continue;
      const cmd = tk.actions.join(' ');
      items.push({ kind: 'task', name: tk.name, command: cmd, location: tk.path, flags: persistenceFlags(cmd) });
    }
    return items.sort((a, b) => b.flags.length - a.flags.length);
  }
}
