// Hayabusa (Yamato Security) event-log hunting results (pure).
// Input: one JSONL line per detection from `hayabusa dfir-timeline -t jsonl -p super-verbose -b`.
// Sigma / Hayabusa rules are under the Detection Rule License 1.1: every match keeps its rule author.

export type EventLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';

/** Hayabusa's short MITRE ATT&CK tactic labels (config/mitre_tactics.txt) → stable ids for i18n. */
export const TACTICS: Record<string, string> = {
  Recon: 'reconnaissance', ResDev: 'resource_development', InitAccess: 'initial_access', Exec: 'execution', Persis: 'persistence',
  PrivEsc: 'privilege_escalation', Stealth: 'stealth', DefImpair: 'defense_impairment', CredAccess: 'credential_access', Disc: 'discovery',
  LatMov: 'lateral_movement', Collect: 'collection', C2: 'command_and_control', Exfil: 'exfiltration', Impact: 'impact',
};

export interface EventDetection {
  time: string | null;
  rule: string;
  level: EventLevel;
  computer: string | null;
  channel: string | null;
  eventId: number | null;
  recordId: number | null;
  tactics: string[];
  techniques: string[];
  details: Array<[string, string]>;
  ruleAuthor: string | null;
  ruleFile: string | null;
  ruleId: string | null;
  evtxFile: string | null;
}

export interface EventHuntSummary {
  total: number;
  byLevel: Record<EventLevel, number>;
  topRules: Array<{ rule: string; level: EventLevel; count: number; author: string | null }>;
  tactics: Array<{ id: string; count: number }>;
  /** MITRE ATT&CK technique ids with match counts. */
  techniques: Array<{ id: string; count: number }>;
  computers: string[];
  first: string | null;
  last: string | null;
}

const LEVELS: Record<string, EventLevel> = {
  critical: 'critical', crit: 'critical', high: 'high', medium: 'medium', med: 'medium', low: 'low', informational: 'informational', info: 'informational',
};
export const LEVEL_ORDER: Record<EventLevel, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

const str = (v: unknown, max = 500): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && /^\d{1,10}$/.test(v) ? Number(v) : null);

/** "2021-10-20 13:39:12.731 +00:00" → ISO; anything else → null. */
export function hayabusaTime(v: unknown): string | null {
  const s = str(v);
  const m = s ? /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) ([+-]\d{2}:\d{2})$/.exec(s) : null;
  if (!m) return null;
  const d = new Date(`${m[1]}T${m[2]!.replace(/(\.\d{3})\d+$/, '$1')}${m[3]}`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function flatDetails(v: unknown): Array<[string, string]> {
  if (typeof v === 'string') return v.trim() ? [['', v.slice(0, 2000)]] : [];
  if (!v || typeof v !== 'object' || Array.isArray(v)) return [];
  return Object.entries(v as Record<string, unknown>)
    .slice(0, 40)
    .map(([k, x]) => [k.slice(0, 100), (typeof x === 'string' ? x : JSON.stringify(x) ?? '').slice(0, 1000)] as [string, string]);
}

export function parseHayabusaLine(line: string): EventDetection | null {
  const t = line.trim();
  if (!t.startsWith('{')) return null;
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(t) as Record<string, unknown>;
  } catch {
    return null;
  }
  const rule = str(o.RuleTitle);
  if (!rule) return null;
  const arr = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
  return {
    time: hayabusaTime(o.Timestamp),
    rule,
    level: LEVELS[String(o.Level ?? '').toLowerCase()] ?? 'informational',
    computer: str(o.Computer, 200),
    channel: str(o.Channel, 200),
    eventId: num(o.EventID),
    recordId: num(o.RecordID),
    tactics: arr(o.MitreTactics).map((x) => TACTICS[x] ?? x.toLowerCase()).slice(0, 10),
    techniques: arr(o.MitreTags).filter((x) => /^T\d{4}(\.\d{3})?$/.test(x)).slice(0, 10),
    details: flatDetails(o.Details),
    ruleAuthor: str(o.RuleAuthor, 300),
    ruleFile: str(o.RuleFile, 300),
    ruleId: str(o.RuleID, 100),
    evtxFile: str(o.EvtxFile, 1000),
  };
}

/** Incremental summary: keeps counts for every detection even when only a sample of rows is kept. */
export class HuntAccumulator {
  private total = 0;
  private byLevel: Record<EventLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  private rules = new Map<string, { rule: string; level: EventLevel; count: number; author: string | null }>();
  private tactics = new Map<string, number>();
  private techniques = new Map<string, number>();
  private computers = new Set<string>();
  private first: string | null = null;
  private last: string | null = null;
  /** Kept rows per level (each capped), so the most severe detections are never crowded out. */
  private buckets: Record<EventLevel, EventDetection[]> = { critical: [], high: [], medium: [], low: [], informational: [] };

  constructor(private readonly maxRows = 5000) {}

  add(d: EventDetection) {
    this.total++;
    this.byLevel[d.level]++;
    const r = this.rules.get(d.rule) ?? { rule: d.rule, level: d.level, count: 0, author: d.ruleAuthor };
    r.count++;
    this.rules.set(d.rule, r);
    for (const t of d.tactics) this.tactics.set(t, (this.tactics.get(t) ?? 0) + 1);
    for (const t of d.techniques) this.techniques.set(t, (this.techniques.get(t) ?? 0) + 1);
    if (d.computer && this.computers.size < 50) this.computers.add(d.computer);
    if (d.time) {
      if (!this.first || d.time < this.first) this.first = d.time;
      if (!this.last || d.time > this.last) this.last = d.time;
    }
    const b = this.buckets[d.level];
    if (b.length < this.maxRows) b.push(d);
  }

  summary(): EventHuntSummary {
    return {
      total: this.total,
      byLevel: { ...this.byLevel },
      topRules: [...this.rules.values()].sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || b.count - a.count).slice(0, 50),
      tactics: [...this.tactics.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count),
      techniques: [...this.techniques.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count),
      computers: [...this.computers],
      first: this.first,
      last: this.last,
    };
  }

  /** Most severe first, newest first within a level; at most `maxRows`. */
  sortedRows(): EventDetection[] {
    const out: EventDetection[] = [];
    for (const lvl of Object.keys(LEVEL_ORDER) as EventLevel[]) {
      out.push(...[...this.buckets[lvl]].sort((a, b) => (b.time ?? '').localeCompare(a.time ?? '')));
      if (out.length >= this.maxRows) break;
    }
    return out.slice(0, this.maxRows);
  }
}
