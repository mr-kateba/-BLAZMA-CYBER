// Full checkup (pure): folds the read-only reports of several modules into one plain summary.
// Each area says ok / attention / problem / unavailable (with the reason) — an area that could not
// be checked never counts as "ok", and nothing is scored twice.

import type { DeviceSecurityReport } from './device-security';
import type { ExtensionAudit } from './extensions';
import type { FimDiff } from './fim';
import type { ListeningService } from './listening';
import type { TamperReport } from './tamper';
import type { WifiFinding } from './wifi';

export type CheckupArea = 'device' | 'tamper' | 'extensions' | 'wifi' | 'ports' | 'folders';
export type AreaState = 'ok' | 'attention' | 'problem' | 'unavailable';

export interface AreaResult {
  area: CheckupArea;
  state: AreaState;
  /** Number of items that need a look (0 when ok). */
  count: number;
  /** i18n error code when unavailable. */
  reason?: string;
  /** Extra numbers for the summary line (e.g. score). */
  vars?: Record<string, string | number>;
}

/** Either the module's data or the error code it returned. */
export type Part<T> = { data: T } | { error: string } | null;

const unavailable = (area: CheckupArea, reason: string): AreaResult => ({ area, state: 'unavailable', count: 0, reason });

export function deviceArea(p: Part<DeviceSecurityReport>): AreaResult {
  if (!p) return unavailable('device', 'not_checked');
  if ('error' in p) return unavailable('device', p.error);
  const r = p.data;
  if (r.evaluated === 0) return unavailable('device', 'unsupported_platform');
  const fail = r.checks.filter((c) => c.status === 'fail').length;
  const warn = r.checks.filter((c) => c.status === 'warn').length;
  return { area: 'device', state: fail ? 'problem' : warn ? 'attention' : 'ok', count: fail + warn, vars: { score: r.score ?? '—' } };
}

export function tamperArea(p: Part<TamperReport>): AreaResult {
  if (!p) return unavailable('tamper', 'not_checked');
  if ('error' in p) return unavailable('tamper', p.error);
  const known = p.data.findings.filter((f) => f.status !== 'unknown');
  if (known.length === 0) return unavailable('tamper', 'unsupported_platform');
  const fail = known.filter((f) => f.status === 'fail').length;
  const warn = known.filter((f) => f.status === 'warn').length;
  return { area: 'tamper', state: fail ? 'problem' : warn ? 'attention' : 'ok', count: fail + warn };
}

export function extensionsArea(p: Part<ExtensionAudit>): AreaResult {
  if (!p) return unavailable('extensions', 'not_checked');
  if ('error' in p) return unavailable('extensions', p.error);
  if (p.data.browsers.length === 0) return unavailable('extensions', 'no_browsers');
  // How an extension got there is the strong signal; broad access alone is not a verdict.
  const n = p.data.extensions.filter((e) => e.risk === 'high').length;
  return { area: 'extensions', state: n ? 'attention' : 'ok', count: n, vars: { total: p.data.extensions.length } };
}

export function wifiArea(p: Part<{ available: boolean; reason: string | null; findings: WifiFinding[] }>): AreaResult {
  if (!p) return unavailable('wifi', 'not_checked');
  if ('error' in p) return unavailable('wifi', p.error);
  if (!p.data.available) return unavailable('wifi', p.data.reason ?? 'wlan_unavailable');
  const high = p.data.findings.filter((f) => f.severity === 'high').length;
  const medium = p.data.findings.filter((f) => f.severity === 'medium').length;
  return { area: 'wifi', state: high ? 'problem' : medium ? 'attention' : 'ok', count: high + medium };
}

/** Programs reachable from the network that offer remote access, file sharing or a database. */
export function portsArea(p: Part<ListeningService[]>): AreaResult {
  if (!p) return unavailable('ports', 'not_checked');
  if ('error' in p) return unavailable('ports', p.error);
  const n = p.data.filter((s) => s.attention).length;
  return { area: 'ports', state: n ? 'attention' : 'ok', count: n, vars: { network: p.data.filter((s) => s.reach === 'network').length } };
}

/** Watched folders: `checks` are the results of checking every watch now. */
export function foldersArea(p: Part<Array<{ diff: FimDiff; totalChanges: number }>>): AreaResult {
  if (!p) return unavailable('folders', 'not_checked');
  if ('error' in p) return unavailable('folders', p.error);
  if (p.data.length === 0) return unavailable('folders', 'no_watches');
  const hidden = p.data.reduce((n, c) => n + c.diff.hiddenEdits.length, 0);
  const changes = p.data.reduce((n, c) => n + c.totalChanges, 0);
  return { area: 'folders', state: hidden ? 'problem' : changes ? 'attention' : 'ok', count: changes, vars: { folders: p.data.length } };
}

const RANK: Record<AreaState, number> = { problem: 3, attention: 2, ok: 1, unavailable: 0 };

/** Overall verdict: the worst checked area; "unavailable" only when nothing could be checked. */
export function overall(areas: AreaResult[]): AreaState {
  return areas.reduce<AreaState>((w, a) => (RANK[a.state] > RANK[w] ? a.state : w), 'unavailable');
}

/** What is remembered of the last checkup (no evidence, only states and counts). */
export interface CheckupSummary {
  at: string;
  verdict: AreaState;
  areas: Array<{ area: CheckupArea; state: AreaState; count: number }>;
}

const AREA_IDS: CheckupArea[] = ['device', 'tamper', 'extensions', 'wifi', 'ports', 'folders'];
const STATES: AreaState[] = ['ok', 'attention', 'problem', 'unavailable'];

/** Validates a summary coming from the (untrusted) renderer. */
export function sanitizeCheckupSummary(x: unknown, now = new Date()): CheckupSummary | null {
  if (!x || typeof x !== 'object') return null;
  const o = x as Record<string, unknown>;
  if (!Array.isArray(o.areas) || o.areas.length > AREA_IDS.length) return null;
  const areas: CheckupSummary['areas'] = [];
  for (const a of o.areas as unknown[]) {
    const r = (a ?? {}) as Record<string, unknown>;
    if (!AREA_IDS.includes(r.area as CheckupArea) || !STATES.includes(r.state as AreaState)) return null;
    if (typeof r.count !== 'number' || !Number.isInteger(r.count) || r.count < 0 || r.count > 1_000_000) return null;
    if (areas.some((y) => y.area === r.area)) return null;
    areas.push({ area: r.area as CheckupArea, state: r.state as AreaState, count: r.count });
  }
  // The verdict is recomputed, never trusted; the time is the main process's own.
  return { at: now.toISOString(), verdict: overall(areas.map((a) => ({ ...a }))), areas };
}
