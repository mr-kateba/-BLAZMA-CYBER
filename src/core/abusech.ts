// abuse.ch community threat intelligence: MalwareBazaar (malware samples), URLhaus (malware
// distribution URLs/hosts) and ThreatFox (IOCs). One free Auth-Key (https://auth.abuse.ch) covers all.
// These parsers only restate what the service answered; "not listed" is never presented as "safe".

import type { ReputationResult } from '../shared/api';

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Json) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null);
const int = (v: unknown): number | undefined => {
  const n = typeof v === 'number' ? v : typeof v === 'string' && /^\d{1,12}$/.test(v.trim()) ? Number(v) : NaN;
  return Number.isFinite(n) ? n : undefined;
};
const uniq = (a: string[], max: number) => [...new Set(a)].slice(0, max);

export const ABUSECH_LINK_HOSTS = ['bazaar.abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch'] as const;

export const ABUSECH_ENDPOINTS = {
  malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
  urlhausHost: 'https://urlhaus-api.abuse.ch/v1/host/',
  urlhausPayload: 'https://urlhaus-api.abuse.ch/v1/payload/',
  threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
} as const;

/** abuse.ch timestamps look like "2026-09-20 08:15:02" or "2026-09-20 08:15:02 UTC" (UTC). */
export function abusechDate(v: unknown): string | null {
  const s = str(v);
  const m = s ? /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\s*UTC)?$/.exec(s) : null;
  if (!m) return null;
  const d = new Date(`${m[1]}T${m[2]}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Classifies the `query_status` every abuse.ch API returns:
 * 'ok' → a record exists; 'not_found' → the service has no record; anything else → an error code.
 */
export function abusechStatus(json: unknown): 'ok' | 'not_found' | 'api_key_invalid' | 'invalid_input' | 'invalid_response' {
  const q = str(obj(json).query_status)?.toLowerCase();
  if (!q) return 'invalid_response';
  if (q === 'ok') return 'ok';
  if (['hash_not_found', 'no_results', 'no_result', 'not_found'].includes(q)) return 'not_found';
  if (q.includes('auth_key') || q === 'unauthorized') return 'api_key_invalid';
  if (q.startsWith('illegal') || q.startsWith('invalid') || q.includes('missing')) return 'invalid_input';
  return 'invalid_response';
}

const earliest = (xs: Array<string | null>) => xs.filter((x): x is string => !!x).sort()[0] ?? null;
const latest = (xs: Array<string | null>) => xs.filter((x): x is string => !!x).sort().at(-1) ?? null;

export function parseMalwareBazaar(json: unknown): ReputationResult {
  const d = obj(arr(obj(json).data)[0]);
  const sha256 = str(d.sha256_hash)?.toLowerCase() ?? null;
  return {
    service: 'malwarebazaar',
    found: true,
    listed: true,
    threat: str(d.signature),
    typeDescription: str(d.file_type),
    names: uniq([str(d.file_name)].filter((x): x is string => !!x), 5),
    tags: uniq(arr(d.tags).map(str).filter((x): x is string => !!x), 30),
    firstSeen: abusechDate(d.first_seen),
    lastSeen: abusechDate(d.last_seen),
    ...(sha256 && /^[a-f0-9]{64}$/.test(sha256) ? { link: `https://bazaar.abuse.ch/sample/${sha256}/` } : {}),
  };
}

export function parseUrlhausHost(json: unknown): ReputationResult {
  const o = obj(json);
  const urls = arr(o.urls).map(obj);
  const online = urls.filter((u) => str(u.url_status) === 'online').length;
  const ref = str(o.urlhaus_reference);
  return {
    service: 'urlhaus',
    found: true,
    listed: true,
    listedActive: online > 0,
    urlCount: int(o.url_count) ?? urls.length,
    onlineUrls: online,
    threat: uniq(urls.map((u) => str(u.threat)).filter((x): x is string => !!x), 5).join(', ') || null,
    tags: uniq(urls.flatMap((u) => arr(u.tags).map(str)).filter((x): x is string => !!x), 30),
    firstSeen: abusechDate(o.firstseen),
    lastSeen: latest(urls.map((u) => abusechDate(u.date_added))),
    ...(ref && urlhausLink(ref) ? { link: ref } : {}),
  };
}

export function parseUrlhausPayload(json: unknown): ReputationResult {
  const o = obj(json);
  const urls = arr(o.urls).map(obj);
  const online = urls.filter((u) => str(u.url_status) === 'online').length;
  return {
    service: 'urlhaus',
    found: true,
    listed: true,
    listedActive: online > 0,
    threat: str(o.signature),
    typeDescription: str(o.file_type),
    urlCount: int(o.url_count) ?? urls.length,
    onlineUrls: online,
    firstSeen: abusechDate(o.firstseen),
    lastSeen: abusechDate(o.lastseen),
  };
}

export function parseThreatFox(json: unknown): ReputationResult {
  const rows = arr(obj(json).data).map(obj);
  const id = rows.map((r) => int(r.id)).find((x) => x !== undefined);
  const last = latest(rows.map((r) => abusechDate(r.last_seen) ?? abusechDate(r.first_seen)));
  const confidences = rows.map((r) => int(r.confidence_level)).filter((x): x is number => x !== undefined);
  return {
    service: 'threatfox',
    found: true,
    listed: true,
    threat: uniq(rows.map((r) => str(r.malware_printable) ?? str(r.malware)).filter((x): x is string => !!x), 5).join(', ') || null,
    typeDescription: uniq(rows.map((r) => str(r.threat_type_desc) ?? str(r.threat_type)).filter((x): x is string => !!x), 3).join(', ') || null,
    tags: uniq(rows.flatMap((r) => arr(r.tags).map(str)).filter((x): x is string => !!x), 30),
    ...(confidences.length ? { confidence: Math.max(...confidences) } : {}),
    firstSeen: earliest(rows.map((r) => abusechDate(r.first_seen))),
    lastSeen: last,
    ...(id !== undefined ? { link: `https://threatfox.abuse.ch/ioc/${id}/` } : {}),
  };
}

function urlhausLink(ref: string): boolean {
  try {
    const u = new URL(ref);
    return u.protocol === 'https:' && u.hostname === 'urlhaus.abuse.ch' && !u.username && !u.port;
  } catch {
    return false;
  }
}
