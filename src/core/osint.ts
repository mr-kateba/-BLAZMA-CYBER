// OSINT workspace (pure): target normalization, parsers for public sources, and pivot links.
//
// Only lawful, public, unauthenticated sources are queried, and only when the user starts a lookup.
// Pivot links are never fetched by Blazma: they open in the user's browser after an explicit click.

import { isDomain } from './validation';

export type OsintTargetType = 'domain' | 'email' | 'username' | 'url';

export const OSINT_TYPES: readonly OsintTargetType[] = ['domain', 'email', 'username', 'url'];

const EMAIL_RE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([a-z0-9.-]{1,253})$/i;
const USERNAME_RE = /^[a-z0-9](?:[a-z0-9._-]{0,38})$/i;

/** Returns the canonical target or null when it isn't valid for the chosen type. */
export function normalizeOsintTarget(type: unknown, raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  const s = raw.trim();
  if (!s || /\s/.test(s)) return null;
  switch (type) {
    case 'domain': {
      const d = s.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
      return isDomain(d) ? d : null;
    }
    case 'email': {
      const m = EMAIL_RE.exec(s);
      if (!m) return null;
      const domain = m[1]!.toLowerCase();
      if (!isDomain(domain)) return null;
      const local = s.slice(0, s.lastIndexOf('@'));
      if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return null;
      return `${local}@${domain}`;
    }
    case 'username': {
      const u = s.replace(/^@/, '');
      return USERNAME_RE.test(u) ? u : null;
    }
    case 'url': {
      let u: URL;
      try {
        u = new URL(s);
      } catch {
        return null;
      }
      if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password) return null;
      if (!isDomain(u.hostname.toLowerCase())) return null;
      u.hash = '';
      return u.toString();
    }
    default:
      return null;
  }
}

export function emailDomain(email: string): string {
  return email.slice(email.lastIndexOf('@') + 1);
}

// ------------------------------------------------------------------ Certificate Transparency (crt.sh)

export interface CtSummary {
  certificates: number;
  subdomains: string[];
  truncated: boolean;
  firstSeen: string | null;
  lastSeen: string | null;
  issuers: Array<{ name: string; count: number }>;
}

const MAX_SUBDOMAINS = 500;

function ctDate(v: unknown): string | null {
  if (typeof v !== 'string' || !v) return null;
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(v) ? v : `${v}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Summarizes crt.sh JSON: unique names under `domain`, logging dates and top issuers. */
export function parseCrtSh(json: unknown, domain: string): CtSummary {
  const rows = Array.isArray(json) ? json : [];
  const names = new Set<string>();
  const issuers = new Map<string, number>();
  const ids = new Set<string>();
  let first: string | null = null;
  let last: string | null = null;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const o = r as Record<string, unknown>;
    const id = String(o.id ?? '');
    if (id && ids.has(id)) continue;
    if (id) ids.add(id);
    for (const field of [o.name_value, o.common_name]) {
      if (typeof field !== 'string') continue;
      for (const line of field.split(/\s+/)) {
        const n = line.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
        if (n && (n === domain || n.endsWith(`.${domain}`)) && isDomain(n)) names.add(n);
      }
    }
    const issuer = typeof o.issuer_name === 'string' ? (/(?:^|,\s*)O=("?)([^,"]+)\1/.exec(o.issuer_name)?.[2] ?? o.issuer_name) : null;
    if (issuer) issuers.set(issuer, (issuers.get(issuer) ?? 0) + 1);
    const at = ctDate(o.entry_timestamp) ?? ctDate(o.not_before);
    if (at) {
      if (!first || at < first) first = at;
      if (!last || at > last) last = at;
    }
  }
  const sorted = [...names].sort((a, b) => a.split('.').length - b.split('.').length || a.localeCompare(b));
  return {
    certificates: ids.size || rows.length,
    subdomains: sorted.slice(0, MAX_SUBDOMAINS),
    truncated: sorted.length > MAX_SUBDOMAINS,
    firstSeen: first,
    lastSeen: last,
    issuers: [...issuers.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count })),
  };
}

// ------------------------------------------------------------------ Wayback Machine availability API

export interface WaybackSnapshot {
  url: string;
  timestamp: string;
}

/** Parses https://archive.org/wayback/available — returns the closest snapshot or null. */
export function parseWaybackAvailable(json: unknown): WaybackSnapshot | null {
  const c = (json as { archived_snapshots?: { closest?: Record<string, unknown> } } | null)?.archived_snapshots?.closest;
  if (!c || c.available !== true || typeof c.url !== 'string' || typeof c.timestamp !== 'string') return null;
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(c.timestamp);
  if (!m) return null;
  let url: URL;
  try {
    url = new URL(c.url);
  } catch {
    return null;
  }
  if (url.hostname !== 'web.archive.org') return null;
  url.protocol = 'https:';
  return { url: url.toString(), timestamp: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z` };
}

// ------------------------------------------------------------------ GitHub public profile

export interface GithubProfile {
  login: string;
  name: string | null;
  company: string | null;
  blog: string | null;
  location: string | null;
  bio: string | null;
  publicRepos: number | null;
  followers: number | null;
  createdAt: string | null;
  htmlUrl: string | null;
}

const str = (v: unknown, max = 300): string | null => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export function parseGithubUser(json: unknown): GithubProfile | null {
  if (!json || typeof json !== 'object') return null;
  const o = json as Record<string, unknown>;
  const login = str(o.login, 64);
  if (!login) return null;
  const html = str(o.html_url, 200);
  return {
    login,
    name: str(o.name),
    company: str(o.company),
    blog: str(o.blog),
    location: str(o.location),
    bio: str(o.bio, 500),
    publicRepos: num(o.public_repos),
    followers: num(o.followers),
    createdAt: str(o.created_at, 40),
    htmlUrl: html && html.startsWith('https://github.com/') ? html : null,
  };
}

// ------------------------------------------------------------------ Pivot links (opened only on click)

export interface OsintPivot {
  id: string;
  url: string;
  /** i18n key (privacy.data.*) describing what the site receives. */
  dataKind: string;
}

const enc = encodeURIComponent;

/** Curated public lookup pages for a (normalized) target. Deterministic, so the main process can re-derive and verify. */
export function osintPivots(type: OsintTargetType, value: string): OsintPivot[] {
  switch (type) {
    case 'domain':
      return [
        { id: 'crtsh', url: `https://crt.sh/?q=${enc(value)}`, dataKind: 'privacy.data.domain' },
        { id: 'wayback', url: `https://web.archive.org/web/*/${enc(value)}*`, dataKind: 'privacy.data.domain' },
        { id: 'urlscan', url: `https://urlscan.io/search/#${enc(`domain:${value}`)}`, dataKind: 'privacy.data.domain' },
        { id: 'virustotal', url: `https://www.virustotal.com/gui/domain/${enc(value)}`, dataKind: 'privacy.data.domain' },
        { id: 'securitytrails', url: `https://securitytrails.com/domain/${enc(value)}/dns`, dataKind: 'privacy.data.domain' },
      ];
    case 'email':
      return [
        { id: 'duckduckgo', url: `https://duckduckgo.com/?q=${enc(`"${value}"`)}`, dataKind: 'privacy.data.email' },
        { id: 'hibp', url: 'https://haveibeenpwned.com/', dataKind: 'privacy.data.none' },
        { id: 'virustotal', url: `https://www.virustotal.com/gui/domain/${enc(emailDomain(value))}`, dataKind: 'privacy.data.domain' },
      ];
    case 'username':
      return [
        { id: 'github', url: `https://github.com/${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'gitlab', url: `https://gitlab.com/${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'reddit', url: `https://www.reddit.com/user/${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'x', url: `https://x.com/${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'keybase', url: `https://keybase.io/${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'hackernews', url: `https://news.ycombinator.com/user?id=${enc(value)}`, dataKind: 'privacy.data.username' },
        { id: 'duckduckgo', url: `https://duckduckgo.com/?q=${enc(`"${value}"`)}`, dataKind: 'privacy.data.username' },
      ];
    case 'url':
      return [
        { id: 'wayback', url: `https://web.archive.org/web/*/${value}`, dataKind: 'privacy.data.url' },
        { id: 'urlscan', url: `https://urlscan.io/search/#${enc(`page.url:"${value}"`)}`, dataKind: 'privacy.data.url' },
        { id: 'duckduckgo', url: `https://duckduckgo.com/?q=${enc(`"${value}"`)}`, dataKind: 'privacy.data.url' },
      ];
  }
}
