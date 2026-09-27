// Pure threat-hunting helpers: indicator typing, matching, and simple persistence-review flags.
// Flags are prompts for an analyst to look closer — never verdicts on their own.

import { isDomain, isIP } from './validation';

export type IndicatorType = 'ip' | 'domain' | 'hash' | 'text';

export function indicatorType(q: string): IndicatorType {
  const s = q.trim();
  if (isIP(s)) return 'ip';
  if (/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(s)) return 'hash';
  if (isDomain(s.toLowerCase())) return 'domain';
  return 'text';
}

/** Case-insensitive containment; hashes and IPs must match whole tokens to avoid partial hits. */
export function matches(haystack: string | null | undefined, query: string, type: IndicatorType): boolean {
  if (!haystack) return false;
  const h = haystack.toLowerCase();
  const q = query.trim().toLowerCase();
  if (!q) return false;
  if (type === 'hash' || type === 'ip') {
    // Characters that would make the match part of a longer token:
    //  hash: hex; IPv4: digits and dots (so "10.0.0.1:443" matches but "10.0.0.12" doesn't); IPv6: hex and colons.
    const cont = type === 'hash' ? /[a-z0-9]/ : q.includes(':') ? /[a-f0-9:]/ : /[0-9.]/;
    let from = 0;
    for (;;) {
      const i = h.indexOf(q, from);
      if (i < 0) return false;
      const before = i === 0 ? '' : h[i - 1]!;
      const after = h[i + q.length] ?? '';
      if (!cont.test(before) && !cont.test(after)) return true;
      from = i + 1;
    }
  }
  return h.includes(q);
}

const USER_FOLDERS = ['\\appdata\\', '\\temp\\', '\\users\\public\\', '\\downloads\\'];
const SYSTEM_FOLDERS = ['c:\\windows\\', 'c:\\program files\\', 'c:\\program files (x86)\\', '%systemroot%', '%windir%'];

/**
 * Location-based review flags for an autostart command (i18n keys under hunt.flag.*):
 *  - userFolder: runs from a per-user or temporary folder
 *  - outsideSystem: runs from outside Windows / Program Files
 */
export function persistenceFlags(command: string | null | undefined): string[] {
  if (!command) return [];
  const c = command.toLowerCase();
  const flags: string[] = [];
  if (USER_FOLDERS.some((f) => c.includes(f))) flags.push('hunt.flag.userFolder');
  if (!SYSTEM_FOLDERS.some((f) => c.includes(f)) && /[a-z]:\\/.test(c)) flags.push('hunt.flag.outsideSystem');
  return flags;
}
