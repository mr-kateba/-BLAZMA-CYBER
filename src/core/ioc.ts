// Extracts indicators of compromise (IOCs) from text/binary strings.
// Pure and deterministic so it can be unit-tested with fixtures.

import { isDomain } from './validation.js';

export interface ExtractedIocs {
  urls: string[];
  domains: string[];
  ipv4: string[];
  emails: string[];
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>()]{4,2048}/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,10}[a-zA-Z]{2,24}\b/g;

function uniqueCapped<T>(items: Iterable<T>, cap = 500): T[] {
  const set = new Set<T>();
  for (const it of items) {
    set.add(it);
    if (set.size >= cap) break;
  }
  return [...set];
}

/**
 * Pulls printable ASCII runs of >= minLen from a byte buffer. This is how static
 * analysis surfaces embedded strings without executing the file.
 */
export function extractAsciiStrings(bytes: Uint8Array, minLen = 5): string[] {
  const out: string[] = [];
  let cur = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= minLen) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

export function extractIocs(text: string): ExtractedIocs {
  const urls = uniqueCapped(text.match(URL_RE) ?? []);
  const ipv4 = uniqueCapped(text.match(IPV4_RE) ?? []);
  const emails = uniqueCapped(text.match(EMAIL_RE) ?? []);

  const domainSet = new Set<string>();
  for (const m of text.match(DOMAIN_RE) ?? []) {
    const d = m.toLowerCase();
    if (isDomain(d) && !ipv4.includes(d)) domainSet.add(d);
    if (domainSet.size >= 500) break;
  }
  // Domains already represented inside a URL host are still listed separately on purpose:
  // analysts want the flat domain list. Emails' domains are excluded to reduce noise.
  const emailDomains = new Set(emails.map((e) => e.split('@')[1]?.toLowerCase()));

  return {
    urls,
    ipv4,
    emails,
    domains: [...domainSet].filter((d) => !emailDomains.has(d)),
  };
}
