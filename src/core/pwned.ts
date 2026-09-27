// Have I Been Pwned "Pwned Passwords" range API (k-anonymity).
// The password is hashed locally with SHA-1; only the first 5 hex characters of the hash are sent.
// The service answers with every known hash suffix under that prefix (plus random padding rows with
// count 0), and the match is made locally — the service never learns which password was checked.

import { createHash } from 'node:crypto';

export const PWNED_HOST = 'api.pwnedpasswords.com';
export const MAX_PASSWORD_CHARS = 1024;

export interface PwnedQuery {
  /** First 5 hex chars (uppercase) — the only part that is sent. */
  prefix: string;
  /** Remaining 35 hex chars — kept local. */
  suffix: string;
}

export function pwnedQuery(password: string): PwnedQuery {
  const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  return { prefix: sha1.slice(0, 5), suffix: sha1.slice(5) };
}

export function pwnedRangeUrl(prefix: string): string {
  if (!/^[0-9A-F]{5}$/.test(prefix)) throw new Error('invalid_prefix');
  return `https://${PWNED_HOST}/range/${prefix}`;
}

/**
 * Finds `suffix` in a range response ("SUFFIX:COUNT" per line). Padding rows have count 0 and are
 * treated as absent. Returns null when the body is not a range response at all (never guessed).
 */
export function parsePwnedRange(body: string, suffix: string): number | null {
  const want = suffix.toUpperCase();
  let valid = 0;
  for (const line of body.split(/\r?\n/)) {
    const m = /^([0-9A-F]{35}):(\d{1,12})$/i.exec(line.trim());
    if (!m) continue;
    valid++;
    if (m[1]!.toUpperCase() === want) return Number(m[2]);
  }
  return valid > 0 ? 0 : null;
}
