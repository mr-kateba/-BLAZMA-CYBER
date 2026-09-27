// OSINT "accounts": asks public sites whether a username exists, through NetworkGate (blocked in
// Offline Mode, every site recorded in Network Activity with the data kind "username").
//
// Only the username is sent — no cookies, no logins, no scraping of profile content. Each answer is
// classified with the site's own signature (core/username-check.ts); anything that doesn't match is
// reported as "couldn't check" with the reason, never guessed.

import type { NetworkGate } from '../../core/network-gate';
import { normalizeOsintTarget } from '../../core/osint';
import {
  buildSiteRequest, classifyAnswer, siteProfileUrl, sitesFor, USERNAME_SITES, USERNAME_SITES_SOURCE,
  type AccountUnknownReason, type UsernameGroup, type UsernameSite,
} from '../../core/username-check';
import type { AccountCheck, AccountsResult } from '../../shared/api';
import { IntelError } from './intel';

const CONCURRENCY = 12;
const TIMEOUT_MS = 12_000;
const MAX_BODY_CHARS = 4 * 1024 * 1024;

/** A regular desktop browser identity: many sites answer an unknown client with an error page. */
function browserUserAgent(): string {
  const major = (process.versions.chrome ?? '140').split('.')[0];
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
}

export function parseGroups(raw: unknown): UsernameGroup[] {
  if (!Array.isArray(raw)) throw new IntelError('invalid_input');
  const groups = [...new Set(raw.filter((g): g is UsernameGroup => g === 'social' || g === 'other'))];
  if (groups.length === 0) throw new IntelError('invalid_input');
  return groups;
}

async function checkSite(gate: NetworkGate, site: UsernameSite, username: string, signal: AbortSignal): Promise<AccountCheck> {
  const profile = siteProfileUrl(site, username);
  const base = { id: site.id, name: site.name, cat: site.cat, group: site.group, url: profile };
  const unknown = (reason: AccountUnknownReason): AccountCheck => ({ ...base, status: 'unknown', reason });
  const req = buildSiteRequest(site, username);
  if (!req) return unknown('invalid_for_site');
  try {
    const res = await gate.request({
      module: 'osint',
      service: `accounts:${site.id}`,
      url: req.url,
      dataKind: 'privacy.data.username',
      redirect: 'manual',
      timeoutMs: TIMEOUT_MS,
      signal,
      init: {
        method: req.method,
        headers: { 'user-agent': browserUserAgent(), 'accept-language': 'en-US,en;q=0.9', ...req.headers },
        ...(req.body !== undefined ? { body: req.body } : {}),
      },
    });
    const body = await res.text();
    if (body.length > MAX_BODY_CHARS) return unknown('too_large');
    const c = classifyAnswer(site, res.status, body);
    return { ...base, status: c.status, ...(c.reason ? { reason: c.reason } : {}) };
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === 'offline_mode') throw e;
    if (code === 'response_too_large') return unknown('too_large');
    const name = (e as Error).name;
    return unknown(name === 'AbortError' || name === 'TimeoutError' ? 'timeout' : 'network_error');
  }
}

/**
 * Checks `username` on every site of the chosen groups, CONCURRENCY at a time.
 * Cancelling stops new requests and aborts the ones in flight; the partial result is returned.
 */
export async function checkUsernameAccounts(
  gate: NetworkGate,
  rawUsername: unknown,
  rawGroups: unknown,
  signal: AbortSignal,
  onProgress: (done: number, total: number) => void = () => {},
  now: () => number = Date.now,
): Promise<AccountsResult> {
  const username = normalizeOsintTarget('username', rawUsername);
  if (!username) throw new IntelError('invalid_osint_target');
  const groups = parseGroups(rawGroups);
  const sites = sitesFor(groups);
  const started = now();
  const out: AccountCheck[] = [];
  let next = 0;
  let offline: unknown = null;
  onProgress(0, sites.length);
  const worker = async () => {
    while (!signal.aborted && offline === null && next < sites.length) {
      const site = sites[next++]!;
      try {
        out.push(await checkSite(gate, site, username, signal));
      } catch (e) {
        offline = e;
        return;
      }
      onProgress(out.length, sites.length);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, sites.length) }, worker));
  if (offline !== null) throw offline;
  const cancelled = signal.aborted && out.length < sites.length;
  // Requests cut short by a cancel are not answers: keep only real results in a cancelled run.
  const accounts = (cancelled ? out.filter((a) => a.reason !== 'timeout') : out).sort((a, b) => a.name.localeCompare(b.name, 'en'));
  const count = (s: AccountCheck['status']) => accounts.filter((a) => a.status === s).length;
  return {
    username,
    groups,
    total: sites.length,
    checked: accounts.length,
    found: count('found'),
    missing: count('missing'),
    unknown: count('unknown'),
    accounts,
    cancelled,
    durationMs: now() - started,
    source: USERNAME_SITES_SOURCE,
  };
}

/** Site counts per group, for the source picker. */
export function accountSiteCounts(): Record<UsernameGroup, number> {
  return { social: USERNAME_SITES.filter((s) => s.group === 'social').length, other: USERNAME_SITES.filter((s) => s.group === 'other').length };
}

/** The profile URL to open for (username, site): re-derived here, never taken from the renderer. */
export function accountProfileUrl(rawUsername: unknown, siteId: unknown): { url: string; site: UsernameSite } {
  const username = normalizeOsintTarget('username', rawUsername);
  const site = USERNAME_SITES.find((s) => s.id === siteId);
  const url = username && site ? siteProfileUrl(site, username) : null;
  if (!url || !site) throw new IntelError('invalid_input');
  return { url, site };
}
