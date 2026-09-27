// Username check across public sites (pure): builds each site's request and classifies the answer.
//
// Site list and detection rules: WhatsMyName (CC BY-SA 4.0, see username-sites.json and
// engines/licenses/whatsmyname.txt). A site only counts as "found" when its answer carries the
// site's own "account exists" signature (status code AND text); "not found" needs the "missing"
// signature. Anything else — a login wall, a captcha, a changed page, a timeout — is "couldn't
// check", never guessed.

import data from './username-sites.json';

export type UsernameGroup = 'social' | 'other';
export type AccountStatus = 'found' | 'missing' | 'unknown';
export type AccountUnknownReason = 'blocked' | 'rate_limited' | 'no_match' | 'timeout' | 'network_error' | 'too_large' | 'invalid_for_site';

export interface UsernameSite {
  id: string;
  name: string;
  cat: string;
  group: UsernameGroup;
  check: string;
  pretty?: string;
  post?: string;
  headers?: Record<string, string>;
  strip?: string;
  eCode: number;
  eString: string;
  mCode: number;
  mString: string;
}

export const USERNAME_SITES: readonly UsernameSite[] = (data as { sites: UsernameSite[] }).sites;
export const USERNAME_SITES_SOURCE: string = (data as { source: string }).source;

export function sitesFor(groups: readonly UsernameGroup[]): UsernameSite[] {
  return USERNAME_SITES.filter((s) => groups.includes(s.group));
}

/** The account name as the site expects it (some sites don't allow e.g. dots), or null if nothing is left. */
export function accountFor(site: UsernameSite, username: string): string | null {
  const a = site.strip ? [...username].filter((ch) => !site.strip!.includes(ch)).join('') : username;
  return a ? a : null;
}

export interface SiteRequest {
  url: string;
  method: 'GET' | 'POST';
  headers: Record<string, string>;
  body?: string;
}

const fill = (template: string, account: string) => template.split('{account}').join(account);

/** The request that checks `username` on `site`; null when the name can't exist there or the URL is not HTTPS. */
export function buildSiteRequest(site: UsernameSite, username: string): SiteRequest | null {
  const account = accountFor(site, username);
  if (!account) return null;
  let url: URL;
  try {
    url = new URL(fill(site.check, encodeURIComponent(account)));
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  return {
    url: url.toString(),
    method: site.post ? 'POST' : 'GET',
    headers: { ...(site.headers ?? {}) },
    ...(site.post ? { body: fill(site.post, account) } : {}),
  };
}

/** The public profile page to open for a found account (never an API endpoint when a page is known). */
export function siteProfileUrl(site: UsernameSite, username: string): string | null {
  const account = accountFor(site, username);
  if (!account) return null;
  if (!site.pretty && site.post) return null;
  try {
    const u = new URL(fill(site.pretty ?? site.check, encodeURIComponent(account)));
    return u.protocol === 'https:' ? u.toString() : null;
  } catch {
    return null;
  }
}

/** Applies the site's signatures to an HTTP answer. */
export function classifyAnswer(site: UsernameSite, status: number, body: string): { status: AccountStatus; reason?: AccountUnknownReason } {
  if (status === site.eCode && body.includes(site.eString)) return { status: 'found' };
  if (status === site.mCode && (site.mString === '' || body.includes(site.mString))) return { status: 'missing' };
  if (status === 429) return { status: 'unknown', reason: 'rate_limited' };
  if (status === 401 || status === 403 || status === 503 || /captcha|cf-chl|challenge-platform|Just a moment\.\.\./i.test(body.slice(0, 20_000))) {
    return { status: 'unknown', reason: 'blocked' };
  }
  return { status: 'unknown', reason: 'no_match' };
}
