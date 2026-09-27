import { describe, expect, it, vi } from 'vitest';
import { NetworkGate } from '../src/core/network-gate';
import { buildSiteRequest, classifyAnswer, siteProfileUrl, sitesFor, USERNAME_SITES, USERNAME_SITES_SOURCE, type UsernameSite } from '../src/core/username-check';

vi.mock('electron', () => ({}));
const { accountProfileUrl, accountSiteCounts, checkUsernameAccounts } = await import('../src/main/services/username-accounts');

const site = (name: string): UsernameSite => {
  const s = USERNAME_SITES.find((x) => x.name === name);
  if (!s) throw new Error(`site ${name} missing from the list`);
  return s;
};

describe('username site list (WhatsMyName, pinned)', () => {
  it('is pinned to a commit and only holds safe, decidable HTTPS checks', () => {
    expect(USERNAME_SITES_SOURCE).toMatch(/^WebBreacher\/WhatsMyName@[0-9a-f]{40}$/);
    expect(USERNAME_SITES.length).toBeGreaterThan(500);
    expect(sitesFor(['social']).length).toBeGreaterThan(250);
    const ids = new Set<string>();
    for (const s of USERNAME_SITES) {
      expect(ids.has(s.id), s.id).toBe(false);
      ids.add(s.id);
      expect(s.check.startsWith('https://'), s.name).toBe(true);
      if (s.pretty) expect(s.pretty.startsWith('https://'), s.name).toBe(true);
      expect(['xx NSFW xx', 'dating', 'political', 'archived']).not.toContain(s.cat);
      expect(s.eString.length, s.name).toBeGreaterThan(0);
      expect(!s.mString && s.mCode === s.eCode, s.name).toBe(false);
      expect(Object.keys(s.headers ?? {}).map((k) => k.toLowerCase())).not.toContain('cookie');
    }
    expect(accountSiteCounts().social + accountSiteCounts().other).toBe(USERNAME_SITES.length);
  });

  it('covers the major social networks', () => {
    for (const name of ['X', 'Facebook', 'Instagram', 'TikTok', 'Reddit', 'Telegram', 'Snapchat', 'Pinterest', 'Threads']) {
      expect(site(name).group, name).toBe('social');
    }
  });
});

describe('site requests and answers', () => {
  const reddit = site('Reddit');

  it('fills the account into the URL, the profile page and POST bodies', () => {
    expect(buildSiteRequest(reddit, 'some_user')).toEqual({ url: 'https://www.reddit.com/user/some_user/about.json', method: 'GET', headers: {} });
    expect(siteProfileUrl(reddit, 'some_user')).toBe('https://www.reddit.com/user/some_user');
    const discord = site('Discord (User)');
    const req = buildSiteRequest(discord, 'someone')!;
    expect(req.method).toBe('POST');
    expect(req.body).toBe('{"username":"someone"}');
    expect(req.headers['Content-Type']).toBe('application/json');
    // An API-only check (POST, no public page) has nothing to open.
    expect(siteProfileUrl(discord, 'someone')).toBeNull();
  });

  it('removes characters a site does not allow, and skips names left empty', () => {
    const s: UsernameSite = { ...reddit, strip: '.' };
    expect(buildSiteRequest(s, 'a.b')!.url).toContain('/user/ab/');
    expect(buildSiteRequest(s, '...')).toBeNull();
  });

  it('needs the exact signature for found / missing; everything else is unknown with a reason', () => {
    expect(classifyAnswer(reddit, reddit.eCode, `{"kind":"t2","data":{${reddit.eString}"x"}}`)).toEqual({ status: 'found' });
    expect(classifyAnswer(reddit, reddit.mCode, `{"message":"Not Found",${reddit.mString}}`)).toEqual({ status: 'missing' });
    // Right status, wrong page (e.g. a login wall) is not a "found".
    expect(classifyAnswer(reddit, 200, '<html>Log in to continue</html>')).toEqual({ status: 'unknown', reason: 'no_match' });
    expect(classifyAnswer(reddit, 429, '')).toEqual({ status: 'unknown', reason: 'rate_limited' });
    expect(classifyAnswer(reddit, 403, '')).toEqual({ status: 'unknown', reason: 'blocked' });
    expect(classifyAnswer(reddit, 200, '<title>Just a moment...</title>')).toEqual({ status: 'unknown', reason: 'blocked' });
    const noText: UsernameSite = { ...reddit, eCode: 200, mCode: 302, mString: '' };
    expect(classifyAnswer(noText, 302, '')).toEqual({ status: 'missing' });
  });
});

describe('checkUsernameAccounts', () => {
  const reddit = site('Reddit');
  const answer = (url: string): Response => {
    if (url.includes('reddit.com')) return new Response(`{"data":{${reddit.eString}1}}`, { status: reddit.eCode });
    return new Response('nothing to see', { status: 999 % 600 });
  };

  it('asks every site of the group through the gate and reports progress', async () => {
    const seen: string[] = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      seen.push(url);
      expect(init?.redirect).toBe('manual');
      return answer(url);
    });
    const log: string[] = [];
    const gate = new NetworkGate(() => false, (e) => log.push(e.dataKind), fetchImpl);
    const progress = vi.fn();
    const r = await checkUsernameAccounts(gate, '@some_user', ['social'], new AbortController().signal, progress);
    const n = sitesFor(['social']).length;
    expect(r.username).toBe('some_user');
    expect(r.total).toBe(n);
    expect(r.checked).toBe(n);
    expect(r.cancelled).toBe(false);
    expect(r.accounts.find((a) => a.id === reddit.id)).toMatchObject({ status: 'found', url: 'https://www.reddit.com/user/some_user' });
    expect(r.found).toBeGreaterThanOrEqual(1);
    expect(r.found + r.missing + r.unknown).toBe(n);
    expect(log.every((k) => k === 'privacy.data.username')).toBe(true);
    expect(progress).toHaveBeenLastCalledWith(n, n);
    expect(seen.every((u) => u.startsWith('https://'))).toBe(true);
  });

  it('is blocked as a whole in Offline Mode', async () => {
    const fetchImpl = vi.fn();
    const gate = new NetworkGate(() => true, () => {}, fetchImpl);
    await expect(checkUsernameAccounts(gate, 'some_user', ['social'], new AbortController().signal)).rejects.toMatchObject({ code: 'offline_mode' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('stops on cancel and returns the partial result', async () => {
    const ctrl = new AbortController();
    let calls = 0;
    const gate = new NetworkGate(() => false, () => {}, async (url) => {
      if (++calls === 20) ctrl.abort();
      return answer(url);
    });
    const r = await checkUsernameAccounts(gate, 'some_user', ['social', 'other'], ctrl.signal);
    expect(r.cancelled).toBe(true);
    expect(r.checked).toBeLessThan(r.total);
    expect(calls).toBeLessThan(40);
  });

  it('reports failures per site instead of failing the lookup', async () => {
    const gate = new NetworkGate(() => false, () => {}, async (url) => {
      if (url.includes('reddit.com')) throw Object.assign(new Error('boom'), { name: 'TypeError' });
      return answer(url);
    });
    const r = await checkUsernameAccounts(gate, 'some_user', ['social'], new AbortController().signal);
    expect(r.accounts.find((a) => a.id === reddit.id)).toMatchObject({ status: 'unknown', reason: 'network_error' });
  });

  it('validates the username and groups', async () => {
    const gate = new NetworkGate(() => false, () => {}, vi.fn());
    const sig = new AbortController().signal;
    await expect(checkUsernameAccounts(gate, 'not a name', ['social'], sig)).rejects.toMatchObject({ code: 'invalid_osint_target' });
    await expect(checkUsernameAccounts(gate, 'ok', ['nope'], sig)).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(checkUsernameAccounts(gate, 'ok', 'social', sig)).rejects.toMatchObject({ code: 'invalid_input' });
  });

  it('re-derives the profile URL to open from (username, site id) only', () => {
    expect(accountProfileUrl('some_user', reddit.id).url).toBe('https://www.reddit.com/user/some_user');
    expect(() => accountProfileUrl('some_user', 'no-such-site')).toThrow();
    expect(() => accountProfileUrl('bad name', reddit.id)).toThrow();
    expect(() => accountProfileUrl('some_user', site('Discord (User)').id)).toThrow();
  });
});

describe('NetworkGate cancel signal', () => {
  it('aborts the request when the caller cancels', async () => {
    const ctrl = new AbortController();
    const gate = new NetworkGate(() => false, () => {}, (_u, init) => new Promise((_, reject) => {
      init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    }));
    const p = gate.request({ module: 't', service: 't', url: 'https://example.test/', dataKind: 'x', signal: ctrl.signal });
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ name: 'AbortError' });
  });
});
