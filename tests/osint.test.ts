import { describe, expect, it, vi } from 'vitest';
import { NetworkGate, type NetworkActivityEntry } from '../src/core/network-gate';
import { normalizeOsintTarget, osintPivots, OSINT_TYPES, parseCrtSh, parseGithubUser, parseWaybackAvailable } from '../src/core/osint';
import { IntelService } from '../src/main/services/intel';
import { OsintService } from '../src/main/services/osint';

// All network traffic in these tests is mocked; example.com / RFC 2606 names only.

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const CRT = [
  { id: 1, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', common_name: 'example.com', name_value: 'example.com\nwww.example.com', entry_timestamp: '2024-03-01T10:00:00.123', not_before: '2024-03-01T09:00:00' },
  { id: 2, issuer_name: 'C=US, O="DigiCert Inc", CN=DigiCert TLS', common_name: '*.api.example.com', name_value: '*.api.example.com\nevil.example.org', entry_timestamp: '2025-06-10T08:00:00', not_before: '2025-06-10T00:00:00' },
  { id: 2, issuer_name: 'duplicate row', common_name: 'dup.example.com', name_value: 'dup.example.com', entry_timestamp: '2025-06-10T08:00:00' },
  { id: 3, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R10', common_name: 'mail.example.com', name_value: 'MAIL.example.com.', entry_timestamp: '2023-01-05T00:00:00' },
];

describe('OSINT target normalization', () => {
  it('accepts valid targets and canonicalizes them', () => {
    expect(normalizeOsintTarget('domain', ' *.Example.COM. ')).toBe('example.com');
    expect(normalizeOsintTarget('email', 'John.Doe+tag@Example.com')).toBe('John.Doe+tag@example.com');
    expect(normalizeOsintTarget('username', '@octocat')).toBe('octocat');
    expect(normalizeOsintTarget('url', 'https://example.com/a?b=1#frag')).toBe('https://example.com/a?b=1');
  });

  it('rejects invalid or dangerous input', () => {
    for (const [type, v] of [
      ['domain', 'not a domain'], ['domain', 'exa$mple.com'], ['email', 'a@b'], ['email', '.a@example.com'], ['email', 'a..b@example.com'],
      ['username', 'a/b'], ['username', '../etc'], ['username', 'x'.repeat(60)], ['url', 'javascript:alert(1)'], ['url', 'file:///c:/x'],
      ['url', 'https://user:pw@example.com/'], ['url', 'https://10.0.0.1/'], ['unknown', 'example.com'], ['domain', 42],
    ] as const) {
      expect(normalizeOsintTarget(type, v), `${type} ${String(v)}`).toBeNull();
    }
  });
});

describe('OSINT parsers', () => {
  it('summarizes Certificate Transparency results', () => {
    const r = parseCrtSh(CRT, 'example.com');
    expect(r.certificates).toBe(3);
    expect(r.subdomains).toEqual(['example.com', 'api.example.com', 'mail.example.com', 'www.example.com']);
    expect(r.subdomains).not.toContain('evil.example.org');
    expect(r.firstSeen).toBe('2023-01-05T00:00:00.000Z');
    expect(r.lastSeen).toBe('2025-06-10T08:00:00.000Z');
    expect(r.issuers[0]).toEqual({ name: "Let's Encrypt", count: 2 });
    expect(r.issuers.map((i) => i.name)).toContain('DigiCert Inc');
    expect(parseCrtSh('garbage', 'example.com')).toMatchObject({ certificates: 0, subdomains: [], firstSeen: null });
  });

  it('parses Wayback snapshots and refuses foreign hosts', () => {
    const ok = { archived_snapshots: { closest: { available: true, status: '200', url: 'http://web.archive.org/web/20010203040506/http://example.com/', timestamp: '20010203040506' } } };
    expect(parseWaybackAvailable(ok)).toEqual({ url: 'https://web.archive.org/web/20010203040506/http://example.com/', timestamp: '2001-02-03T04:05:06Z' });
    expect(parseWaybackAvailable({ archived_snapshots: {} })).toBeNull();
    expect(parseWaybackAvailable({ archived_snapshots: { closest: { ...ok.archived_snapshots.closest, url: 'https://evil.example/x' } } })).toBeNull();
  });

  it('parses a GitHub profile and drops non-GitHub profile URLs', () => {
    const p = parseGithubUser({ login: 'octocat', name: 'The Octocat', public_repos: 8, followers: 100, created_at: '2011-01-25T18:44:36Z', html_url: 'https://github.com/octocat' });
    expect(p).toMatchObject({ login: 'octocat', name: 'The Octocat', publicRepos: 8, htmlUrl: 'https://github.com/octocat', bio: null });
    expect(parseGithubUser({ login: 'x', html_url: 'javascript:alert(1)' })?.htmlUrl).toBeNull();
    expect(parseGithubUser({ message: 'Not Found' })).toBeNull();
  });

  it('pivot links are https and encode the target', () => {
    for (const type of OSINT_TYPES) {
      const value = type === 'email' ? 'a+b@example.com' : type === 'url' ? 'https://example.com/p?q=1' : type === 'username' ? 'user.name' : 'example.com';
      const pivots = osintPivots(type, value);
      expect(pivots.length).toBeGreaterThan(0);
      for (const p of pivots) {
        expect(new URL(p.url).protocol).toBe('https:');
        expect(p.dataKind).toMatch(/^privacy\.data\./);
      }
      expect(new Set(pivots.map((p) => p.id)).size).toBe(pivots.length);
    }
    expect(osintPivots('email', 'a+b@example.com')[0]!.url).toContain(encodeURIComponent('"a+b@example.com"'));
  });
});

function build(opts: { offline?: boolean; routes?: Record<string, () => Response> } = {}) {
  const log: NetworkActivityEntry[] = [];
  const fetchMock = vi.fn(async (url: string, _init?: RequestInit) => {
    for (const [prefix, r] of Object.entries(opts.routes ?? {})) if (url.startsWith(prefix)) return r();
    return new Response('not found', { status: 404 });
  });
  const gate = new NetworkGate(() => !!opts.offline, (e) => log.push(e), fetchMock);
  const enodata = () => Promise.reject(Object.assign(new Error('no data'), { code: 'ENODATA' }));
  const resolver = {
    getServers: () => ['192.0.2.53'],
    reverse: vi.fn(enodata), resolve4: vi.fn(enodata), resolve6: vi.fn(enodata), resolveNs: vi.fn(enodata), resolveCname: vi.fn(enodata),
    resolveCaa: vi.fn(enodata), resolveSoa: vi.fn(async () => null),
    resolveMx: vi.fn(async () => [{ exchange: 'mx.example.com', priority: 10 }]),
    resolveTxt: vi.fn(async (name: string) => (name.startsWith('_dmarc.') ? [['v=DMARC1; p=reject']] : [['v=spf1 -all']])),
  };
  const intel = new IntelService({ gate, secret: () => null, resolver: resolver as never });
  const openExternal = vi.fn(async (_url: string) => {});
  const svc = new OsintService({ intel, gate, openExternal });
  return { svc, log, fetchMock, openExternal, resolver };
}

const ALL = { ct: true, wayback: true, github: true, emailDns: true };

describe('OSINT service', () => {
  it('domain: CT + Wayback with provenance on every source', async () => {
    const snap = (ts: string) => ({ archived_snapshots: { closest: { available: true, url: `http://web.archive.org/web/${ts}/example.com`, timestamp: ts } } });
    const { svc, log, fetchMock } = build({
      routes: {
        'https://crt.sh/': () => json(CRT),
        'https://archive.org/wayback/available?url=example.com&timestamp=': () => json(snap('19990101000000')),
        'https://archive.org/wayback/available?url=example.com': () => json(snap('20260901000000')),
      },
    });
    const r = await svc.lookup('domain', 'Example.com', ALL);
    expect(r.value).toBe('example.com');
    expect(r.ct?.subdomains).toContain('www.example.com');
    expect(r.wayback?.first?.timestamp).toBe('1999-01-01T00:00:00Z');
    expect(r.wayback?.last?.timestamp).toBe('2026-09-01T00:00:00Z');
    expect(r.github).toBeNull();
    expect(r.sources.map((s) => s.id)).toEqual(['osint:ct', 'osint:wayback']);
    for (const s of r.sources) {
      expect(s.ok).toBe(true);
      expect(s.url).toMatch(/^https:\/\//);
    }
    expect(fetchMock.mock.calls[0]![0]).toContain('q=%25.example.com');
    expect(log.every((e) => e.module === 'osint' && e.outcome === 'allowed')).toBe(true);
  });

  it('username: GitHub 404 is "no public profile", not an error', async () => {
    const { svc } = build();
    const r = await svc.lookup('username', 'nobody-here', ALL);
    expect(r.github).toBeNull();
    expect(r.sources).toEqual([expect.objectContaining({ id: 'osint:github', ok: true, url: 'https://api.github.com/users/nobody-here' })]);
  });

  it('email: only the domain goes to the resolver', async () => {
    const { svc, resolver, fetchMock } = build();
    const r = await svc.lookup('email', 'someone@example.com', ALL);
    expect(r.email).toMatchObject({ domain: 'example.com', acceptsMail: true, spf: 'v=spf1 -all', dmarc: 'v=DMARC1; p=reject' });
    expect(fetchMock).not.toHaveBeenCalled();
    const asked = [...resolver.resolveMx.mock.calls, ...resolver.resolveTxt.mock.calls].map((c) => String(c[0]));
    expect(asked.some((n) => n.includes('someone'))).toBe(false);
  });

  it('Offline Mode blocks lookups and pivots', async () => {
    const { svc, fetchMock, openExternal, log } = build({ offline: true });
    const r = await svc.lookup('domain', 'example.com', ALL);
    expect(r.sources.every((s) => !s.ok && s.error === 'offline_mode')).toBe(true);
    expect(r.pivots.length).toBeGreaterThan(0);
    await expect(svc.openPivot('domain', 'example.com', 'crtsh')).rejects.toMatchObject({ code: 'offline_mode' });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(openExternal).not.toHaveBeenCalled();
    expect(log.every((e) => e.outcome === 'blocked_offline')).toBe(true);
  });

  it('pivots are re-derived in the main process: no arbitrary URLs', async () => {
    const { svc, openExternal, log } = build();
    await svc.openPivot('username', 'octocat', 'github');
    expect(openExternal).toHaveBeenCalledWith('https://github.com/octocat');
    expect(log.at(-1)).toMatchObject({ module: 'osint', service: 'browser:github', host: 'github.com', dataKind: 'privacy.data.username' });
    await expect(svc.openPivot('username', 'octocat', 'https://evil.example')).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(svc.openPivot('username', 'a/../b', 'github')).rejects.toMatchObject({ code: 'invalid_osint_target' });
    await expect(svc.lookup('url', 'javascript:alert(1)', ALL)).rejects.toMatchObject({ code: 'invalid_osint_target' });
    expect(openExternal).toHaveBeenCalledTimes(1);
  });
});
