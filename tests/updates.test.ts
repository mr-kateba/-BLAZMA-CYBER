import { describe, expect, it, vi } from 'vitest';
import { NetworkGate, type NetworkActivityEntry } from '../src/core/network-gate';
import { compareSemver, newestRelease, parseSemver } from '../src/core/version';
import { checkForUpdates, lastReleaseUrl } from '../src/main/services/updates';

const v = (s: string) => parseSemver(s)!;
const RELEASES = [
  { tag_name: 'v0.2.0-beta.1', name: 'Beta 2', draft: false, prerelease: true, published_at: '2026-10-01T00:00:00Z', html_url: 'https://evil.example/' },
  { tag_name: 'v0.1.0-beta.1', name: 'Beta 1', draft: false, prerelease: true, published_at: '2026-09-27T08:12:00Z' },
  { tag_name: 'v9.9.9', draft: true },
  { tag_name: 'nightly-2026', draft: false },
];

describe('Version comparison', () => {
  it('follows SemVer precedence', () => {
    const order = ['0.1.0-alpha', '0.1.0-alpha.1', '0.1.0-beta', '0.1.0-beta.2', '0.1.0-beta.11', '0.1.0-rc.1', '0.1.0', '0.1.1', '0.2.0', '1.0.0'];
    for (let i = 1; i < order.length; i++) expect(compareSemver(v(order[i]!), v(order[i - 1]!)), order[i]).toBeGreaterThan(0);
    expect(compareSemver(v('v1.2.3'), v('1.2.3'))).toBe(0);
    expect(parseSemver('1.2')).toBeNull();
    expect(parseSemver('1.2.3; rm -rf')).toBeNull();
  });

  it('picks the newest real release; drafts and non-version tags are ignored; the URL is built, never taken from the answer', () => {
    expect(newestRelease(RELEASES, 'mr-kateba/-BLAZMA-CYBER')).toEqual({
      tag: 'v0.2.0-beta.1', name: 'Beta 2', url: 'https://github.com/mr-kateba/-BLAZMA-CYBER/releases/tag/v0.2.0-beta.1', publishedAt: '2026-10-01T00:00:00Z', prerelease: true,
    });
    expect(newestRelease({ message: 'Not Found' }, 'x/y')).toBeNull();
  });
});

describe('Manual update check', () => {
  const gate = (fetchImpl: (u: string) => Promise<Response>, offline = false) => {
    const log: NetworkActivityEntry[] = [];
    return { g: new NetworkGate(() => offline, (e) => log.push(e), fetchImpl), log };
  };

  it('compares the running version with the newest release through NetworkGate', async () => {
    const f = vi.fn(async (_u: string) => new Response(JSON.stringify(RELEASES), { status: 200 }));
    const { g, log } = gate(f);
    const r = await checkForUpdates(g, '0.1.0');
    expect(f.mock.calls[0]![0]).toBe('https://api.github.com/repos/mr-kateba/-BLAZMA-CYBER/releases?per_page=20');
    expect(r).toMatchObject({ current: '0.1.0', newer: true, latest: { tag: 'v0.2.0-beta.1' } });
    expect(lastReleaseUrl()).toBe('https://github.com/mr-kateba/-BLAZMA-CYBER/releases/tag/v0.2.0-beta.1');
    expect(log[0]).toMatchObject({ host: 'api.github.com', dataKind: 'privacy.data.none', outcome: 'allowed' });
    expect((await checkForUpdates(gate(f).g, '0.2.0')).newer).toBe(false); // the final 0.2.0 is newer than its beta
  });

  it('Offline Mode blocks it; errors are honest', async () => {
    const f = vi.fn(async () => new Response('[]'));
    await expect(checkForUpdates(gate(f, true).g, '0.1.0')).rejects.toMatchObject({ code: 'offline_mode' });
    expect(f).not.toHaveBeenCalled();
    await expect(checkForUpdates(gate(async () => new Response('', { status: 403 })).g, '0.1.0')).rejects.toMatchObject({ code: 'rate_limited' });
    await expect(checkForUpdates(gate(async () => new Response('<html>', { status: 200 })).g, '0.1.0')).rejects.toMatchObject({ code: 'invalid_response' });
    expect(await checkForUpdates(gate(async () => new Response('[]')).g, '0.1.0')).toMatchObject({ latest: null, newer: false });
  });
});
