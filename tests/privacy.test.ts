import { describe, expect, it, vi } from 'vitest';
import { NetworkGate, OfflineModeError, type NetworkActivityEntry } from '../src/core/network-gate';
import { redact, redactString, REDACTED } from '../src/core/redact';

describe('Offline Mode network gate', () => {
  it('blocks every request in offline mode before calling fetch', async () => {
    const fetchMock = vi.fn();
    const log: NetworkActivityEntry[] = [];
    const gate = new NetworkGate(() => true, (e) => log.push(e), fetchMock);
    await expect(
      gate.request({ module: 'ip', service: 'test', url: 'https://api.example.com/x?key=SECRET', dataKind: 'privacy.data.ip_address' }),
    ).rejects.toBeInstanceOf(OfflineModeError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(log).toHaveLength(1);
    expect(log[0]!.outcome).toBe('blocked_offline');
    // Only the host is recorded, never the query string with the key
    expect(JSON.stringify(log)).not.toContain('SECRET');
    expect(log[0]!.host).toBe('api.example.com');
  });
  it('allows and records requests when online', async () => {
    const fetchMock = vi.fn(async () => new Response('ok'));
    const log: NetworkActivityEntry[] = [];
    const gate = new NetworkGate(() => false, (e) => log.push(e), fetchMock);
    const res = await gate.request({ module: 'ip', service: 'test', url: 'https://api.example.com/', dataKind: 'k' });
    expect(await res.text()).toBe('ok');
    expect(log[0]!.outcome).toBe('allowed');
  });
  it('refuses plain http', async () => {
    const gate = new NetworkGate(() => false, () => {}, vi.fn());
    await expect(gate.request({ module: 'm', service: 's', url: 'http://example.com', dataKind: 'k' })).rejects.toThrow('insecure_protocol');
  });
  it('records errors', async () => {
    const log: NetworkActivityEntry[] = [];
    const gate = new NetworkGate(() => false, (e) => log.push(e), async () => { throw new Error('boom'); });
    await expect(gate.request({ module: 'm', service: 's', url: 'https://example.com', dataKind: 'k' })).rejects.toThrow('boom');
    expect(log[0]!.outcome).toBe('error');
  });
});

describe('Gate for non-HTTP operations (DNS, TLS)', () => {
  it('blocks in offline mode without running the operation', async () => {
    const op = vi.fn(async () => 'x');
    const log: NetworkActivityEntry[] = [];
    const gate = new NetworkGate(() => true, (e) => log.push(e));
    await expect(gate.run({ module: 'ipIntel', service: 'dns', host: '8.8.8.8', dataKind: 'privacy.data.ip_address' }, op)).rejects.toBeInstanceOf(OfflineModeError);
    expect(op).not.toHaveBeenCalled();
    expect(log[0]).toMatchObject({ outcome: 'blocked_offline', service: 'dns', host: '8.8.8.8' });
  });
  it('runs and records when online, records failures', async () => {
    const log: NetworkActivityEntry[] = [];
    const gate = new NetworkGate(() => false, (e) => log.push(e));
    expect(await gate.run({ module: 'm', service: 'tls', host: 'example.com:443', dataKind: 'k' }, async () => 42)).toBe(42);
    await expect(gate.run({ module: 'm', service: 'tls', host: 'h', dataKind: 'k' }, async () => { throw new Error('nope'); })).rejects.toThrow('nope');
    expect(log.map((e) => e.outcome)).toEqual(['allowed', 'error']);
  });
  it('can hand back redirects for manual, gated following', async () => {
    const fetchMock = vi.fn(async (_u: string, init?: RequestInit) => {
      expect(init?.redirect).toBe('manual');
      return new Response(null, { status: 302, headers: { location: 'https://rdap.example/next' } });
    });
    const gate = new NetworkGate(() => false, () => {}, fetchMock);
    const res = await gate.request({ module: 'm', service: 's', url: 'https://a.example/x', dataKind: 'k', redirect: 'manual' });
    expect(res.status).toBe(302);
  });
});

describe('log redaction', () => {
  it('redacts sensitive keys recursively', () => {
    const out = redact({ apiKey: 'abc', nested: { password: 'p', ok: 'v', list: [{ token: 't' }] }, Authorization: 'Bearer x' }) as any;
    expect(out.apiKey).toBe(REDACTED);
    expect(out.nested.password).toBe(REDACTED);
    expect(out.nested.ok).toBe('v');
    expect(out.nested.list[0].token).toBe(REDACTED);
    expect(out.Authorization).toBe(REDACTED);
  });
  it('redacts inline secrets in strings', () => {
    expect(redactString('GET https://x.io/a?apikey=12345&q=1')).toBe('GET https://x.io/a?apikey=[REDACTED]&q=1');
    expect(redactString('Authorization: Bearer abcdefghijkl')).toBe('Authorization: Bearer [REDACTED]');
  });
});
