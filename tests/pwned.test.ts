import { describe, expect, it, vi } from 'vitest';
import { NetworkGate, type NetworkActivityEntry } from '../src/core/network-gate';
import { parsePwnedRange, pwnedQuery, pwnedRangeUrl } from '../src/core/pwned';
import { passwordTips } from '../src/core/password-tips';
import { checkPwnedPassword } from '../src/main/services/pwned';

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (well-known test vector).
const PW = 'password';
const SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
const pad = (n: number) => Array.from({ length: n }, (_, i) => `${i.toString(16).toUpperCase().padStart(35, 'F')}:0`).join('\r\n');

function gate(fetchImpl: (url: string, init?: RequestInit) => Promise<Response>, offline = false) {
  const log: NetworkActivityEntry[] = [];
  return { gate: new NetworkGate(() => offline, (e) => log.push(e), fetchImpl), log };
}

describe('Pwned Passwords (k-anonymity)', () => {
  it('hashes locally and splits into a 5-char prefix and a local suffix', () => {
    expect(pwnedQuery(PW)).toEqual({ prefix: '5BAA6', suffix: SUFFIX });
    expect(pwnedQuery('كلمة-سر').prefix).toMatch(/^[0-9A-F]{5}$/);
    expect(pwnedRangeUrl('5BAA6')).toBe('https://api.pwnedpasswords.com/range/5BAA6');
    expect(() => pwnedRangeUrl('5BAA61E4')).toThrow();
  });

  it('parses the range response; padding rows (count 0) are not matches', () => {
    const body = `${pad(3)}\r\n${SUFFIX}:10434004\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1`;
    expect(parsePwnedRange(body, SUFFIX)).toBe(10434004);
    expect(parsePwnedRange(body, SUFFIX.toLowerCase())).toBe(10434004);
    expect(parsePwnedRange(`${pad(2)}\r\n${SUFFIX}:0`, SUFFIX)).toBe(0);
    expect(parsePwnedRange('0018A45C4D1DEF81644B54AB7F969B88D65:3', SUFFIX)).toBe(0);
    expect(parsePwnedRange('<html>captive portal</html>', SUFFIX)).toBeNull();
  });

  it('sends only the prefix (never the password or full hash), with padding, and logs host + data kind', async () => {
    const secret = 'Zebra#Moon-2026';
    const q = pwnedQuery(secret);
    const f = vi.fn(async (_u: string, _i?: RequestInit) => new Response(`${pad(5)}\r\n${q.suffix}:42`, { status: 200 }));
    const { gate: g, log } = gate(f);
    const r = await checkPwnedPassword(g, secret, () => new Date('2026-09-27T10:00:00Z'));
    expect(r).toEqual({ found: true, count: 42, checkedAt: '2026-09-27T10:00:00.000Z' });
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe(`https://api.pwnedpasswords.com/range/${q.prefix}`);
    const sent = JSON.stringify({ url, headers: init?.headers, body: init?.body ?? null });
    expect(sent).not.toContain(secret);
    expect(sent.toUpperCase()).not.toContain(q.suffix);
    expect((init?.headers as Record<string, string>)['Add-Padding']).toBe('true');
    expect(JSON.stringify(r)).not.toContain(secret);
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ module: 'passwordCheck', host: 'api.pwnedpasswords.com', dataKind: 'privacy.data.password_hash_prefix', outcome: 'allowed' });
    expect(JSON.stringify(log)).not.toContain(q.prefix);
  });

  it('not found → found:false, count 0', async () => {
    const { gate: g } = gate(async () => new Response(pad(8), { status: 200 }));
    expect(await checkPwnedPassword(g, 'correct horse battery staple ٢٠٢٦')).toMatchObject({ found: false, count: 0 });
  });

  it('Offline Mode blocks before any request; errors are honest codes', async () => {
    const f = vi.fn(async () => new Response(''));
    const off = gate(f, true);
    await expect(checkPwnedPassword(off.gate, PW)).rejects.toMatchObject({ code: 'offline_mode' });
    expect(f).not.toHaveBeenCalled();
    expect(off.log[0]!.outcome).toBe('blocked_offline');

    const code = async (res: () => Promise<Response>) => (await checkPwnedPassword(gate(res).gate, PW).catch((e) => e)).code;
    expect(await code(async () => new Response('slow down', { status: 429 }))).toBe('rate_limited');
    expect(await code(async () => new Response('', { status: 503 }))).toBe('api_error');
    expect(await code(async () => new Response('<html>login to wifi</html>', { status: 200 }))).toBe('invalid_response');
    expect(await code(async () => { throw new TypeError('fetch failed'); })).toBe('network_error');
  });

  it('rejects invalid input without any request', async () => {
    const f = vi.fn(async () => new Response(''));
    const { gate: g } = gate(f);
    for (const bad of ['', 42, null, 'x'.repeat(1025)]) await expect(checkPwnedPassword(g, bad)).rejects.toMatchObject({ code: 'invalid_input' });
    expect(f).not.toHaveBeenCalled();
  });
});

describe('Local password observations', () => {
  it('lists concrete weaknesses only', () => {
    expect(passwordTips('123456').tips).toEqual(['too_short', 'only_digits', 'sequence']);
    expect(passwordTips('qwerty1990').tips).toEqual(['too_short', 'few_kinds', 'keyboard', 'year']);
    expect(passwordTips('aaa-Bbb-9').tips).toContain('repeated');
    const strong = passwordTips('Tall-Camel!Drinks7Tea');
    expect(strong.tips).toEqual([]);
    expect(strong.kinds).toBe(4);
  });

  it('counts Arabic letters as characters and as their own kind', () => {
    const r = passwordTips('سماء-زرقاء-صافية');
    expect(r.length).toBe(16);
    expect(r.kinds).toBe(2);
    expect(r.tips).toEqual(['few_kinds']);
  });
});
