import { describe, expect, it, vi } from 'vitest';
import { NetworkGate, type NetworkActivityEntry } from '../src/core/network-gate';
import { abusechDate, abusechStatus, parseMalwareBazaar, parseThreatFox, parseUrlhausHost, parseUrlhausPayload } from '../src/core/abusech';
import { externalLinkHost } from '../src/core/intel';
import { abusechSignal, assess } from '../src/core/detection';
import { summarizeDomain } from '../src/core/link-summary';
import { IntelService } from '../src/main/services/intel';
import type { ApiKeyService } from '../src/shared/api';

// Response shapes follow the public abuse.ch API documentation (bazaar.abuse.ch/api, urlhaus-api.abuse.ch,
// threatfox.abuse.ch/api). Values are fixtures, not real samples.
const SHA256 = 'a'.repeat(63) + 'b';
const MD5 = 'c'.repeat(32);
const MB_OK = {
  query_status: 'ok',
  data: [{
    sha256_hash: SHA256, md5_hash: MD5, file_name: 'Invoice_2026.exe', file_type: 'exe', signature: 'AgentTesla',
    first_seen: '2026-09-20 08:15:02', last_seen: '2026-09-25 10:00:00', tags: ['AgentTesla', 'exe'], reporter: 'someone',
  }],
};
const UH_HOST = {
  query_status: 'ok', urlhaus_reference: 'https://urlhaus.abuse.ch/host/bad.example/', host: 'bad.example', firstseen: '2026-09-01 12:00:00 UTC',
  url_count: '3', blacklists: { spamhaus_dbl: 'abused_legit_malware', surbl: 'listed' },
  urls: [
    { url: 'http://bad.example/a.exe', url_status: 'online', date_added: '2026-09-24 09:00:00 UTC', threat: 'malware_download', tags: ['Emotet'] },
    { url: 'http://bad.example/b.exe', url_status: 'offline', date_added: '2026-09-02 09:00:00 UTC', threat: 'malware_download', tags: ['Emotet', 'exe'] },
  ],
};
const UH_PAYLOAD = { query_status: 'ok', md5_hash: MD5, sha256_hash: SHA256, file_type: 'exe', signature: 'Emotet', firstseen: '2026-09-01 00:00:00', lastseen: null, url_count: '2', urls: [{ url_status: 'offline' }, { url_status: 'offline' }] };
const TF_OK = {
  query_status: 'ok',
  data: [
    { id: '1234567', ioc: SHA256, threat_type: 'payload', threat_type_desc: 'Malware sample', malware: 'win.agent_tesla', malware_printable: 'Agent Tesla', confidence_level: 100, first_seen: '2026-09-20 08:00:00 UTC', last_seen: null, tags: ['AgentTesla'] },
    { id: '1234500', ioc: SHA256, threat_type: 'payload', threat_type_desc: 'Malware sample', malware_printable: 'Agent Tesla', confidence_level: 50, first_seen: '2026-09-19 08:00:00 UTC', tags: null },
  ],
};

describe('abuse.ch parsers', () => {
  it('dates and statuses', () => {
    expect(abusechDate('2026-09-20 08:15:02')).toBe('2026-09-20T08:15:02.000Z');
    expect(abusechDate('2026-09-20 08:15:02 UTC')).toBe('2026-09-20T08:15:02.000Z');
    expect(abusechDate('yesterday')).toBeNull();
    expect(abusechStatus(MB_OK)).toBe('ok');
    expect(abusechStatus({ query_status: 'hash_not_found' })).toBe('not_found');
    expect(abusechStatus({ query_status: 'no_results' })).toBe('not_found');
    expect(abusechStatus({ query_status: 'no_result' })).toBe('not_found');
    expect(abusechStatus({ query_status: 'unknown_auth_key' })).toBe('api_key_invalid');
    expect(abusechStatus({ query_status: 'illegal_hash' })).toBe('invalid_input');
    expect(abusechStatus({ query_status: 'invalid_host' })).toBe('invalid_input');
    expect(abusechStatus('<html>')).toBe('invalid_response');
    expect(abusechStatus({ query_status: 'something_new' })).toBe('invalid_response');
  });

  it('MalwareBazaar sample', () => {
    expect(parseMalwareBazaar(MB_OK)).toEqual({
      service: 'malwarebazaar', found: true, listed: true, threat: 'AgentTesla', typeDescription: 'exe', names: ['Invoice_2026.exe'], tags: ['AgentTesla', 'exe'],
      firstSeen: '2026-09-20T08:15:02.000Z', lastSeen: '2026-09-25T10:00:00.000Z', link: `https://bazaar.abuse.ch/sample/${SHA256}/`,
    });
    // A malformed hash never becomes a link.
    expect(parseMalwareBazaar({ query_status: 'ok', data: [{ sha256_hash: '../../x' }] }).link).toBeUndefined();
  });

  it('URLhaus host: active vs historical, reference link only on urlhaus.abuse.ch', () => {
    const r = parseUrlhausHost(UH_HOST);
    expect(r).toMatchObject({ service: 'urlhaus', found: true, listed: true, listedActive: true, urlCount: 3, onlineUrls: 1, threat: 'malware_download', tags: ['Emotet', 'exe'], firstSeen: '2026-09-01T12:00:00.000Z', lastSeen: '2026-09-24T09:00:00.000Z', link: 'https://urlhaus.abuse.ch/host/bad.example/' });
    const old = parseUrlhausHost({ ...UH_HOST, urlhaus_reference: 'https://evil.example/', urls: [{ url_status: 'offline' }] });
    expect(old.listedActive).toBe(false);
    expect(old.link).toBeUndefined();
  });

  it('URLhaus payload and ThreatFox', () => {
    expect(parseUrlhausPayload(UH_PAYLOAD)).toMatchObject({ service: 'urlhaus', listed: true, listedActive: false, threat: 'Emotet', urlCount: 2, onlineUrls: 0, lastSeen: null });
    expect(parseThreatFox(TF_OK)).toMatchObject({
      service: 'threatfox', listed: true, threat: 'Agent Tesla', typeDescription: 'Malware sample', confidence: 100, tags: ['AgentTesla'],
      firstSeen: '2026-09-19T08:00:00.000Z', link: 'https://threatfox.abuse.ch/ioc/1234567/',
    });
  });

  it('abuse.ch report pages are allowed external links; look-alikes are not', () => {
    expect(externalLinkHost(`https://bazaar.abuse.ch/sample/${SHA256}/`)).toBe('bazaar.abuse.ch');
    expect(externalLinkHost('https://threatfox.abuse.ch/ioc/1/')).toBe('threatfox.abuse.ch');
    expect(externalLinkHost('https://abuse.ch.evil.example/')).toBeNull();
    expect(externalLinkHost('http://urlhaus.abuse.ch/host/x/')).toBeNull();
  });
});

describe('abuse.ch evidence', () => {
  it('a MalwareBazaar match alone is enough for "malicious"; not listed is neutral, never clean', () => {
    const all = new Set(['defender', 'yara', 'signature', 'hash_reputation'] as const);
    expect(assess([abusechSignal(parseMalwareBazaar(MB_OK))], { availableSources: new Set(all) }).verdict).toBe('malicious');
    expect(abusechSignal({ service: 'urlhaus', found: true, urlCount: 2 }).weight).toBe('strong');
    expect(abusechSignal({ service: 'threatfox', found: true, confidence: 50 }).weight).toBe('strong');
    expect(abusechSignal({ service: 'threatfox', found: true, confidence: 100 }).weight).toBe('malicious');
    expect(abusechSignal({ service: 'malwarebazaar', found: false }).weight).toBe('neutral');
  });

  it('domain summary: active listing is risky, historical is caution, "not listed" adds nothing', () => {
    const base = { input: 'bad.example', domain: 'bad.example', dns: null, rdap: null, tls: null, infrastructure: [], sources: [] };
    const now = new Date('2026-09-27T00:00:00Z');
    expect(summarizeDomain({ ...base, reputation: [parseUrlhausHost(UH_HOST)] }, now)).toEqual({ level: 'risky', signals: [{ key: 'listedActive', tone: 'red', vars: { service: 'urlhaus' } }] });
    expect(summarizeDomain({ ...base, reputation: [{ ...parseUrlhausHost(UH_HOST), listedActive: false }] }, now).level).toBe('caution');
    expect(summarizeDomain({ ...base, reputation: [{ service: 'urlhaus', found: false }] }, now).level).toBe('unknown');
  });
});

function build(routes: Record<string, (init?: RequestInit) => Response>, keys: Partial<Record<ApiKeyService, string>> = { abusech: 'k'.repeat(48) }) {
  const log: NetworkActivityEntry[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    for (const [prefix, r] of Object.entries(routes)) if (url.startsWith(prefix)) return r(init);
    return new Response('not found', { status: 404 });
  });
  const gate = new NetworkGate(() => false, (e) => log.push(e), fetchMock);
  const svc = new IntelService({ gate, secret: (s) => keys[s] ?? null, resolver: {} as never, tls: vi.fn() });
  return { svc, log, fetchMock };
}
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });

describe('abuse.ch through IntelService', () => {
  it('file hash → POSTs with the Auth-Key to all three services; only the hash is sent; key never logged', async () => {
    const { svc, log, fetchMock } = build({
      'https://mb-api.abuse.ch/api/v1/': () => json(MB_OK),
      'https://urlhaus-api.abuse.ch/v1/payload/': () => json({ query_status: 'no_results' }),
      'https://threatfox-api.abuse.ch/api/v1/': () => json(TF_OK),
    });
    const r = await svc.reputation('hash', SHA256.toUpperCase(), ['malwarebazaar', 'urlhaus', 'threatfox']);
    expect(r.results.map((x) => [x.service, x.found])).toEqual([['malwarebazaar', true], ['urlhaus', false], ['threatfox', true]]);
    const calls = Object.fromEntries(fetchMock.mock.calls.map(([u, i]) => [u, i!]));
    const mb = calls['https://mb-api.abuse.ch/api/v1/']!;
    expect(mb.method).toBe('POST');
    expect((mb.headers as Record<string, string>)['Auth-Key']).toBe('k'.repeat(48));
    expect(mb.body).toBe(`query=get_info&hash=${SHA256}`);
    expect(calls['https://urlhaus-api.abuse.ch/v1/payload/']!.body).toBe(`sha256_hash=${SHA256}`);
    expect(JSON.parse(String(calls['https://threatfox-api.abuse.ch/api/v1/']!.body))).toEqual({ query: 'search_hash', hash: SHA256 });
    expect(JSON.stringify(log)).not.toContain('k'.repeat(48));
    expect(log.every((e) => e.module === 'fileAnalyzer' && e.dataKind === 'privacy.data.file_hash')).toBe(true);
  });

  it('SHA-1 is not supported by URLhaus/ThreatFox: skipped with a reason, no request', async () => {
    const { svc, fetchMock } = build({ 'https://mb-api.abuse.ch/': () => json({ query_status: 'hash_not_found' }) });
    const r = await svc.reputation('hash', 'd'.repeat(40), ['malwarebazaar', 'urlhaus', 'threatfox']);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(r.results).toEqual([{ service: 'malwarebazaar', found: false }]);
    expect(r.sources.filter((s) => !s.ok).map((s) => [s.id, s.error])).toEqual([['reputation:urlhaus', 'unsupported_indicator'], ['reputation:threatfox', 'unsupported_indicator']]);
  });

  it('domain → URLhaus host + ThreatFox IOC search; MalwareBazaar is not applicable', async () => {
    const { svc, fetchMock } = build({
      'https://urlhaus-api.abuse.ch/v1/host/': () => json(UH_HOST),
      'https://threatfox-api.abuse.ch/api/v1/': () => json({ query_status: 'no_result', data: 'Your search did not yield any results' }),
    });
    const r = await svc.reputation('domain', 'https://Bad.Example/path', ['malwarebazaar', 'urlhaus', 'threatfox']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.find(([u]) => u.includes('urlhaus'))![1]!.body).toBe('host=bad.example');
    expect(r.results.find((x) => x.service === 'urlhaus')).toMatchObject({ listed: true, listedActive: true });
    expect(r.results.find((x) => x.service === 'threatfox')).toEqual({ service: 'threatfox', found: false });
  });

  it('errors: missing key, rejected key (HTTP 401 or query_status), rate limit', async () => {
    const none = build({}, {});
    expect((await none.svc.reputation('hash', SHA256, ['malwarebazaar'])).sources[0]).toMatchObject({ ok: false, error: 'api_key_missing' });
    expect(none.fetchMock).not.toHaveBeenCalled();
    const bad = build({ 'https://mb-api.abuse.ch/': () => json({ query_status: 'unknown_auth_key' }, 401) });
    expect((await bad.svc.reputation('hash', SHA256, ['malwarebazaar'])).sources[0]!.error).toBe('api_key_invalid');
    const bad2 = build({ 'https://mb-api.abuse.ch/': () => json({ query_status: 'unknown_auth_key' }) });
    expect((await bad2.svc.reputation('hash', SHA256, ['malwarebazaar'])).sources[0]!.error).toBe('api_key_invalid');
    const slow = build({ 'https://threatfox-api.abuse.ch/': () => json({}, 429) });
    expect((await slow.svc.reputation('ip', '8.8.8.8', ['threatfox'])).sources[0]!.error).toBe('rate_limited');
  });
});
